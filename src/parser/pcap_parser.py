from __future__ import annotations

import ipaddress
import logging
import struct
from bisect import bisect_right
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Iterator, NamedTuple

import dpkt

logger = logging.getLogger(__name__)

# Recorded in the ingest log, so rows can be traced to the parser that produced them
PARSER_VERSION = "dpkt-1"


class PcapParseError(Exception):
    """The file could not be read as a PCAP (corrupt, truncated, wrong format)."""


DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_LOOP, DLT_LINUX_SLL, DLT_LINUX_SLL2 = 0, 1, 101, 108, 113, 276
DLT_RAW_ALIASES = {12, 14, DLT_RAW, 228, 229}
SUPPORTED_DLTS = {DLT_NULL, DLT_EN10MB, DLT_LOOP, DLT_LINUX_SLL, DLT_LINUX_SLL2} | DLT_RAW_ALIASES

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# TCP options by kind; the ordered list of them is a scanner / OS fingerprint (unknown kinds become "?<kind>")
TCP_OPTION_NAMES = {0: "eol", 1: "nop", 2: "mss", 3: "ws", 4: "sok", 5: "sack", 8: "ts"}


class Packet(NamedTuple):
    """One inbound TCP packet, in the column order of telescope.packets"""
    ts: datetime
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    ttl: int
    ip_len: int
    ip_id: int
    ip_df: int
    flags: int          # TCP flag byte: FIN 1, SYN 2, RST 4, PSH 8, ACK 16, URG 32, ECE 64, CWR 128
    tcp_window: int
    tcp_seq: int
    tcp_ack: int
    tcp_options: str
    tcp_mss: int
    tcp_wscale: int
    payload_len: int


@dataclass
class ParseStats:
    frames: int = 0
    parsed: int = 0
    non_ip: int = 0
    non_tcp: int = 0
    out_of_scope: int = 0
    malformed: int = 0
    ts_min: datetime | None = None
    ts_max: datetime | None = None


class Darknet:
    """The destination addresses the telescope owns"""

    def __init__(self, text: str = ""):
        nets = [ipaddress.ip_network(t, strict=True) for t in text.replace(",", " ").split()]
        ranges = sorted((int(n.network_address), int(n.broadcast_address)) for n in nets if n.version == 4)
        merged: list[list[int]] = []
        for lo, hi in ranges:
            if merged and lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        self._starts = [r[0] for r in merged]
        self._ends = [r[1] for r in merged]

    def __bool__(self) -> bool:
        return bool(self._starts)

    def __contains__(self, ip: int) -> bool:
        i = bisect_right(self._starts, ip) - 1
        return i >= 0 and ip <= self._ends[i]


def _tcp_options(buf: bytes) -> tuple[str, int, int]:
    """(ordered option kinds, MSS, window scale) of the TCP options area; a SYN with broken options is still a
    valid observation, "malformed" is part of its fingerprint."""
    layout: list[str] = []
    mss = wscale = 0
    i, end = 0, len(buf)
    while i < end:
        kind = buf[i]
        if kind == 0:               # end of option list, the rest is padding
            layout.append("eol")
            break
        if kind == 1:
            layout.append("nop")
            i += 1
            continue
        if i + 1 >= end or buf[i + 1] < 2 or i + buf[i + 1] > end:
            return "malformed", 0, 0
        length = buf[i + 1]
        layout.append(TCP_OPTION_NAMES.get(kind, f"?{kind}"))
        if kind == 2 and length == 4:
            mss = int.from_bytes(buf[i + 2 : i + 4], "big")
        elif kind == 3 and length == 3:
            wscale = buf[i + 2]
        i += length
    return ",".join(layout), mss, wscale


def _utc(ts) -> datetime:
    """Capture timestamp as UTC, truncated to the microsecond: whole microseconds (pcapng, see _PcapngReader),
    Decimal (nanosecond pcap) or float seconds (microsecond pcap)"""
    if isinstance(ts, int):
        micros = ts
    elif isinstance(ts, Decimal):
        micros = int(ts.scaleb(6))
    else:
        micros = round(ts * 1_000_000)
    return EPOCH + timedelta(microseconds=micros)


def _network_layer(buf: bytes, dlt: int):
    """The decoded IP object, raw bytes if an IP header failed to decode, or None for non-IP frames"""
    if dlt == DLT_EN10MB:
        l2 = dpkt.ethernet.Ethernet(buf)
        ethertype = l2.type
    elif dlt == DLT_LINUX_SLL:
        l2 = dpkt.sll.SLL(buf)
        ethertype = l2.ethtype
    elif dlt == DLT_LINUX_SLL2:
        l2 = dpkt.sll2.SLL2(buf)
        ethertype = l2.ethtype
    elif dlt in (DLT_NULL, DLT_LOOP):
        l2 = dpkt.loopback.Loopback(buf)
        return l2.data if isinstance(l2.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    else:   # raw IP
        version = buf[0] >> 4 if buf else 0
        if version == 4:
            return dpkt.ip.IP(buf)
        return dpkt.ip6.IP6(buf) if version == 6 else None

    if isinstance(l2.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return l2.data
    if ethertype in (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6):
        return bytes(l2.data)   # IP ethertype, but the header did not decode
    return None


class _PcapngReader(dpkt.pcapng.Reader):
    """dpkt's iterator turns the timestamp ticks into float seconds, which cannot hold nanoseconds at current epoch
    values (steps of 0.24 µs); this one yields exact whole microseconds. Relies on dpkt 1.9.8 internals (pinned)."""

    truncated = False       # the file ends inside a block

    def __iter__(self):
        f, le = self._Reader__f, self._Reader__le
        head_fmt = "<II" if le else ">II"
        ticks_per_s = int(self._divisor)
        offset_us = self._tsoffset * 1_000_000
        while True:
            head = f.read(8)
            if len(head) < 8:
                self.truncated = bool(head)
                return
            block_type, block_len = struct.unpack(head_fmt, head)
            if block_len < 12 or block_len % 4:
                raise ValueError(f"invalid pcapng block length {block_len}")
            buf = head + f.read(block_len - 8)
            if len(buf) < block_len:
                self.truncated = True
                return
            if block_type == dpkt.pcapng.PCAPNG_BT_EPB:
                block = (dpkt.pcapng.EnhancedPacketBlockLE if le else dpkt.pcapng.EnhancedPacketBlock)(buf)
            elif block_type == dpkt.pcapng.PCAPNG_BT_PB:
                block = (dpkt.pcapng.PacketBlockLE if le else dpkt.pcapng.PacketBlock)(buf)
            else:
                continue
            yield offset_us + ((block.ts_high << 32 | block.ts_low) * 1_000_000) // ticks_per_s, block.pkt_data


def _open_reader(fh):
    magic = fh.read(4)
    fh.seek(0)
    return _PcapngReader(fh) if magic == PCAPNG_MAGIC else dpkt.pcap.Reader(fh)


class PcapParser:
    """Streams a .pcap / .pcapng file into rows for telescope.packets: IPv4 TCP packets to the darknet."""

    def parse_chunks(self, filepath: Path, stats: ParseStats, chunk_size: int, darknet: Darknet) -> Iterator[list[Packet]]:
        """Yield lists of at most chunk_size rows, of the packets addressed to the darknet (an empty one keeps all).
        Raises PcapParseError if the file cannot be read to its end."""
        chunk: list[Packet] = []
        try:
            with filepath.open("rb") as fh:
                reader = _open_reader(fh)
                dlt = reader.datalink()
                if dlt not in SUPPORTED_DLTS:
                    raise PcapParseError(f"{filepath.name}: unsupported link type {dlt}")
                try:
                    for ts, buf in reader:
                        stats.frames += 1
                        packet = self._parse_frame(ts, buf, dlt, stats, darknet)
                        if packet is None:
                            continue
                        chunk.append(packet)
                        if len(chunk) >= chunk_size:
                            yield chunk
                            chunk = []
                except dpkt.NeedData:
                    stats.malformed += 1    # the file ends inside a record header (like a cut-off last frame)
        except PcapParseError:
            raise
        except Exception as e:
            raise PcapParseError(f"Error reading {filepath.name}: {e}") from e
        if getattr(reader, "truncated", False):
            stats.malformed += 1        # cut off inside the last block
        if chunk:
            yield chunk

    def _parse_frame(self, ts: float, buf: bytes, dlt: int, stats: ParseStats, darknet: Darknet) -> Packet | None:
        try:
            l3 = _network_layer(buf, dlt)
            if l3 is None or isinstance(l3, dpkt.ip6.IP6):
                stats.non_ip += 1
                return None
            if isinstance(l3, bytes):
                raise dpkt.UnpackError("truncated or malformed IP header")

            if l3.p != dpkt.ip.IP_PROTO_TCP or l3.offset:
                stats.non_tcp += 1
                return None
            tcp = l3.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                raise dpkt.UnpackError("truncated TCP header")

            dst_ip = int.from_bytes(l3.dst, "big")
            if darknet and dst_ip not in darknet:
                stats.out_of_scope += 1
                return None

            options, mss, wscale = _tcp_options(tcp.opts)
            when = _utc(ts)
        except (dpkt.UnpackError, IndexError, struct.error, OverflowError, OSError, ValueError) as e:
            stats.malformed += 1
            logger.debug(f"frame {stats.frames}: malformed ({e})")
            return None

        stats.parsed += 1
        if stats.ts_min is None or when < stats.ts_min:
            stats.ts_min = when
        if stats.ts_max is None or when > stats.ts_max:
            stats.ts_max = when
        return Packet(
            when, int.from_bytes(l3.src, "big"), dst_ip, tcp.sport, tcp.dport, l3.ttl, l3.len, l3.id, int(bool(l3.df)),
            tcp.flags & 0xFF, tcp.win, tcp.seq, tcp.ack, options, mss, wscale, len(tcp.data),
        )
