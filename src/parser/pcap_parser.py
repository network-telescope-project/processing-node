from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_scapy_loaded = False


def _load_scapy():
    global _scapy_loaded
    if not _scapy_loaded:
        import logging as _logging
        _logging.getLogger("scapy").setLevel(logging.ERROR)
        _scapy_loaded = True


PROTO_MAP = {6: "TCP", 17: "UDP"}

IPV6_EXT_HEADERS = {0: "HOPOPT", 43: "ROUTING", 44: "FRAGMENT", 51: "AH", 50: "ESP", 60: "DESTOPTIONS"}

TCP_FLAG_NAMES = {
    0x001: "F",  # FIN
    0x002: "S",  # SYN
    0x004: "R",  # RST
    0x008: "P",  # PSH
    0x010: "A",  # ACK
    0x020: "U",  # URG
}


def _decode_tcp_flags(flags_int: int) -> str:
    return "".join(v for k, v in sorted(TCP_FLAG_NAMES.items()) if flags_int & k)


def _parse_packet(raw_pkt) -> dict[str, Any] | None:
    """Extract header fields from a single scapy packet."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether

    try:
        ts = datetime.fromtimestamp(float(raw_pkt.time), tz=timezone.utc)

        record: dict[str, Any] = {
            "ts": ts,
            "ip_version": 0,
            "src_ip": "",
            "dst_ip": "",
            "src_port": None,
            "dst_port": None,
            "protocol": "OTHER",
            "ttl": 0,
            "length": None,
            "flags": "",
            "tcp_window": None,
        }

        if raw_pkt.haslayer(IP):
            ip = raw_pkt[IP]
            record.update(
                ip_version=4,
                src_ip=str(ip.src),
                dst_ip=str(ip.dst),
                ttl=int(ip.ttl),
                length=int(ip.len),
                protocol=PROTO_MAP.get(int(ip.proto), "OTHER"),
            )
        elif raw_pkt.haslayer(IPv6):
            ip6 = raw_pkt[IPv6]

            if raw_pkt.haslayer(TCP):
                proto_str = "TCP"
            elif raw_pkt.haslayer(UDP):
                proto_str = "UDP"
            else:
                current_layer = ip6
                while current_layer.payload and current_layer.payload.nh in IPV6_EXT_HEADERS:
                    current_layer = current_layer.payload

                final_nh = getattr(current_layer, "nh", ip6.nh)
                proto_str = PROTO_MAP.get(int(final_nh), "OTHER")

            record.update(
                ip_version=6,
                src_ip=str(ip6.src),
                dst_ip=str(ip6.dst),
                ttl=int(ip6.hlim),
                length=len(ip6),
                protocol=proto_str,
            )
        else:
            return None

        if raw_pkt.haslayer(TCP):
            tcp = raw_pkt[TCP]
            record["src_port"] = int(tcp.sport)
            record["dst_port"] = int(tcp.dport)
            record["tcp_window"] = int(tcp.window)
            record["flags"] = _decode_tcp_flags(int(tcp.flags))
        elif raw_pkt.haslayer(UDP):
            udp = raw_pkt[UDP]
            record["src_port"] = int(udp.sport)
            record["dst_port"] = int(udp.dport)

        return record

    except Exception as e:
        logger.debug(f"Skipping malformed packet: {e}")
        return None


class PcapParser:
    """Parses a .pcap file and returns a list of packet header records."""

    def parse(self, filepath: Path) -> list[dict[str, Any]]:
        _load_scapy()
        from scapy.utils import PcapReader

        logger.info(f"Parsing {filepath.name} ...")
        records: list[dict[str, Any]] = []

        try:
            with PcapReader(str(filepath)) as reader:
                for pkt in reader:
                    record = _parse_packet(pkt)
                    if record is not None:
                        records.append(record)
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")
            return []

        logger.info(f"Parsed {len(records)} IP packets from {filepath.name}")
        return records
