from __future__ import annotations

import errno
import logging
import os
import shutil
import time
import requests
import zstandard
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from prometheus_client import Counter, Gauge

logger = logging.getLogger(__name__)

PACKETS_INGESTED = Counter(
    "telescope_packets_ingested_total",
    "Total number of packet records inserted into ClickHouse",
)
PCAPS_ARCHIVED = Counter(
    "telescope_pcap_archived_total",
    "Ingested PCAP files moved to the archive",
)
PCAPS_QUARANTINED = Counter(
    "telescope_pcap_quarantined_total",
    "PCAP files moved to quarantine because they could not be parsed",
)
QUARANTINE_FILES = Gauge(
    "telescope_quarantine_files",
    "PCAP files currently waiting in the quarantine directory",
)
ARCHIVE_FILES = Gauge("telescope_archive_files", "Files in the PCAP archive")
ARCHIVE_BYTES = Gauge("telescope_archive_bytes", "Total size of the PCAP archive in bytes")
ARCHIVE_PRUNED = Counter(
    "telescope_archive_pruned_total",
    "Archive files deleted by the retention policy",
    ["reason"],  # age | size | free_space
)
ARCHIVE_ERRORS = Counter(
    "telescope_archive_errors_total",
    "Failures while archiving, compressing or quarantining a PCAP",
    ["stage"],  # move | compress | quarantine
)

COLUMNS = [
    "ts",
    "ip_version",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "ttl",
    "length",
    "flags",
    "tcp_window",
    "src_asn",
    "src_asn_name",
    "src_country_code",
    "src_country_name",
    "src_city",
]

INSERT_BATCH_SIZE = int(os.environ.get("INSERT_BATCH_SIZE", "10000"))
INGESTION_DROP_THRESHOLD = float(os.environ.get("INGESTION_DROP_THRESHOLD", "0.90"))

PCAP_ARCHIVE_DIR = Path(os.environ.get("PCAP_ARCHIVE_DIR", "/var/lib/network-telescope/data/archive"))
PCAP_QUARANTINE_DIR = Path(os.environ.get("PCAP_QUARANTINE_DIR", "/var/lib/network-telescope/data/quarantine"))
GIB = 1024 ** 3
ARCHIVE_MAX_BYTES = int(float(os.environ.get("ARCHIVE_MAX_GB", "30")) * GIB)
ARCHIVE_MIN_FREE_BYTES = int(float(os.environ.get("ARCHIVE_MIN_FREE_GB", "20")) * GIB)
ARCHIVE_MAX_AGE_DAYS = int(os.environ.get("ARCHIVE_MAX_AGE_DAYS", "90"))
ZSTD_LEVEL = 3


def _move(src: Path, dest: Path) -> None:
    """Rename src to dest; across filesystems copy next to dest first, so dest is never partial."""
    try:
        os.replace(src, dest)
    except OSError as e:
        if e.errno != errno.EXDEV:
            raise
        tmp = dest.with_name(dest.name + ".tmp")
        shutil.copy2(src, tmp)
        os.replace(tmp, dest)
        src.unlink()


def _to_row(pkt: dict[str, Any]) -> list:
    return [
        pkt.get("ts") or datetime.now(tz=timezone.utc),
        pkt.get("ip_version") or 0,
        pkt.get("src_ip") or "",
        pkt.get("dst_ip") or "",
        pkt.get("src_port"),
        pkt.get("dst_port"),
        pkt.get("protocol") or "OTHER",
        pkt.get("ttl") or 0,
        pkt.get("length") or 0,
        str(pkt.get("flags") or ""),
        pkt.get("tcp_window") or 0,
        str(pkt.get("src_asn") or ""),
        pkt.get("src_asn_name") or "",
        pkt.get("src_country_code") or "",
        pkt.get("src_country_name") or "",
        pkt.get("src_city") or "",
    ]


class DataLifecycleManager:
    def __init__(self, db_client):
        self._db = db_client
        self._last_ingestion_pps: float | None = None
        self._alert_webhook = os.environ.get("ALERT_WEBHOOK_URL", "")
        self._archive_dir = PCAP_ARCHIVE_DIR
        self._quarantine_dir = PCAP_QUARANTINE_DIR

    def save_batch(self, packets: list[dict[str, Any]]) -> int:
        if not packets:
            return 0

        total = 0
        t_start = time.monotonic()

        for i in range(0, len(packets), INSERT_BATCH_SIZE):
            chunk = packets[i : i + INSERT_BATCH_SIZE]
            rows = [_to_row(p) for p in chunk]
            try:
                self._db.insert("packets", rows, column_names=COLUMNS)
                total += len(rows)
                PACKETS_INGESTED.inc(len(rows))
                logger.debug(f"Inserted {len(rows)} rows into ClickHouse.")
            except Exception as e:
                logger.error(f"ClickHouse insert failed: {e}")
                raise

        elapsed = time.monotonic() - t_start
        if elapsed > 0 and total > 0:
            current_pps = total / elapsed
            self._check_ingestion_drop(current_pps)
            self._last_ingestion_pps = current_pps

        return total

    def _check_ingestion_drop(self, current_pps: float) -> None:
        if self._last_ingestion_pps is None or self._last_ingestion_pps == 0:
            return
        drop_fraction = 1.0 - (current_pps / self._last_ingestion_pps)
        if drop_fraction > INGESTION_DROP_THRESHOLD:
            msg = (
                f"[Network Telescope] INGESTION DROP ALERT: "
                f"{self._last_ingestion_pps:.1f} → {current_pps:.1f} pkt/s "
                f"({drop_fraction * 100:.0f}% drop between consecutive files)"
            )
            logger.warning(msg)
            if self._alert_webhook:
                try:
                    requests.post(self._alert_webhook, json={"text": msg}, timeout=5)
                except Exception as e:
                    logger.warning(f"Ingestion alert webhook failed: {e}")

    def _send_alert(self, msg: str) -> None:
        if not self._alert_webhook:
            return
        try:
            requests.post(self._alert_webhook, json={"text": msg}, timeout=5)
        except Exception as e:
            logger.warning(f"Alert webhook failed: {e}")

    def ensure_dirs(self, inbox: Path) -> None:
        for d in (self._archive_dir, self._quarantine_dir):
            d.mkdir(parents=True, exist_ok=True)
            if d.stat().st_dev != inbox.stat().st_dev:
                logger.warning(
                    f"{d} is on a different filesystem than the inbox {inbox}: "
                    "moving files out of the inbox is a copy, not an atomic rename"
                )
        self.update_quarantine_gauge()

    def archive_pcap(self, filepath: Path) -> None:
        """Take an ingested file out of the inbox into the archive, compress it, apply retention."""
        try:
            _move(filepath, self._archive_dir / filepath.name)
        except OSError as e:
            ARCHIVE_ERRORS.labels(stage="move").inc()
            logger.error(f"Could not archive {filepath.name}: {e}")
            return

        PCAPS_ARCHIVED.inc()
        logger.info(f"Archived: {filepath.name}")
        self.maintain_archive()

    def quarantine_pcap(self, filepath: Path, reason: str) -> None:
        """Keep a file that could not be parsed, untouched, for later inspection."""
        dest = self._quarantine_dir / filepath.name
        try:
            _move(filepath, dest)
            dest.with_name(dest.name + ".error.txt").write_text(
                f"{datetime.now(tz=timezone.utc).isoformat()}\n{reason}\n"
            )
        except OSError as e:
            ARCHIVE_ERRORS.labels(stage="quarantine").inc()
            logger.error(f"Could not quarantine {filepath.name}: {e}")
            return

        PCAPS_QUARANTINED.inc()
        self.update_quarantine_gauge()
        msg = f"[Network Telescope] PCAP QUARANTINED: {filepath.name} - {reason}"
        logger.error(msg)
        self._send_alert(msg)

    def update_quarantine_gauge(self) -> None:
        QUARANTINE_FILES.set(sum(1 for _ in self._quarantine_dir.glob("*.pcap")))

    def maintain_archive(self) -> None:
        """Compress leftovers, then enforce retention (age, size cap, minimum free disk)."""
        for tmp in self._archive_dir.glob("*.tmp"):
            tmp.unlink(missing_ok=True)
        for raw in sorted(self._archive_dir.glob("*.pcap")):
            self._compress(raw)
        self.prune_archive()

    def _compress(self, raw: Path) -> None:
        dest = raw.with_name(raw.name + ".zst")
        tmp = raw.with_name(raw.name + ".zst.tmp")
        try:
            st = raw.stat()
            with raw.open("rb") as src, tmp.open("wb") as dst:
                zstandard.ZstdCompressor(level=ZSTD_LEVEL, write_checksum=True).copy_stream(src, dst)
            # Keeping the original mtime (~ capture time) for the age limit
            os.utime(tmp, ns=(st.st_atime_ns, st.st_mtime_ns))
            os.replace(tmp, dest)
            raw.unlink()
        except Exception as e:
            ARCHIVE_ERRORS.labels(stage="compress").inc()
            logger.error(f"Could not compress {raw.name}: {e}")
            tmp.unlink(missing_ok=True)

    def prune_archive(self) -> None:
        """Delete the oldest archive files while any limit is exceeded."""
        entries = sorted(
            (st.st_mtime, st.st_size, p)
            for p in self._archive_dir.iterdir()
            if p.is_file() and p.suffix in (".zst", ".pcap")
            for st in (p.stat(),)
        )
        total = sum(size for _, size, _ in entries)
        free = shutil.disk_usage(self._archive_dir).free
        max_age = ARCHIVE_MAX_AGE_DAYS * 86400
        now = time.time()
        pruned = {"age": 0, "size": 0, "free_space": 0}

        while entries:
            mtime, size, path = entries[0]
            if ARCHIVE_MAX_AGE_DAYS > 0 and now - mtime > max_age:
                reason = "age"
            elif ARCHIVE_MAX_BYTES > 0 and total > ARCHIVE_MAX_BYTES:
                reason = "size"
            elif ARCHIVE_MIN_FREE_BYTES > 0 and free < ARCHIVE_MIN_FREE_BYTES:
                reason = "free_space"
            else:
                break
            try:
                path.unlink()
            except OSError as e:
                logger.error(f"Could not prune {path.name}: {e}")
                break
            entries.pop(0)
            total -= size
            free += size
            pruned[reason] += 1
            ARCHIVE_PRUNED.labels(reason=reason).inc()

        for reason, n in pruned.items():
            if n:
                logger.info(f"Archive retention: deleted {n} oldest file(s) ({reason})")
        if pruned["size"] or pruned["free_space"]:
            msg = (
                f"[Network Telescope] ARCHIVE FULL: deleted {pruned['size'] + pruned['free_space']} "
                f"file(s) before the {ARCHIVE_MAX_AGE_DAYS}-day limit "
                f"(size cap: {pruned['size']}, low free disk: {pruned['free_space']})"
            )
            logger.warning(msg)
            self._send_alert(msg)
        if ARCHIVE_MIN_FREE_BYTES > 0 and free < ARCHIVE_MIN_FREE_BYTES:
            msg = (
                f"[Network Telescope] DISK LOW: {free / GIB:.1f} GB free, below the "
                f"{ARCHIVE_MIN_FREE_BYTES / GIB:.0f} GB limit, with nothing left to prune in the archive"
            )
            logger.error(msg)
            self._send_alert(msg)

        ARCHIVE_FILES.set(len(entries))
        ARCHIVE_BYTES.set(total)
