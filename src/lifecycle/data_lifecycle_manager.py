from __future__ import annotations

import errno
import hashlib
import logging
import os
import shutil
import time
import requests
import zstandard
from datetime import datetime, timezone
from pathlib import Path

from prometheus_client import Counter, Gauge

from src.parser.pcap_parser import PARSER_VERSION, Packet, ParseStats

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
QUARANTINE_BYTES = Gauge(
    "telescope_quarantine_bytes",
    "Total size of the PCAP files in the quarantine directory in bytes",
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

COLUMNS = [*Packet._fields, "pcap_file"]
COLUMN_TYPES = [
    "DateTime64(6, 'UTC')", "UInt32", "UInt32", "UInt16", "UInt16", "UInt8", "UInt16", "UInt16", "UInt8", "UInt8",
    "UInt16", "UInt32", "UInt32", "LowCardinality(String)", "UInt16", "UInt8", "UInt16", "LowCardinality(String)",
]

SOURCE_COLUMNS = ["ip", "asn", "asn_name", "country_code", "country_name", "city"]
SOURCE_COLUMN_TYPES = [
    "UInt32", "UInt32", "LowCardinality(String)", "LowCardinality(String)", "LowCardinality(String)", "String",
]

LOG_COLUMNS = [
    "ingested_at", "file_name", "file_sha256", "file_size", "ts_min", "ts_max", "frames", "parsed",
    "non_ip", "non_tcp", "out_of_scope", "malformed", "duplicates", "inserted", "tool_version", "status", "message",
]
TOOL_VERSION = f"nt-processing/{PARSER_VERSION}"
DONE_STATUSES = ("ingested", "empty")

INSERT_BATCH_SIZE = int(os.environ.get("INSERT_BATCH_SIZE", "10000"))
SOURCE_LOOKUP_BATCH = 5000      # addresses per "which sources are new" query
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


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


class DataLifecycleManager:
    def __init__(self, db_client):
        self._db = db_client
        self._last_ingestion_pps: float | None = None
        self._alert_webhook = os.environ.get("ALERT_WEBHOOK_URL", "")
        self._archive_dir = PCAP_ARCHIVE_DIR
        self._quarantine_dir = PCAP_QUARANTINE_DIR

    def already_ingested(self, sha256: str) -> bool:
        done = ", ".join(f"'{s}'" for s in DONE_STATUSES)
        res = self._db.query(
            f"SELECT count() FROM pcap_ingest_log WHERE file_sha256 = {{s:String}} AND status IN ({done})",
            parameters={"s": sha256},
        )
        return res.result_rows[0][0] > 0

    def remove_partial_rows(self, pcap_file: str) -> None:
        """Delete rows left by mid-insert crashed attempt, so retrying the file doesn't duplicate them."""
        res = self._db.query(
            "SELECT count() FROM packets WHERE pcap_file = {f:String}", parameters={"f": pcap_file}
        )
        n = res.result_rows[0][0]
        if n:
            logger.warning(f"{pcap_file}: removing {n} rows of an unfinished earlier attempt before re-ingesting")
            self._db.command(
                "ALTER TABLE packets DELETE WHERE pcap_file = {f:String}",
                parameters={"f": pcap_file},
                settings={"mutations_sync": 1},
            )

    def log_file(
        self,
        filepath: Path,
        sha256: str,
        status: str,
        stats: ParseStats | None = None,
        inserted: int = 0,
        message: str = "",
    ) -> None:
        s = stats or ParseStats()
        row = [
            datetime.now(tz=timezone.utc), filepath.name, sha256, filepath.stat().st_size,
            s.ts_min, s.ts_max, s.frames, s.parsed, s.non_ip, s.non_tcp, s.out_of_scope, s.malformed, 0, inserted,
            TOOL_VERSION, status, message,
        ]
        self._db.insert("pcap_ingest_log", [row], column_names=LOG_COLUMNS)

    def save_batch(self, packets: list[Packet], pcap_file: str) -> int:
        """Insert one chunk of parsed packets."""
        if not packets:
            return 0
        rows = [(*p, pcap_file) for p in packets]
        try:
            self._db.insert("packets", rows, column_names=COLUMNS, column_type_names=COLUMN_TYPES)
        except Exception as e:
            logger.error(f"ClickHouse insert failed: {e}")
            raise
        PACKETS_INGESTED.inc(len(rows))
        logger.debug(f"Inserted {len(rows)} rows into ClickHouse.")
        return len(rows)

    def unknown_sources(self, ips: set[int]) -> list[int]:
        """The source addresses (as integers) that have no row in source_enrichment yet."""
        known: set[int] = set()
        ordered = sorted(ips)
        for i in range(0, len(ordered), SOURCE_LOOKUP_BATCH):
            res = self._db.query(
                "SELECT toUInt32(ip) FROM source_enrichment WHERE toUInt32(ip) IN {ips:Array(UInt32)}",
                parameters={"ips": ordered[i : i + SOURCE_LOOKUP_BATCH]},
            )
            known.update(row[0] for row in res.result_rows)
        return [ip for ip in ordered if ip not in known]

    def save_sources(self, rows: list[list]) -> None:
        if rows:
            self._db.insert(
                "source_enrichment", rows, column_names=SOURCE_COLUMNS, column_type_names=SOURCE_COLUMN_TYPES
            )

    def check_ingestion_speed(self, inserted: int, elapsed: float) -> None:
        """Compares the speed of this file (parse + enrich + insert) with the previous one."""
        if elapsed > 0 and inserted > 0:
            current_pps = inserted / elapsed
            self._check_ingestion_drop(current_pps)
            self._last_ingestion_pps = current_pps

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

    def quarantine_pcap(self, filepath: Path, reason: str, sha256: str = "") -> None:
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

        try:
            self.log_file(dest, sha256, "quarantined", message=reason)
        except Exception as e:
            logger.warning(f"Could not write the ingest log row for {dest.name}: {e}")

        PCAPS_QUARANTINED.inc()
        self.update_quarantine_gauge()
        msg = f"[Network Telescope] PCAP QUARANTINED: {filepath.name} - {reason}"
        logger.error(msg)
        self._send_alert(msg)

    def update_quarantine_gauge(self) -> None:
        files = list(self._quarantine_dir.glob("*.pcap"))
        QUARANTINE_FILES.set(len(files))
        QUARANTINE_BYTES.set(sum(f.stat().st_size for f in files))

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
