import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import schedule
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

from prometheus_client import start_http_server as _start_metrics_server
from src.parser.pcap_parser import ParseStats, PcapParser, PcapParseError
from src.enricher.metadata_enricher import MetadataEnricher
from src.lifecycle.data_lifecycle_manager import (
    HELD_FILES,
    DataLifecycleManager,
    INSERT_BATCH_SIZE,
    PCAP_ARCHIVE_DIR,
    PCAP_QUARANTINE_DIR,
    file_sha256,
)
from src.registry.sensor_registry import LOCAL_SENSOR_ID, SENSOR_ID, SensorNotReady, SensorRegistry
from src.health.health_monitoring_manager import HealthMonitoringManager
from src.health.ingest_watchdog import IngestWatchdog
from src.db import get_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("main")

PCAP_INBOX_DIR = Path(os.environ.get("PCAP_INBOX_DIR", "/var/lib/network-telescope/data/queue"))
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "10"))
READY_AGE_SECONDS = int(os.environ.get("READY_AGE_SECONDS", "5"))
PROMETHEUS_TARGETS_FILE = os.environ.get("PROMETHEUS_TARGETS_FILE", "")


def sensor_of(filepath: Path) -> str | None:
    """The sensor a file in the inbox came from: the sub-directory it was delivered to. A file directly in the inbox
    is the single-node local setup's. None for anything deeper or oddly named."""
    try:
        parts = filepath.relative_to(PCAP_INBOX_DIR).parts
    except ValueError:
        return LOCAL_SENSOR_ID      # listed by the local file detector from outside the inbox
    if len(parts) == 1:
        return LOCAL_SENSOR_ID
    if len(parts) == 2 and SENSOR_ID.match(parts[0]):
        return parts[0]
    return None


def process_pcap_file(
    filepath: Path,
    sensor_id: str,
    parser: PcapParser,
    enricher: MetadataEnricher,
    lifecycle: DataLifecycleManager,
    registry: SensorRegistry,
) -> bool:
    """Ingest one file of a sensor. Returns True if the file was held in the inbox (sensor not ready)."""
    try:
        try:
            darknet = registry.darknet_for(sensor_id, datetime.fromtimestamp(filepath.stat().st_mtime, timezone.utc))
        except SensorNotReady as e:
            lifecycle.report_held(sensor_id, str(e))
            return True
        logger.info(f"Processing: {sensor_id}/{filepath.name}")

        sha256 = file_sha256(filepath)

        try:
            already_done = lifecycle.already_ingested(sha256)
        except Exception as e:
            logger.warning(f"Could not check the ingest log for {filepath.name}: {e}")
            already_done = False
        if already_done:
            logger.info(f"{filepath.name} is already in the ingest log, archiving without ingesting it again.")
            lifecycle.archive_pcap(filepath, sensor_id)
            return False

        lifecycle.remove_partial_rows(sensor_id, filepath.name)
        stats = ParseStats()
        inserted = 0
        started = time.monotonic()
        try:
            for chunk in parser.parse_chunks(filepath, stats, INSERT_BATCH_SIZE, darknet):
                new_sources = lifecycle.unknown_sources({p.src_ip for p in chunk})
                lifecycle.save_sources(enricher.enrich_sources(new_sources))
                inserted += lifecycle.save_batch(chunk, sensor_id, filepath.name)
        except PcapParseError as e:
            lifecycle.remove_partial_rows(sensor_id, filepath.name)    # chunks of the unreadable file that were already stored
            lifecycle.quarantine_pcap(filepath, sensor_id, str(e), sha256)
            return False

        if not inserted:
            logger.info(f"No packets for the darknet in {sensor_id}/{filepath.name} ({stats.frames} frames), archiving.")
            lifecycle.log_file(filepath, sensor_id, sha256, "empty", stats)
            lifecycle.archive_pcap(filepath, sensor_id)
            return False

        lifecycle.log_file(filepath, sensor_id, sha256, "ingested", stats, inserted)
        lifecycle.check_ingestion_speed(inserted, time.monotonic() - started)
        lifecycle.archive_pcap(filepath, sensor_id)
        logger.info(
            f"Done: {sensor_id}/{filepath.name} - {inserted} packets ingested "
            f"({stats.frames} frames, {stats.non_ip} not IPv4, {stats.non_tcp} not TCP, "
            f"{stats.out_of_scope} outside the darknet, {stats.malformed} malformed)."
        )
    except Exception as e:
        logger.exception(f"Failed to process {sensor_id}/{filepath.name}: {e}")
    return False


def scan_inbox(
    parser: PcapParser,
    enricher: MetadataEnricher,
    lifecycle: DataLifecycleManager,
    registry: SensorRegistry,
) -> None:
    candidates: set[Path] = set()

    # Explicit ready-list written by file_detector.sh (local Docker mode)
    ready_list_path = PCAP_INBOX_DIR / ".ready_files"
    if ready_list_path.exists():
        try:
            lines = ready_list_path.read_text().splitlines()
            ready_list_path.unlink()
            for line in lines:
                p = Path(line.strip())
                if p.exists() and p.suffix == ".pcap":
                    candidates.add(p)
        except OSError:
            pass

    # Any .pcap not modified in the last READY_AGE_SECONDS: directly in the inbox (local setup) or in a sensor's
    # sub-directory; anywhere deeper is found too, so that a mistyped delivery directory is reported, not ignored
    now = time.time()
    for pcap in PCAP_INBOX_DIR.rglob("*.pcap"):
        if (now - pcap.stat().st_mtime) > READY_AGE_SECONDS:
            candidates.add(pcap)

    held = 0
    for filepath in sorted(candidates):
        sensor_id = sensor_of(filepath)
        if sensor_id is None:
            lifecycle.report_held(str(filepath.parent), f"{filepath} is neither directly in the inbox nor in a sensor sub-directory")
            held += 1
            continue
        held += process_pcap_file(filepath, sensor_id, parser, enricher, lifecycle, registry)
    HELD_FILES.set(held)

    # Files are removed from quarantine by hand once looked at
    lifecycle.update_quarantine_gauge()


def sync_prometheus_targets(registry: SensorRegistry) -> None:
    if not PROMETHEUS_TARGETS_FILE:
        return
    try:
        if registry.write_prometheus_targets(Path(PROMETHEUS_TARGETS_FILE)):
            logger.info(f"Prometheus targets updated: {PROMETHEUS_TARGETS_FILE}")
    except Exception as e:
        logger.warning(f"Could not update the Prometheus targets: {e}")


def main() -> None:
    logger.info("=== Network Telescope - Processing Node Starting ===")
    PCAP_INBOX_DIR.mkdir(parents=True, exist_ok=True)

    metrics_port = int(os.environ.get("METRICS_PORT", "8000"))
    _start_metrics_server(metrics_port)
    logger.info(f"Prometheus metrics available on :{metrics_port}/metrics")

    db = get_client()
    registry = SensorRegistry(db)
    if not registry.darknet_for(LOCAL_SENSOR_ID, datetime.now(tz=timezone.utc)):
        logger.warning("DARKNET_NETS is empty - files directly in the inbox are not filtered on the destination (local mode only)")
    parser = PcapParser()
    enricher = MetadataEnricher()
    lifecycle = DataLifecycleManager(db)
    health_mgr = HealthMonitoringManager(db, registry)

    lifecycle.ensure_dirs(PCAP_INBOX_DIR)
    lifecycle.maintain_archive()

    watchdog = IngestWatchdog(PCAP_INBOX_DIR, PCAP_ARCHIVE_DIR, PCAP_QUARANTINE_DIR, registry)
    watchdog.run()
    sync_prometheus_targets(registry)

    schedule.every(5).minutes.do(health_mgr.run)
    schedule.every(5).minutes.do(watchdog.run)
    schedule.every(5).minutes.do(sync_prometheus_targets, registry)
    schedule.every().hour.do(lifecycle.maintain_archive)

    # Graceful shutdown
    shutdown = {"requested": False}
    def _handle_signal(sig, _frame):
        logger.info(f"Signal {sig} received, shutting down...")
        shutdown["requested"] = True
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info(f"Watching for .pcap files in: {PCAP_INBOX_DIR}")
    logger.info(f"Poll interval: {POLL_INTERVAL_SECONDS}s")

    while not shutdown["requested"]:
        try:
            scan_inbox(parser, enricher, lifecycle, registry)
            schedule.run_pending()
        except Exception as e:
            logger.exception(f"Unexpected error in main loop: {e}")
        time.sleep(POLL_INTERVAL_SECONDS)

    logger.info("Processing node stopped.")


if __name__ == "__main__":
    main()
