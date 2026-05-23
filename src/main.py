import logging
import os
import signal
import sys
import time
from pathlib import Path

import schedule
from dotenv import load_dotenv

# Load .env before importing modules that use env vars
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

from prometheus_client import start_http_server as _start_metrics_server
from src.parser.pcap_parser import PcapParser
from src.enricher.metadata_enricher import MetadataEnricher
from src.lifecycle.data_lifecycle_manager import DataLifecycleManager
from src.health.health_monitoring_manager import HealthMonitoringManager
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


def process_pcap_file(
    filepath: Path,
    parser: PcapParser,
    enricher: MetadataEnricher,
    lifecycle: DataLifecycleManager,
) -> None:
    logger.info(f"Processing: {filepath.name}")
    try:
        packets = parser.parse(filepath)
        if not packets:
            logger.info(f"No packets in {filepath.name}, skipping.")
            filepath.unlink(missing_ok=True)
            return

        enriched = enricher.enrich_batch(packets)
        lifecycle.save_batch(enriched)
        lifecycle.cleanup_pcap(filepath)
        logger.info(f"Done: {filepath.name} - {len(enriched)} packets ingested.")
    except Exception as e:
        logger.exception(f"Failed to process {filepath.name}: {e}")


def scan_inbox(
    parser: PcapParser,
    enricher: MetadataEnricher,
    lifecycle: DataLifecycleManager,
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

    # Any .pcap not modified in the last READY_AGE_SECONDS
    now = time.time()
    for pcap in PCAP_INBOX_DIR.glob("*.pcap"):
        if (now - pcap.stat().st_mtime) > READY_AGE_SECONDS:
            candidates.add(pcap)

    for filepath in sorted(candidates):
        process_pcap_file(filepath, parser, enricher, lifecycle)


def main() -> None:
    logger.info("=== Network Telescope - Processing Node Starting ===")
    PCAP_INBOX_DIR.mkdir(parents=True, exist_ok=True)

    metrics_port = int(os.environ.get("METRICS_PORT", "8000"))
    _start_metrics_server(metrics_port)
    logger.info(f"Prometheus metrics available on :{metrics_port}/metrics")

    db = get_client()
    parser = PcapParser()
    enricher = MetadataEnricher()
    lifecycle = DataLifecycleManager(db)
    health_mgr = HealthMonitoringManager(db)

    schedule.every(5).minutes.do(health_mgr.run)

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
            scan_inbox(parser, enricher, lifecycle)
            schedule.run_pending()
        except Exception as e:
            logger.exception(f"Unexpected error in main loop: {e}")
        time.sleep(POLL_INTERVAL_SECONDS)

    logger.info("Processing node stopped.")


if __name__ == "__main__":
    main()
