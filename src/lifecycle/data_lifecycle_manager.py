from __future__ import annotations

import logging
import os
import time
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from prometheus_client import Counter

logger = logging.getLogger(__name__)

PACKETS_INGESTED = Counter(
    "telescope_packets_ingested_total",
    "Total number of packet records inserted into ClickHouse",
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

    def cleanup_pcap(self, filepath: Path) -> None:
        try:
            filepath.unlink(missing_ok=True)
            logger.info(f"Deleted: {filepath.name}")
        except Exception as e:
            logger.warning(f"Could not delete {filepath}: {e}")
