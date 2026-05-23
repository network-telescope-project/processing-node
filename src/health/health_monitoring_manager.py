from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import requests

logger = logging.getLogger(__name__)

NIC_DROP_THRESHOLD = float(os.environ.get("NIC_DROP_THRESHOLD", "0.90"))

HEALTH_COLUMNS = [
    "ts",
    "ingestion_pps",
    "rx_dropped_rate",
    "rx_missed_rate",
    "rx_fifo_rate",
    "udp_rx_errors",
    "disk_avail_bytes",
    "disk_io_util",
    "dumpcap_cpu_pct",
    "nic_temp_celsius",
    "pps_drop_alert",
]


def _query_prometheus(prometheus_url: str, metric: str) -> float | None:
    try:
        resp = requests.get(
            f"{prometheus_url}/api/v1/query",
            params={"query": metric},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get("data", {}).get("result", [])
        if results:
            return float(results[0]["value"][1])
        return None
    except Exception as e:
        logger.warning(f"Prometheus query failed [{metric}]: {e}")
        return None


class HealthMonitoringManager:
    def __init__(self, db_client):
        self._db = db_client
        self._prometheus_url = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
        self._alert_webhook = os.environ.get("ALERT_WEBHOOK_URL", "")

    def _q(self, metric: str) -> float:
        result = _query_prometheus(self._prometheus_url, metric)
        if result is None:
            return 0.0
        return result

    def _collect_metrics(self) -> dict[str, Any]:
        m: dict[str, Any] = {}

        # Reflects actual packets reaching the DB, not just arriving at the NIC
        m["ingestion_pps"] = self._q("rate(telescope_packets_ingested_total[5m])")

        # NIC health
        m["rx_dropped_rate"] = self._q("rate(node_ethtool_rx_dropped_total[5m])")
        m["rx_missed_rate"] = self._q("rate(node_ethtool_rx_missed_errors_total[5m])")
        m["rx_fifo_rate"] = self._q("rate(node_ethtool_rx_fifo_errors_total[5m])")
        m["udp_rx_errors"] = self._q("node_netstat_Udp_RxErrors")

        # Disk health
        capture_mount = os.environ.get("CAPTURE_MOUNTPOINT", "/var/lib/network-telescope")
        m["disk_avail_bytes"] = self._q(f'node_filesystem_avail_bytes{{mountpoint="{capture_mount}"}}')
        m["disk_io_util"] = self._q("rate(node_disk_io_time_seconds_total[5m])")

        # Process health
        m["dumpcap_cpu_pct"] = self._q('rate(namedprocess_namegroup_cpu_seconds_total{groupname="dumpcap"}[5m]) * 100')
        m["nic_temp_celsius"] = self._q("node_hwmon_temp_celsius")

        return m

    def _check_nic_drop(self, rx_dropped_rate: float) -> bool:
        if rx_dropped_rate > NIC_DROP_THRESHOLD:
            msg = (
                f"[Network Telescope] NIC DROP ALERT: "
                f"rx_dropped_rate={rx_dropped_rate:.2f} pkt/s "
                f"(threshold={NIC_DROP_THRESHOLD:.1f})"
            )
            logger.warning(msg)
            if self._alert_webhook:
                try:
                    requests.post(self._alert_webhook, json={"text": msg}, timeout=5)
                except Exception as e:
                    logger.warning(f"Alert webhook failed: {e}")
            return True
        return False

    def run(self) -> None:
        ts = datetime.now(tz=timezone.utc)
        logger.info("Running health check...")

        metrics = self._collect_metrics()
        pps_drop_alert = self._check_nic_drop(metrics["rx_dropped_rate"])

        row = [[
            ts,
            metrics["ingestion_pps"],
            metrics["rx_dropped_rate"],
            metrics["rx_missed_rate"],
            metrics["rx_fifo_rate"],
            metrics["udp_rx_errors"],
            metrics["disk_avail_bytes"],
            metrics["disk_io_util"],
            metrics["dumpcap_cpu_pct"],
            metrics["nic_temp_celsius"],
            pps_drop_alert,
        ]]

        try:
            self._db.insert("telescope_health", row, column_names=HEALTH_COLUMNS)
            logger.info(f"Health snapshot saved. ingestion_pps={metrics['ingestion_pps']:.1f}, rx_dropped={metrics['rx_dropped_rate']:.2f}/s")
        except Exception as e:
            logger.error(f"Failed to write health snapshot: {e}")
