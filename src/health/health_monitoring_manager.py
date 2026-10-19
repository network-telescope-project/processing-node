from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import requests

logger = logging.getLogger(__name__)

NIC_DROP_THRESHOLD = float(os.environ.get("NIC_DROP_THRESHOLD", "0.90"))
DISK_LOW_THRESHOLD_PCT = float(os.environ.get("DISK_LOW_THRESHOLD_PCT", "20"))
DISK_ALERT_REPEAT_SECONDS = 6 * 3600
GB = 1024 ** 3

HEALTH_COLUMNS = [
    "ts",
    "sensor_id",
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


def _query_prometheus_series(prometheus_url: str, metric: str) -> list[tuple[dict, float]]:
    """All series of a query as (labels, value); empty if the query fails or matches nothing."""
    try:
        resp = requests.get(
            f"{prometheus_url}/api/v1/query",
            params={"query": metric},
            timeout=10,
        )
        resp.raise_for_status()
        results = resp.json().get("data", {}).get("result", [])
        return [(r["metric"], float(r["value"][1])) for r in results]
    except Exception as e:
        logger.warning(f"Prometheus query failed [{metric}]: {e}")
        return []


def find_filesystem(path: str, avail: list[tuple[dict, float]], size: list[tuple[dict, float]]):
    """(mountpoint, avail_bytes, size_bytes) of the filesystem holding `path`"""
    sizes = {(l.get("device"), l.get("mountpoint")): v for l, v in size}
    best = None
    for labels, avail_bytes in avail:
        mount = labels.get("mountpoint", "")
        if path != mount and not path.startswith(mount.rstrip("/") + "/"):
            continue
        total = sizes.get((labels.get("device"), mount))
        if total and (best is None or len(mount) > len(best[0])):
            best = (mount, avail_bytes, total)
    return best


class HealthMonitoringManager:
    def __init__(self, db_client, registry):
        self._db = db_client
        self._registry = registry
        self._prometheus_url = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
        self._alert_webhook = os.environ.get("ALERT_WEBHOOK_URL", "")
        self._disk_state: dict[str, str] = {}  # per sensor: ok | low | unknown
        self._disk_last_alert: dict[str, float] = {}

    def _q(self, metric: str) -> float:
        result = _query_prometheus(self._prometheus_url, metric)
        if result is None:
            return 0.0
        return result

    def _collect_metrics(self, sensor: str) -> dict[str, Any]:
        m: dict[str, Any] = {}
        # The sensor label is put on the capturing node's exporter target by Prometheus (see the sensor registry)
        node = f'job="capturing-node",sensor="{sensor}"'

        # Reflects actual packets reaching the DB, not just arriving at the NIC
        m["ingestion_pps"] = self._q(f'sum(rate(telescope_packets_ingested_total{{sensor="{sensor}"}}[5m]))')

        # NIC health
        m["rx_dropped_rate"] = self._q(f"rate(node_ethtool_rx_dropped_total{{{node}}}[5m])")
        m["rx_missed_rate"] = self._q(f"rate(node_ethtool_rx_missed_errors_total{{{node}}}[5m])")
        m["rx_fifo_rate"] = self._q(f"rate(node_ethtool_rx_fifo_errors_total{{{node}}}[5m])")
        m["udp_rx_errors"] = self._q(f"node_netstat_Udp_RxErrors{{{node}}}")

        # TODO make these queries adaptive rather than hardcoded
        # Disk health
        capture_path = os.environ.get("CAPTURE_MOUNTPOINT", "/var/lib/network-telescope")
        fs = find_filesystem(
            capture_path,
            _query_prometheus_series(self._prometheus_url, f"node_filesystem_avail_bytes{{{node}}}"),
            _query_prometheus_series(self._prometheus_url, f"node_filesystem_size_bytes{{{node}}}"),
        )
        m["capture_path"] = capture_path
        m["capture_fs"] = fs
        m["disk_avail_bytes"] = fs[1] if fs else 0.0
        m["disk_io_util"] = self._q(f"rate(node_disk_io_time_seconds_total{{{node}}}[5m])")

        # Process health
        m["dumpcap_cpu_pct"] = self._q(f'rate(namedprocess_namegroup_cpu_seconds_total{{{node},groupname="dumpcap"}}[5m]) * 100')
        m["nic_temp_celsius"] = self._q(f"node_hwmon_temp_celsius{{{node}}}")

        return m

    def _check_nic_drop(self, sensor: str, rx_dropped_rate: float) -> bool:
        if rx_dropped_rate > NIC_DROP_THRESHOLD:
            msg = (
                f"[Network Telescope] {sensor}: NIC DROP ALERT: "
                f"rx_dropped_rate={rx_dropped_rate:.2f} pkt/s "
                f"(threshold={NIC_DROP_THRESHOLD:.1f})"
            )
            logger.warning(msg)
            self._send_alert(msg)
            return True
        return False

    def _send_alert(self, msg: str) -> None:
        if not self._alert_webhook:
            return
        try:
            requests.post(self._alert_webhook, json={"text": msg}, timeout=5)
        except Exception as e:
            logger.warning(f"Alert webhook failed: {e}")

    def _check_disk(self, sensor: str, capture_path: str, fs) -> None:
        """Alert when the capture node's disk runs low."""
        now = time.time()
        previous = self._disk_state.get(sensor, "ok")
        if fs is None:
            state, msg = "unknown", (
                f"[Network Telescope] {sensor}: CAPTURE DISK UNKNOWN: no filesystem metrics for {capture_path} "
                "from the capturing node (is its node-exporter reachable?)"
            )
        else:
            mount, avail, size = fs
            pct = avail / size * 100
            if pct >= DISK_LOW_THRESHOLD_PCT:
                if previous != "ok":
                    msg = f"[Network Telescope] {sensor}: capture disk OK again: {pct:.1f}% free ({avail / GB:.1f} GB of {size / GB:.1f} GB on {mount})"
                    logger.info(msg)
                    self._send_alert(msg)
                self._disk_state[sensor] = "ok"
                return
            state, msg = "low", (
                f"[Network Telescope] {sensor}: CAPTURE DISK LOW: {pct:.1f}% free ({avail / GB:.1f} GB of {size / GB:.1f} GB "
                f"on {mount}), threshold {DISK_LOW_THRESHOLD_PCT:.0f}%. Check the PCAP transfer to the processing node."
            )

        if state != previous or now - self._disk_last_alert.get(sensor, 0.0) > DISK_ALERT_REPEAT_SECONDS:
            logger.warning(msg)
            self._send_alert(msg)
            self._disk_last_alert[sensor] = now
        self._disk_state[sensor] = state

    def run(self) -> None:
        logger.info("Running health check...")
        try:
            sensors = self._registry.monitored_ids()
        except Exception as e:
            logger.error(f"Could not read the sensor registry, health check skipped: {e}")
            return
        for sensor in sensors:
            self._run_sensor(sensor)

    def _run_sensor(self, sensor: str) -> None:
        ts = datetime.now(tz=timezone.utc)

        metrics = self._collect_metrics(sensor)
        pps_drop_alert = self._check_nic_drop(sensor, metrics["rx_dropped_rate"])
        self._check_disk(sensor, metrics["capture_path"], metrics["capture_fs"])

        row = [[
            ts,
            sensor,
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
            logger.info(f"Health snapshot saved for {sensor}. ingestion_pps={metrics['ingestion_pps']:.1f}, rx_dropped={metrics['rx_dropped_rate']:.2f}/s")
        except Exception as e:
            logger.error(f"Failed to write health snapshot: {e}")
