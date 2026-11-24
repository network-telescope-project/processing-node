from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from src.health import alerts
from src.health.prometheus import Prometheus
from src.registry.sensor_registry import LOCAL_SENSOR_ID

logger = logging.getLogger(__name__)

DISK_LOW_THRESHOLD_PCT = float(os.environ.get("DISK_LOW_THRESHOLD_PCT", "20"))
CAPTURE_CPU_ALERT_PCT = 80      # of one CPU core
NET_DROP_ALERT_PCT = 1          # of the received packets
RING_ALERT_FRACTION = 0.5       # of the files the capture node keeps before it deletes the oldest
METRICS_MAX_AGE = 600           # seconds; the node writes its own metrics (nt_*) every minute
GB = 1024 ** 3

PROCESSING_NODE = "_processing"     # sensor_id of this machine's own rows

# Column of telescope_health -> PromQL; SEL is replaced by the labels that select the machine.
HOST_METRICS = {
    "cpu_busy_pct": '100 * (1 - sum(rate(node_cpu_seconds_total{SEL,mode="idle"}[5m])) / sum(rate(node_cpu_seconds_total{SEL}[5m])))',
    "mem_avail_pct": "100 * max(node_memory_MemAvailable_bytes{SEL}) / max(node_memory_MemTotal_bytes{SEL})",
    "net_rx_pps": 'sum(rate(node_network_receive_packets_total{SEL,device!~"lo|wg-.*|docker.*|br-.*|veth.*"}[5m]))',
    "net_drop_pps": 'sum(rate(node_network_receive_drop_total{SEL,device!~"lo|wg-.*|docker.*|br-.*|veth.*"}[5m]))',
    "softnet_drop_pps": "sum(rate(node_softnet_dropped_total{SEL}[5m]))",
    "disk_io_util": "max(rate(node_disk_io_time_seconds_total{SEL}[5m]))",
    "clock_synced": "max(node_timex_sync_status{SEL})",
    "clock_offset_s": "max(node_timex_offset_seconds{SEL})",
}
# Written by the capturing node itself (monitoring/node_metrics.sh)
CAPTURE_METRICS = {
    "capture_running": "max(nt_capture_running{SEL})",
    "capture_cpu_pct": "100 * sum(rate(nt_capture_cpu_seconds_total{SEL}[10m]))",
    "capture_last_loss": "max(nt_capture_last_loss_packets{SEL})",
    "units_down": "sum(1 - nt_unit_active{SEL})",
    "unsent_files": "max(nt_unsent_files{SEL})",
    "unsent_oldest_s": "max(nt_unsent_oldest_seconds{SEL})",
}
INTEGER_COLUMNS = {"clock_synced", "capture_running", "capture_last_loss", "units_down", "unsent_files", "unsent_oldest_s"}

HEALTH_COLUMNS = [
    "ts", "sensor_id", "exporter_up", "problems", "disk_avail_bytes", "disk_size_bytes", *HOST_METRICS, *CAPTURE_METRICS,
]


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
    """Every run: one telescope_health row per capturing node and one for processing node, and alerts on what is wrong.
    A value that could not be read is NULL."""

    def __init__(self, db_client, registry):
        self._db = db_client
        self._registry = registry
        self._prom = Prometheus()
        self._conditions = alerts.Conditions("health")

    def run(self) -> None:
        logger.info("Running health check...")
        reachable = self._prom.series("up") is not None
        self._conditions.update(
            ("prometheus",),
            None if reachable else "PROMETHEUS does not answer: the health of the nodes is unknown (docker ps; is nt_prometheus running?)",
            "Prometheus answers again",
            after=2, level=logging.ERROR,
        )
        sensors, error = None, None
        try:
            sensors = self._registry.monitored_ids()
        except Exception as e:
            logger.error(f"Could not read the sensor registry, health check skipped: {e}")
            error = "CLICKHOUSE does not answer: nothing is ingested (docker ps; is nt_clickhouse running?)"
        self._conditions.update(("clickhouse",), error, "ClickHouse answers again", after=2, level=logging.ERROR)
        if sensors is None:
            return

        capture_path = os.environ.get("CAPTURE_MOUNTPOINT", "/var/lib/network-telescope")
        for sensor in sensors:
            self._check_node(sensor, f'job="capturing-node",sensor="{sensor}"', [capture_path], reachable, capturing=True)
        if sensors != [LOCAL_SENSOR_ID]:
            paths = [
                os.environ.get("PCAP_ARCHIVE_DIR", "/var/lib/network-telescope/data/archive"),
                os.environ.get("CLICKHOUSE_DATA_DIR", "/var/lib/network-telescope/clickhouse"),
            ]
            self._check_node(PROCESSING_NODE, 'job="processing-node"', paths, reachable, capturing=False)

    # One machine
    def _collect(self, sel: str, paths: list[str], capturing: bool) -> dict[str, Any]:
        m: dict[str, Any] = dict.fromkeys([*HOST_METRICS, *CAPTURE_METRICS])
        # Down only if every scrape of the last minutes failed
        m["exporter_up"] = self._prom.value(f"max(max_over_time(up{{{sel}}}[5m]))")

        queries = dict(HOST_METRICS)
        if capturing:
            age = self._prom.value(f'time() - max(node_textfile_mtime_seconds{{{sel},file=~".*nt.prom"}})')
            m["metrics_fresh"] = None if age is None else age <= METRICS_MAX_AGE
            if m["metrics_fresh"]:
                queries |= CAPTURE_METRICS
                m["last_loss"] = self._prom.value(f"max(nt_capture_last_loss_seconds{{{sel}}})")
                m["ring_limit"] = self._prom.value(f"max(nt_ring_limit_files{{{sel}}})")
                m["down_units"] = sorted(
                    labels.get("unit", "?") for labels, _ in self._prom.series(f"nt_unit_active{{{sel}}} == 0") or []
                )
        for column, query in queries.items():
            m[column] = self._prom.value(query.replace("SEL", sel))

        avail = self._prom.series(f"node_filesystem_avail_bytes{{{sel}}}") or []
        size = self._prom.series(f"node_filesystem_size_bytes{{{sel}}}") or []
        found = [fs for fs in (find_filesystem(p, avail, size) for p in paths) if fs]
        m["fs"] = min(found, key=lambda fs: fs[1] / fs[2]) if found else None
        m["disk_avail_bytes"] = m["fs"][1] if m["fs"] else None
        m["disk_size_bytes"] = m["fs"][2] if m["fs"] else None
        return m

    def _check_node(self, node: str, sel: str, paths: list[str], reachable: bool, capturing: bool) -> None:
        ts = datetime.now(tz=timezone.utc)
        m = self._collect(sel, paths, capturing)
        problems = self._check(node, m, reachable, capturing)

        row = {**m, "ts": ts, "sensor_id": node, "problems": problems}
        for column in (*INTEGER_COLUMNS, "exporter_up"):
            if row[column] is not None:
                row[column] = max(0, round(row[column]))
        try:
            self._db.insert("telescope_health", [[row[c] for c in HEALTH_COLUMNS]], column_names=HEALTH_COLUMNS)
            logger.info(f"Health snapshot saved for {node}: {', '.join(problems) if problems else 'no problems'}")
        except Exception as e:
            logger.error(f"Failed to write health snapshot: {e}")

    def _check(self, node: str, m: dict[str, Any], reachable: bool, capturing: bool) -> list[str]:
        """The problems of a machine (their names)."""
        name = "processing node" if node == PROCESSING_NODE else node
        problems: list[str] = []

        def check(problem: str, is_on: bool, msg: str, resolved: str, after: int = 1, level: int = logging.WARNING) -> None:
            if self._conditions.update((node, problem), f"{name}: {msg}" if is_on else None, f"{name}: {resolved}", after, level):
                problems.append(problem)

        if not reachable or (node == LOCAL_SENSOR_ID and m["exporter_up"] is None):
            return problems

        check(
            "exporter", m["exporter_up"] != 1.0,
            "UNREACHABLE: its node-exporter does not answer (node or tunnel down?)" if m["exporter_up"] == 0.0
            else "NOT MONITORED: Prometheus does not scrape its node-exporter",
            "reachable again", after=1 if m["exporter_up"] == 0.0 else 4, level=logging.ERROR,
        )
        if m["exporter_up"] != 1.0:
            return problems

        if m["fs"]:
            mount, avail, size = m["fs"]
            pct = avail / size * 100
            text = f"{pct:.1f}% free ({avail / GB:.1f} of {size / GB:.1f} GB on {mount})"
            check("disk", pct < DISK_LOW_THRESHOLD_PCT, f"DISK LOW: {text}, threshold {DISK_LOW_THRESHOLD_PCT:.0f}%", f"disk OK again: {text}", level=logging.ERROR)
        if m["clock_synced"] is not None:
            check("clock", m["clock_synced"] == 0, "CLOCK NOT SYNCHRONISED: it will drift", "clock synchronised again", after=3)
        if m["softnet_drop_pps"] is not None:
            check("softnet", m["softnet_drop_pps"] > 1, f"KERNEL DROPS PACKETS: {m['softnet_drop_pps']:.1f}/s (CPU overloaded)", "kernel packet drops are over", after=2)
        if m["net_drop_pps"] is not None and m["net_rx_pps"]:
            pct = 100 * m["net_drop_pps"] / m["net_rx_pps"]
            check("nic", m["net_drop_pps"] > 1 and pct > NET_DROP_ALERT_PCT, f"NIC DROPS PACKETS: {m['net_drop_pps']:.1f}/s ({pct:.1f}%)", "NIC packet drops are over", after=2)
        if not capturing:
            return problems

        check("metrics", not m["metrics_fresh"], "its own metrics are missing or old (nt-metrics.timer)", "its own metrics are back", after=2)
        if not m["metrics_fresh"]:
            return problems
        if m["capture_running"] is not None:
            check("capture", m["capture_running"] == 0, "CAPTURE NOT RUNNING: no dumpcap process", "capture is running again", level=logging.ERROR)
        units = [u for u in m["down_units"] if u != "nt-capture.service"]      # that one is the check above
        check("units", bool(units), f"SERVICES DOWN: {', '.join(units)}", "all services are running again", after=2, level=logging.ERROR)
        if m["capture_cpu_pct"] is not None:
            check("capture_cpu", m["capture_cpu_pct"] > CAPTURE_CPU_ALERT_PCT, f"dumpcap uses {m['capture_cpu_pct']:.0f}% of a CPU core: it may be losing packets", "dumpcap CPU usage is normal again", after=2)
        if m["unsent_files"] is not None and m["ring_limit"]:
            check(
                "unsent", m["unsent_files"] >= RING_ALERT_FRACTION * m["ring_limit"],
                f"{m['unsent_files']:.0f} PCAP FILES NOT TRANSFERRED (oldest {(m['unsent_oldest_s'] or 0) / 3600:.1f} h): beyond {m['ring_limit']:.0f} files the node deletes the oldest",
                "the transfer has caught up", level=logging.ERROR,
            )
        self._report_drops(node, m)
        return problems

    def _report_drops(self, node: str, m: dict[str, Any]) -> None:
        """dumpcap says how many packets it lost when it stops"""
        ended = m.get("last_loss")
        if ended and m["capture_last_loss"] and alerts.once(("loss", node, int(ended))):
            alerts.send(
                f"{node}: dumpcap LOST {m['capture_last_loss']:.0f} PACKETS in the capture that ended at "
                f"{datetime.fromtimestamp(ended, timezone.utc):%Y-%m-%d %H:%M} UTC",
                logging.ERROR,
            )
