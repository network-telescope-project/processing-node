from __future__ import annotations

import logging
import os
import re
import time
from collections import defaultdict
from pathlib import Path

import requests
from prometheus_client import Counter, Gauge

from src.health.health_monitoring_manager import _query_prometheus
from src.registry.sensor_registry import LOCAL_SENSOR_ID, SensorRegistry

logger = logging.getLogger(__name__)

SECONDS_SINCE_LAST_FILE = Gauge(
    "telescope_seconds_since_last_file",
    "Seconds since the newest PCAP file (by modification time, ~capture time) of the sensor reached the processing node",
    ["sensor"],
)
SEQUENCE_GAPS = Counter(
    "telescope_capture_sequence_gaps_total",
    "Capture files missing from a sensor's numbering (lost, overwritten or never transferred)",
    ["sensor"],
)

# capture_<sequence>_<YYYYMMDDHHMMSS>.pcap
CAPTURE_FILE = re.compile(r"^capture_(\d+)_(\d{14})\.pcap(\.zst)?$")
INGEST_STALE_SECONDS = int(os.environ.get("INGEST_STALE_SECONDS", "7200"))
GAP_GRACE_SECONDS = 3 * 3600
GAP_LOOKBACK_SECONDS = 24 * 3600
ALERT_REPEAT_SECONDS = 6 * 3600
MAX_GAPS_IN_MESSAGE = 5


class IngestWatchdog:
    """Per sensor: alerts when its files stop arriving and when its capture file numbering has gaps"""

    def __init__(self, inbox: Path, archive: Path, quarantine: Path, registry: SensorRegistry):
        self._inbox = inbox
        self._archive = archive
        self._quarantine = quarantine
        self._registry = registry
        self._prometheus_url = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
        self._alert_webhook = os.environ.get("ALERT_WEBHOOK_URL", "")
        self._started = time.time()
        self._stale: dict[str, bool] = {}
        self._stale_last_alert: dict[str, float] = {}
        self._reported_gaps: set[tuple[str, str, str]] = set()

    def _send_alert(self, msg: str) -> None:
        if not self._alert_webhook:
            return
        try:
            requests.post(self._alert_webhook, json={"text": msg}, timeout=5)
        except Exception as e:
            logger.warning(f"Alert webhook failed: {e}")

    def _files(self) -> dict[str, list[tuple[Path, float]]]:
        """(path, mtime) of every PCAP in the inbox, archive and quarantine, by sensor."""
        found: dict[str, list[tuple[Path, float]]] = defaultdict(list)

        def add(sensor: str, p: Path) -> None:
            try:
                if p.is_file() and (p.suffix == ".pcap" or p.name.endswith(".pcap.zst")):
                    found[sensor].append((p, p.stat().st_mtime))
            except FileNotFoundError:
                pass    # moved by the ingest while listing

        for p in self._inbox.iterdir():
            if p.is_dir():
                for q in p.iterdir():
                    add(p.name, q)
            else:
                add(LOCAL_SENSOR_ID, p)       # directly in the inbox: the single-node local setup
        for root in (self._archive, self._quarantine):
            for sub in root.iterdir():
                if sub.is_dir():
                    for q in sub.iterdir():
                        add(sub.name, q)
        return found

    def run(self) -> None:
        now = time.time()
        files = self._files()
        try:
            sensors = self._registry.monitored_ids()
        except Exception as e:
            logger.warning(f"Could not read the sensor registry, checking the sensors seen in the files: {e}")
            sensors = sorted(files)
        for sensor in sensors:
            self._check_stale(sensor, now, files.get(sensor, []))
            self._check_gaps(sensor, now, files.get(sensor, []))

    def _check_stale(self, sensor: str, now: float, files: list[tuple[Path, float]]) -> None:
        newest = max(files, key=lambda f: f[1]) if files else None
        age = now - (newest[1] if newest else self._started)
        SECONDS_SINCE_LAST_FILE.labels(sensor=sensor).set(age)

        if age <= INGEST_STALE_SECONDS:
            if self._stale.get(sensor):
                msg = f"[Network Telescope] {sensor}: PCAP files are arriving again (newest: {newest[0].name if newest else '-'})"
                logger.info(msg)
                self._send_alert(msg)
            self._stale[sensor] = False
            return

        if not self._stale.get(sensor) or now - self._stale_last_alert.get(sensor, 0.0) > ALERT_REPEAT_SECONDS:
            msg = (
                f"[Network Telescope] {sensor}: NO NEW PCAP FILES for {age / 3600:.1f} h "
                f"(threshold {INGEST_STALE_SECONDS / 3600:.1f} h); newest: {newest[0].name if newest else 'none yet'}. "
                + self._diagnosis(sensor, now)
            )
            logger.warning(msg)
            self._send_alert(msg)
            self._stale_last_alert[sensor] = now
        self._stale[sensor] = True

    def _diagnosis(self, sensor: str, now: float) -> str:
        """Where to look first, from what the processing node can see."""
        inbox = self._inbox if sensor == LOCAL_SENSOR_ID else self._inbox / sensor
        waiting = []
        for p in inbox.glob("*.pcap"):
            try:
                waiting.append(p.stat().st_mtime)
            except FileNotFoundError:
                pass
        if waiting:
            oldest = (now - min(waiting)) / 3600
            return (
                f"{len(waiting)} file(s) are waiting in the inbox (oldest {oldest:.1f} h): "
                "the processing pipeline looks stuck or holds them (sensor not ready) - see `journalctl -u nt-processing`."
            )
        up = _query_prometheus(self._prometheus_url, f'up{{job="capturing-node",sensor="{sensor}"}}')
        if up == 0.0:
            return "Inbox is empty and the capturing node's exporter is unreachable: the capturing node is probably down."
        if up == 1.0:
            return "Inbox is empty and the capturing node is reachable: check nt-capture, nt-file-detector and the transfer."
        return "Inbox is empty; could not tell whether the capturing node is reachable (no Prometheus data)."

    def _check_gaps(self, sensor: str, now: float, files: list[tuple[Path, float]]) -> None:
        named = []
        for path, mtime in files:
            m = CAPTURE_FILE.match(path.name)
            if m:
                named.append((m.group(2), int(m.group(1)), path.name, mtime))
        named.sort()

        new_gaps = []
        for (_, prev_seq, prev_name, _), (_, cur_seq, cur_name, cur_mtime) in zip(named, named[1:]):
            # The sequence restarts at 1 whenever dumpcap restarts; a restart that does not
            # begin at 1 means the files before it are missing
            first_missing = prev_seq + 1 if cur_seq > prev_seq else 1
            if cur_seq == 1 or cur_seq == first_missing:
                continue
            age = now - cur_mtime   # file modification time ~ capture time, independent of time zones
            if not GAP_GRACE_SECONDS <= age <= GAP_LOOKBACK_SECONDS:
                continue
            key = (sensor, prev_name, cur_name)
            if key in self._reported_gaps:
                continue
            self._reported_gaps.add(key)
            new_gaps.append((first_missing, cur_seq - 1, prev_name, cur_name))

        if not new_gaps:
            return
        lost = sum(last - first + 1 for first, last, _, _ in new_gaps)
        SEQUENCE_GAPS.labels(sensor=sensor).inc(lost)
        lines = [
            f"capture_{first:05d}" + (f"..{last:05d}" if last > first else "") + f" missing between {a} and {b}"
            for first, last, a, b in new_gaps[:MAX_GAPS_IN_MESSAGE]
        ]
        extra = f" (+{len(new_gaps) - MAX_GAPS_IN_MESSAGE} more)" if len(new_gaps) > MAX_GAPS_IN_MESSAGE else ""
        msg = (
            f"[Network Telescope] {sensor}: CAPTURE FILE(S) MISSING ({lost}): " + "; ".join(lines) + extra
            + ". Lost on the capturing node (ring buffer overwrite, failed transfer) or removed by hand."
        )
        logger.warning(msg)
        self._send_alert(msg)
