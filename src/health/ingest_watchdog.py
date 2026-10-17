from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path

import requests
from prometheus_client import Counter, Gauge

from src.health.health_monitoring_manager import _query_prometheus

logger = logging.getLogger(__name__)

SECONDS_SINCE_LAST_FILE = Gauge(
    "telescope_seconds_since_last_file",
    "Seconds since the newest PCAP file (by modification time, ~capture time) reached the processing node",
)
SEQUENCE_GAPS = Counter(
    "telescope_capture_sequence_gaps_total",
    "Capture files missing from the numbering (lost, overwritten or never transferred)",
)

# capture_<sequence>_<YYYYMMDDHHMMSS>.pcap
CAPTURE_FILE = re.compile(r"^capture_(\d+)_(\d{14})\.pcap(\.zst)?$")
INGEST_STALE_SECONDS = int(os.environ.get("INGEST_STALE_SECONDS", "7200"))
GAP_GRACE_SECONDS = 3 * 3600
GAP_LOOKBACK_SECONDS = 24 * 3600
ALERT_REPEAT_SECONDS = 6 * 3600
MAX_GAPS_IN_MESSAGE = 5


class IngestWatchdog:
    def __init__(self, inbox: Path, archive: Path, quarantine: Path):
        self._dirs = (inbox, archive, quarantine)
        self._inbox = inbox
        self._prometheus_url = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
        self._alert_webhook = os.environ.get("ALERT_WEBHOOK_URL", "")
        self._started = time.time()
        self._stale = False
        self._stale_last_alert = 0.0
        self._reported_gaps: set[tuple[str, str]] = set()

    def _send_alert(self, msg: str) -> None:
        if not self._alert_webhook:
            return
        try:
            requests.post(self._alert_webhook, json={"text": msg}, timeout=5)
        except Exception as e:
            logger.warning(f"Alert webhook failed: {e}")

    def _files(self) -> list[tuple[Path, float]]:
        """(path, mtime) of every PCAP in the inbox, archive and quarantine."""
        found = []
        for d in self._dirs:
            for p in d.iterdir():
                if p.is_file() and (p.suffix == ".pcap" or p.name.endswith(".pcap.zst")):
                    found.append((p, p.stat().st_mtime))
        return found

    def run(self) -> None:
        now = time.time()
        files = self._files()
        self._check_stale(now, files)
        self._check_gaps(now, files)

    def _check_stale(self, now: float, files: list[tuple[Path, float]]) -> None:
        newest = max(files, key=lambda f: f[1]) if files else None
        age = now - (newest[1] if newest else self._started)
        SECONDS_SINCE_LAST_FILE.set(age)

        if age <= INGEST_STALE_SECONDS:
            if self._stale:
                msg = f"[Network Telescope] PCAP files are arriving again (newest: {newest[0].name if newest else '-'})"
                logger.info(msg)
                self._send_alert(msg)
            self._stale = False
            return

        if not self._stale or now - self._stale_last_alert > ALERT_REPEAT_SECONDS:
            msg = (
                f"[Network Telescope] NO NEW PCAP FILES for {age / 3600:.1f} h "
                f"(threshold {INGEST_STALE_SECONDS / 3600:.1f} h); newest: {newest[0].name if newest else 'none yet'}. "
                + self._diagnosis(now)
            )
            logger.warning(msg)
            self._send_alert(msg)
            self._stale_last_alert = now
        self._stale = True

    def _diagnosis(self, now: float) -> str:
        """Where to look first, from what the processing node can see."""
        waiting = [p.stat().st_mtime for p in self._inbox.glob("*.pcap")]
        if waiting:
            oldest = (now - min(waiting)) / 3600
            return (
                f"{len(waiting)} file(s) are waiting in the inbox (oldest {oldest:.1f} h): "
                "the processing pipeline looks stuck - see `journalctl -u nt-processing`."
            )
        up = _query_prometheus(self._prometheus_url, 'up{job="capturing-node"}')
        if up == 0.0:
            return "Inbox is empty and the capturing node's exporter is unreachable: the capturing node is probably down."
        if up == 1.0:
            return "Inbox is empty and the capturing node is reachable: check nt-capture, nt-file-detector and the transfer."
        return "Inbox is empty; could not tell whether the capturing node is reachable (no Prometheus data)."

    def _check_gaps(self, now: float, files: list[tuple[Path, float]]) -> None:
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
            key = (prev_name, cur_name)
            if key in self._reported_gaps:
                continue
            self._reported_gaps.add(key)
            new_gaps.append((first_missing, cur_seq - 1, prev_name, cur_name))

        if not new_gaps:
            return
        lost = sum(last - first + 1 for first, last, _, _ in new_gaps)
        SEQUENCE_GAPS.inc(lost)
        lines = [
            f"capture_{first:05d}" + (f"..{last:05d}" if last > first else "") + f" missing between {a} and {b}"
            for first, last, a, b in new_gaps[:MAX_GAPS_IN_MESSAGE]
        ]
        extra = f" (+{len(new_gaps) - MAX_GAPS_IN_MESSAGE} more)" if len(new_gaps) > MAX_GAPS_IN_MESSAGE else ""
        msg = (
            f"[Network Telescope] CAPTURE FILE(S) MISSING ({lost}): " + "; ".join(lines) + extra
            + ". Lost on the capturing node (ring buffer overwrite, failed transfer) or removed by hand."
        )
        logger.warning(msg)
        self._send_alert(msg)
