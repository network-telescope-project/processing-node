"""Alerts for the network telescope operator: always logged, and posted to ALERT_WEBHOOK_URL (if it is set)"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)

REPEAT_SECONDS = 6 * 3600


def send(msg: str, level: int = logging.WARNING) -> None:
    logger.log(level, msg)
    url = os.environ.get("ALERT_WEBHOOK_URL", "")
    if not url:
        return
    try:
        requests.post(url, json={"text": f"[Network Telescope] {msg}"}, timeout=5).raise_for_status()
    except requests.HTTPError as e:
        logger.warning(f"Alert webhook refused the message: HTTP {e.response.status_code}")
    except Exception as e:
        logger.warning(f"Alert webhook failed: {type(e).__name__}")


@dataclass
class _State:
    seen: int = 0
    last_alert: float = 0.0


class Conditions:
    def __init__(self, repeat_seconds: float = REPEAT_SECONDS):
        self._repeat = repeat_seconds
        self._states: dict[tuple, _State] = {}

    def update(self, key: tuple, problem: str | None, resolved: str = "", after: int = 1) -> bool:
        if problem is None:
            state = self._states.pop(key, None)
            if state and state.last_alert and resolved:
                send(resolved, logging.INFO)
            return False

        state = self._states.setdefault(key, _State())
        state.seen += 1
        if state.seen < after:
            return False
        now = time.time()
        if now - state.last_alert > self._repeat:
            send(problem)
            state.last_alert = now
        return True
