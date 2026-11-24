"""Alerts for the network telescope operator: always logged, and posted to Slack (ALERT_WEBHOOK_URL, if it is set)"""
from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

RESOLVED = 25
logging.addLevelName(RESOLVED, "RESOLVED")
ICONS = {logging.ERROR: "🔴", logging.WARNING: "🟡", RESOLVED: "🟢", logging.INFO: "🔵"}

REPEAT_SECONDS = 6 * 3600
STATE_MAX_AGE = 30 * 86400

# Delivery
MAX_LENGTH = 3000
QUEUE_SIZE = 200
RETRY_SECONDS = 6 * 3600
MAX_BACKOFF = 300
LATE_SECONDS = 120
FLOOD_MESSAGES = 20
FLOOD_SECONDS = 600


@dataclass
class _Message:
    text: str
    level: int
    raised: float = field(default_factory=time.time)


def _post(url: str, text: str) -> float | None:
    for char, entity in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;")):
        text = text.replace(char, entity)
    try:
        resp = requests.post(
            url, json={"text": text, "mrkdwn": False, "unfurl_links": False}, timeout=10, allow_redirects=False
        )
    except ValueError:
        logger.error("Alert webhook: ALERT_WEBHOOK_URL is not a valid URL")
        return None
    except requests.RequestException as e:
        logger.warning(f"Alert webhook failed: {type(e).__name__}")
        return 0
    if resp.status_code == 429:
        logger.warning("Alert webhook: too many messages, slowing down")
        retry_after = resp.headers.get("Retry-After", "")
        return float(retry_after) if retry_after.isdigit() else 30
    if resp.status_code >= 500:
        logger.warning(f"Alert webhook failed: HTTP {resp.status_code}")
        return 0
    if resp.status_code != 200:
        logger.error(f"Alert webhook refused the message: HTTP {resp.status_code} {resp.text[:100]!r} (is ALERT_WEBHOOK_URL still right?)")
    return None


class _Sender:
    def __init__(self) -> None:
        self._queue: queue.Queue[_Message] = queue.Queue(QUEUE_SIZE)
        self._recent: dict[int, deque[float]] = {}
        self._suppressed: dict[int, int] = {}
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def put(self, message: _Message) -> None:
        with self._lock:
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name="alerts", daemon=True)
                self._thread.start()
        try:
            self._queue.put_nowait(message)
        except queue.Full:
            logger.error("Alert queue is full, the message is only in this log")

    def flush(self, timeout: float) -> None:
        deadline = time.time() + timeout
        while self._queue.unfinished_tasks and time.time() < deadline:
            time.sleep(0.1)

    def _run(self) -> None:
        while True:
            try:
                message = self._queue.get(timeout=30)
            except queue.Empty:
                self._report_suppressed()
                continue
            try:
                if self._allowed(message.level):
                    self._deliver(message)
                else:
                    self._suppressed[message.level] = self._suppressed.get(message.level, 0) + 1
            except Exception as e:
                logger.error(f"Alert could not be delivered: {type(e).__name__}")
            finally:
                self._queue.task_done()

    def _allowed(self, level: int) -> bool:
        now = time.time()
        recent = self._recent.setdefault(level, deque())
        while recent and now - recent[0] > FLOOD_SECONDS:
            recent.popleft()
        if len(recent) >= FLOOD_MESSAGES:
            return False
        recent.append(now)
        return True

    def _report_suppressed(self) -> None:
        for level, count in list(self._suppressed.items()):
            if self._allowed(level):
                del self._suppressed[level]
                self._deliver(_Message(f"{count} more alert(s) like these were not sent: journalctl -u nt-processing", level))

    def _deliver(self, message: _Message) -> None:
        backoff = 5.0
        while True:
            text = f"{ICONS.get(message.level, '')} [Network Telescope] {message.text[:MAX_LENGTH]}"
            if time.time() - message.raised > LATE_SECONDS:
                text += f" (raised at {datetime.fromtimestamp(message.raised, timezone.utc):%Y-%m-%d %H:%M} UTC, delivered late)"
            wait = _post(os.environ.get("ALERT_WEBHOOK_URL", ""), text)
            if wait is None:
                time.sleep(1)
                return
            if time.time() - message.raised > RETRY_SECONDS:
                logger.error("Alert given up, the message is only in this log")
                return
            time.sleep(max(wait, backoff))
            backoff = min(backoff * 2, MAX_BACKOFF)


_sender = _Sender()


def send(msg: str, level: int = logging.WARNING) -> None:
    logger.log(level, msg)
    if os.environ.get("ALERT_WEBHOOK_URL", ""):
        _sender.put(_Message(msg, level))


def flush(timeout: float = 10) -> None:
    """Wait until the messages raised so far are delivered (before the process ends)"""
    _sender.flush(timeout)


def heartbeat() -> None:
    url = os.environ.get("HEARTBEAT_URL", "")
    if not url:
        return
    try:
        requests.get(url, timeout=10).raise_for_status()
    except requests.HTTPError as e:
        logger.warning(f"Heartbeat refused: HTTP {e.response.status_code}")
    except Exception as e:
        logger.warning(f"Heartbeat failed: {type(e).__name__}")


class _Memory:
    def __init__(self) -> None:
        path = os.environ.get("ALERT_STATE_FILE", "")
        self._path = Path(path) if path else None
        self._data: dict[str, dict] = {}
        if self._path and self._path.exists():
            try:
                now = time.time()
                self._data = {k: v for k, v in json.loads(self._path.read_text()).items() if now - v["last"] < STATE_MAX_AGE}
            except Exception as e:
                self._data = {}
                logger.warning(f"Could not read {self._path}, starting without it: {e}")

    def get(self, key: str) -> dict | None:
        return self._data.get(key)

    def set(self, key: str, **values) -> None:
        self._data[key] = values
        self._save()

    def remove(self, key: str) -> dict | None:
        value = self._data.pop(key, None)
        if value is not None:
            self._save()
        return value

    def _save(self) -> None:
        if not self._path:
            return
        try:
            tmp = self._path.with_name(self._path.name + ".tmp")
            tmp.write_text(json.dumps(self._data))
            os.replace(tmp, self._path)
        except OSError as e:
            logger.warning(f"Could not write {self._path}: {e}")


_memory: _Memory | None = None


def _state() -> _Memory:
    global _memory
    if _memory is None:
        _memory = _Memory()
    return _memory


def once(key: tuple, every: float = STATE_MAX_AGE) -> bool:
    name = "once|" + "|".join(map(str, key))
    said = _state().get(name)
    if said and time.time() - said["last"] < every:
        return False
    _state().set(name, last=time.time())
    return True


def _duration(seconds: float) -> str:
    return f"{seconds / 3600:.1f} h" if seconds >= 3600 else f"{seconds / 60:.0f} min"


class Conditions:
    def __init__(self, name: str, repeat_seconds: float = REPEAT_SECONDS):
        self._name = name
        self._repeat = repeat_seconds
        self._seen: dict[str, int] = {}

    def update(
        self, key: tuple, problem: str | None, resolved: str = "", after: int = 1, level: int = logging.WARNING
    ) -> bool:
        name = "|".join(map(str, (self._name, *key)))
        now = time.time()
        if problem is None:
            self._seen.pop(name, None)
            alerted = _state().remove(name)
            if alerted and resolved:
                send(f"{resolved} (after {_duration(now - alerted['since'])})", RESOLVED)
            return False

        alerted = _state().get(name)
        if alerted is None:
            self._seen[name] = self._seen.get(name, 0) + 1
            if self._seen[name] < after:
                return False
            send(problem, level)
            _state().set(name, since=now, last=now)
        elif now - alerted["last"] > self._repeat:
            send(f"{problem} (reminder, since {datetime.fromtimestamp(alerted['since'], timezone.utc):%Y-%m-%d %H:%M} UTC)", level)
            _state().set(name, since=alerted["since"], last=now)
        return True


def _test() -> int:
    from dotenv import load_dotenv

    load_dotenv(dotenv_path=Path(__file__).parents[2] / ".env")
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    url = os.environ.get("ALERT_WEBHOOK_URL", "")
    if not url:
        print("ALERT_WEBHOOK_URL is not set")
        return 1
    errors: list[str] = []
    handler = logging.Handler(logging.WARNING)
    handler.emit = lambda record: errors.append(record.getMessage())
    logger.addHandler(handler)
    for level, text in (
        (logging.ERROR, "TEST: a problem that needs you now"),
        (logging.WARNING, "TEST: a warning"),
        (RESOLVED, "TEST: a problem is over"),
        (logging.INFO, "TEST: for your information"),
    ):
        if _post(url, f"{ICONS[level]} [Network Telescope] {text}") is not None or errors:
            print("NOT delivered")
            return 1
        time.sleep(1)
    print("4 test messages delivered")
    if os.environ.get("HEARTBEAT_URL", ""):
        heartbeat()
        print("Heartbeat NOT accepted" if errors else "Heartbeat accepted")
        return 1 if errors else 0
    print("HEARTBEAT_URL is not set: nobody notices when this machine itself is down")
    return 0


if __name__ == "__main__":
    raise SystemExit(_test())
