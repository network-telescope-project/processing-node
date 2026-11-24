from __future__ import annotations

import logging
import math
import os

import requests

logger = logging.getLogger(__name__)


class Prometheus:
    """Instant queries"""

    def __init__(self) -> None:
        self._url = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")

    def series(self, query: str) -> list[tuple[dict, float]] | None:
        """All series of a query as (labels, value); None if Prometheus could not be 'asked'"""
        try:
            resp = requests.get(f"{self._url}/api/v1/query", params={"query": query}, timeout=10)
            resp.raise_for_status()
            return [(r["metric"], float(r["value"][1])) for r in resp.json()["data"]["result"]]
        except Exception as e:
            logger.warning(f"Prometheus query failed [{query}]: {e}")
            return None

    def value(self, query: str) -> float | None:
        """The value of a query that yields one series; None if there is no data"""
        series = self.series(query)
        if not series or not math.isfinite(series[0][1]):
            return None
        return series[0][1]
