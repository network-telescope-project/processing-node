from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from src.parser.pcap_parser import Darknet

# Files that are not in a sensor's sub-directory of the inbox (the single-node local Docker setup) belong to this
# sensor; it is not in the registry, its address space comes from DARKNET_NETS
LOCAL_SENSOR_ID = "local"
SENSOR_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
EXPORTER = re.compile(r"^[A-Za-z0-9._-]+:\d{1,5}$")


class RegistryError(Exception):
    """A registry change that is not allowed (unknown sensor, overlapping prefix, bad value)"""


class SensorNotReady(Exception):
    """Files of this sensor cannot be ingested (not registered, deactivated, no address space); says why"""


@dataclass
class Sensor:
    sensor_id: str
    description: str
    exporter: str
    active: bool


def normalize_prefix(text: str) -> str:
    try:
        net = ipaddress.ip_network(text.strip(), strict=True)
    except ValueError as e:
        raise RegistryError(f"{text!r}: {e}") from e
    if net.version != 4:
        raise RegistryError(f"{text!r}: only IPv4 is monitored")
    return str(net)


class SensorRegistry:
    """The capture nodes and the address space each one monitors (database mgmt). Reads are cheap queries on
    a handful of rows, made when needed, so a change applies without restarting anything."""

    def __init__(self, db):
        self._db = db
        self._local = Darknet(os.environ.get("DARKNET_NETS", ""))

    # --- reads -------------------------------------------------------------------------------------------
    def get_sensor(self, sensor_id: str) -> Sensor | None:
        rows = self._db.query(
            "SELECT sensor_id, description, exporter, active FROM mgmt.sensors FINAL WHERE sensor_id = {s:String}",
            parameters={"s": sensor_id},
        ).result_rows
        return Sensor(rows[0][0], rows[0][1], rows[0][2], bool(rows[0][3])) if rows else None

    def sensors(self) -> list[Sensor]:
        rows = self._db.query(
            "SELECT sensor_id, description, exporter, active FROM mgmt.sensors FINAL ORDER BY sensor_id"
        ).result_rows
        return [Sensor(r[0], r[1], r[2], bool(r[3])) for r in rows]

    def monitored_ids(self) -> list[str]:
        """The sensors to watch and report on: the active ones, or just the local one if none is registered"""
        ids = [s.sensor_id for s in self.sensors() if s.active]
        return ids or [LOCAL_SENSOR_ID]

    def prefixes(self, sensor_id: str | None = None, open_only: bool = True) -> list[tuple[str, str, datetime, datetime | None]]:
        """(sensor_id, prefix, valid_from, valid_to) rows, optionally of one sensor and only the still valid ones"""
        where = ["1"]
        if open_only:
            where.append("valid_to IS NULL")
        if sensor_id:
            where.append("sensor_id = {s:String}")
        return self._db.query(
            "SELECT sensor_id, prefix, valid_from, valid_to FROM mgmt.sensor_prefixes FINAL "
            f"WHERE {' AND '.join(where)} ORDER BY sensor_id, prefix, valid_from",
            parameters={"s": sensor_id or ""},
        ).result_rows

    def darknet_for(self, sensor_id: str, file_time: datetime) -> Darknet:
        """The destination addresses a file of this sensor may contain. A prefix counts if it was still monitored when
        the file was written (valid_to not before it), so a file that arrives after the prefix was removed is not cut."""
        if sensor_id == LOCAL_SENSOR_ID:
            return self._local
        sensor = self.get_sensor(sensor_id)
        if sensor is None:
            raise SensorNotReady(f"sensor '{sensor_id}' is not registered")
        if not sensor.active:
            raise SensorNotReady(f"sensor '{sensor_id}' is deactivated")
        rows = self._db.query(
            "SELECT prefix FROM mgmt.sensor_prefixes FINAL WHERE sensor_id = {s:String} "
            "AND (valid_to IS NULL OR valid_to >= toDateTime({t:UInt32}, 'UTC'))",
            parameters={"s": sensor_id, "t": int(file_time.timestamp())},
        ).result_rows
        if not rows:
            raise SensorNotReady(f"sensor '{sensor_id}' has no monitored address space at {file_time:%Y-%m-%d %H:%M} UTC")
        return Darknet(" ".join(r[0] for r in rows))

    # --- changes (append-only) ---------------------------------------------------------------------------
    def _put_sensor(self, s: Sensor) -> None:
        self._db.insert(
            "sensors", [[s.sensor_id, s.description, s.exporter, int(s.active)]], database="mgmt",
            column_names=["sensor_id", "description", "exporter", "active"],
        )

    def add_sensor(self, sensor_id: str, description: str = "", exporter: str = "") -> None:
        self._validate_sensor(sensor_id, exporter)
        if self.get_sensor(sensor_id):
            raise RegistryError(f"sensor '{sensor_id}' already exists (use set-sensor to change it)")
        self._put_sensor(Sensor(sensor_id, description, exporter, True))

    def set_sensor(self, sensor_id: str, description: str | None = None, exporter: str | None = None,
                   active: bool | None = None) -> None:
        s = self.get_sensor(sensor_id)
        if s is None:
            raise RegistryError(f"unknown sensor '{sensor_id}'")
        if exporter is not None:
            self._validate_sensor(sensor_id, exporter)
        self._put_sensor(Sensor(
            sensor_id,
            s.description if description is None else description,
            s.exporter if exporter is None else exporter,
            s.active if active is None else active,
        ))

    @staticmethod
    def _validate_sensor(sensor_id: str, exporter: str) -> None:
        if sensor_id == LOCAL_SENSOR_ID:
            raise RegistryError(f"'{LOCAL_SENSOR_ID}' is reserved for the single-node local setup")
        if not SENSOR_ID.match(sensor_id):
            raise RegistryError("sensor id: 1-32 characters of a-z, 0-9, '-' and '_', starting with a letter or digit")
        if exporter and not EXPORTER.match(exporter):
            raise RegistryError(f"exporter {exporter!r}: expected host:port")

    def add_prefix(self, sensor_id: str, prefix: str) -> str:
        """Start monitoring a prefix now; returns its normalised form. A prefix is never shared between sensors."""
        net = ipaddress.ip_network(normalize_prefix(prefix))
        if self.get_sensor(sensor_id) is None:
            raise RegistryError(f"unknown sensor '{sensor_id}'")
        for owner, other, _, _ in self.prefixes():
            if ipaddress.ip_network(other).overlaps(net):
                if owner == sensor_id and other == str(net):
                    raise RegistryError(f"{net} is already monitored by '{sensor_id}'")
                raise RegistryError(f"{net} overlaps {other}, monitored by '{owner}'")
        self._db.insert(
            "sensor_prefixes", [[sensor_id, str(net), datetime.now(tz=timezone.utc), None]], database="mgmt",
            column_names=["sensor_id", "prefix", "valid_from", "valid_to"],
        )
        return str(net)

    def remove_prefix(self, sensor_id: str, prefix: str) -> str:
        """Stop monitoring a prefix now (its history stays)"""
        prefix = normalize_prefix(prefix)
        rows = [r for r in self.prefixes(sensor_id) if r[1] == prefix]
        if not rows:
            raise RegistryError(f"'{sensor_id}' does not monitor {prefix}")
        self._db.insert(
            "sensor_prefixes", [[sensor_id, prefix, rows[0][2], datetime.now(tz=timezone.utc)]], database="mgmt",
            column_names=["sensor_id", "prefix", "valid_from", "valid_to"],
        )
        return prefix

    # --- Prometheus --------------------------------------------------------------------------------------
    def write_prometheus_targets(self, path: Path) -> bool:
        """File-based service discovery for Prometheus: one target per active sensor with an exporter, labelled
        sensor=<id>. Returns whether the file changed."""
        doc = [
            {"targets": [s.exporter], "labels": {"sensor": s.sensor_id}}
            for s in self.sensors() if s.active and s.exporter
        ]
        text = json.dumps(doc, indent=2) + "\n"
        if path.exists() and path.read_text() == text:
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(text)
        tmp.chmod(0o644)
        os.replace(tmp, path)
        return True
