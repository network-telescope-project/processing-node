"""Manage the capture nodes (sensors) and the address space each monitors:

    python -m src.registry list
    python -m src.registry add-sensor SENSOR_ID [--description TEXT] [--exporter HOST:PORT]
    python -m src.registry set-sensor SENSOR_ID [--description TEXT] [--exporter HOST:PORT] [--active | --inactive]
    python -m src.registry add-prefix SENSOR_ID CIDR [CIDR ...]
    python -m src.registry remove-prefix SENSOR_ID CIDR [CIDR ...]
    python -m src.registry sync-targets

A node delivers its PCAP files to <inbox>/<SENSOR_ID>/ (REMOTE_DIR on the capturing node). Files of a sensor that is not
registered, deactivated or without a prefix are held in the inbox, not ingested. Changes apply without a restart.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).parent.parent.parent / ".env")

from src.db import get_client
from src.registry.sensor_registry import RegistryError, SensorRegistry


def _list(reg: SensorRegistry, _args) -> None:
    sensors = reg.sensors()
    if not sensors:
        print("No sensors registered.")
    for s in sensors:
        print(f"{s.sensor_id}  [{'active' if s.active else 'INACTIVE'}]  exporter={s.exporter or '-'}  {s.description}")
        for _, prefix, valid_from, valid_to in reg.prefixes(s.sensor_id, open_only=False):
            span = f"since {valid_from:%Y-%m-%d %H:%M}" if valid_to is None else f"{valid_from:%Y-%m-%d %H:%M} .. {valid_to:%Y-%m-%d %H:%M}"
            print(f"    {prefix:<20} {span}")


def _sync(reg: SensorRegistry, _args) -> None:
    path = os.environ.get("PROMETHEUS_TARGETS_FILE", "")
    if not path:
        raise RegistryError("PROMETHEUS_TARGETS_FILE is not set")
    print(("Updated " if reg.write_prometheus_targets(Path(path)) else "Already up to date: ") + path)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m src.registry", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="sensors and their prefixes, with history").set_defaults(fn=_list)

    a = sub.add_parser("add-sensor", help="register a capture node")
    a.add_argument("sensor_id")
    a.add_argument("--description", default="")
    a.add_argument("--exporter", default="", help="host:port of its node-exporter, for Prometheus")
    a.set_defaults(fn=lambda r, x: r.add_sensor(x.sensor_id, x.description, x.exporter))

    s = sub.add_parser("set-sensor", help="change a registered capture node")
    s.add_argument("sensor_id")
    s.add_argument("--description")
    s.add_argument("--exporter")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--active", dest="active", action="store_true", default=None)
    g.add_argument("--inactive", dest="active", action="store_false")
    s.set_defaults(fn=lambda r, x: r.set_sensor(x.sensor_id, x.description, x.exporter, x.active))

    ap = sub.add_parser("add-prefix", help="start monitoring prefixes (IPv4 CIDR, a single address is /32)")
    ap.add_argument("sensor_id")
    ap.add_argument("prefixes", nargs="+")
    ap.set_defaults(fn=lambda r, x: [print("added", r.add_prefix(x.sensor_id, c)) for c in x.prefixes])

    rp = sub.add_parser("remove-prefix", help="stop monitoring prefixes (their history stays)")
    rp.add_argument("sensor_id")
    rp.add_argument("prefixes", nargs="+")
    rp.set_defaults(fn=lambda r, x: [print("removed", r.remove_prefix(x.sensor_id, c)) for c in x.prefixes])

    sub.add_parser("sync-targets", help="write the Prometheus target file now").set_defaults(fn=_sync)

    args = p.parse_args(argv)
    try:
        args.fn(SensorRegistry(get_client()), args)
    except RegistryError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
