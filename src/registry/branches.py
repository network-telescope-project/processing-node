from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

HEADER = "# nt-branches v1"
BRANCHES = ("passive", "r-irregular", "r-regular")
FLAGS = ("", "special", "mgmt")
MAX_BYTES = 1024 * 1024
_SEED = re.compile(r"(?:^|\s)seed=(\d+)(?:\s|$)")


class ManifestError(Exception):
    """The delivered file is not a valid branch assignment"""


@dataclass
class Manifest:
    seed: int
    rows: list[tuple[ipaddress.IPv4Address, str, str]]     # (address, branch, flag)

    def counts(self) -> dict[str, int]:
        return {b: sum(1 for _, branch, _ in self.rows if branch == b) for b in BRANCHES}


def parse_manifest(text: str) -> Manifest:
    lines = text.split("\n")
    if lines[0] != HEADER:
        raise ManifestError(f"first line is not '{HEADER}'")
    seed = 0
    rows: list[tuple[ipaddress.IPv4Address, str, str]] = []
    seen: set[ipaddress.IPv4Address] = set()
    for number, line in enumerate(lines[1:], start=2):
        if not line:
            continue
        if line.startswith("#"):
            m = _SEED.search(line[1:])
            if m:
                seed = int(m.group(1))
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise ManifestError(f"line {number}: expected 3 tab-separated fields")
        try:
            ip = ipaddress.IPv4Address(fields[0])
        except ValueError as e:
            raise ManifestError(f"line {number}: {e}") from e
        branch, flag = fields[1], fields[2]
        if branch not in BRANCHES:
            raise ManifestError(f"line {number}: unknown branch {branch!r}")
        if flag not in FLAGS:
            raise ManifestError(f"line {number}: unknown flag {flag!r}")
        if flag and branch != "passive":
            raise ManifestError(f"line {number}: {ip} is flagged '{flag}' and must be passive")
        if ip in seen:
            raise ManifestError(f"line {number}: {ip} is listed twice")
        seen.add(ip)
        rows.append((ip, branch, flag))
    if not rows:
        raise ManifestError("no addresses")
    return Manifest(seed, rows)
