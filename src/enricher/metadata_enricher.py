from __future__ import annotations

import ipaddress
import logging
import os
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

import maxminddb

logger = logging.getLogger(__name__)

DB_DIR = Path(os.environ.get("GEOIP_DB_DIR", "/var/lib/geoip"))
CITY_DB = DB_DIR / "GeoLite2-City.mmdb"
ASN_DB = DB_DIR / "GeoLite2-ASN.mmdb"
RELOAD_INTERVAL = int(os.environ.get("GEOIP_RELOAD_INTERVAL_SECONDS", "3600"))
CACHE_MAX_SIZE = int(os.environ.get("GEOIP_CACHE_SIZE", "200000"))

_EMPTY_GEO: dict[str, Any] = {"country_code": "", "country_name": "", "city": "", "asn": "", "asn_name": ""}


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast
    except ValueError:
        return True     # Skipping unparsable IPs


class MetadataEnricher:
    """Adds GeoIP/ASN fields to parsed packet records."""

    def __init__(self):
        self._cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._city_reader: maxminddb.Reader | None = None
        self._asn_reader: maxminddb.Reader | None = None
        self._last_load: float = 0.0
        self._load_databases()

    def _load_databases(self) -> None:
        if self._city_reader:
            try:
                self._city_reader.close()
            except Exception as e:
                logger.exception(f"Error closing maxminddb reader: {e}")
        if self._asn_reader:
            try:
                self._asn_reader.close()
            except Exception as e:
                logger.exception(f"Error closing maxminddb reader: {e}")

        missing = [p for p in (CITY_DB, ASN_DB) if not p.exists()]
        if missing:
            logger.warning(
                f"MaxMind database file(s) not found: {[str(p) for p in missing]}. "
                f"GeoIP enrichment will return empty fields until the files are present. "
                f"Check GEOIP_DB_DIR ({DB_DIR}) and ensure geoipupdate has run."
            )
            self._city_reader = None
            self._asn_reader = None
        else:
            self._city_reader = maxminddb.open_database(str(CITY_DB))
            self._asn_reader = maxminddb.open_database(str(ASN_DB))
            city_age = time.strftime(
                "%Y-%m-%d", time.gmtime(CITY_DB.stat().st_mtime)
            )
            asn_age = time.strftime(
                "%Y-%m-%d", time.gmtime(ASN_DB.stat().st_mtime)
            )
            logger.info(
                f"MaxMind databases loaded from {DB_DIR} "
                f"(City: {city_age}, ASN: {asn_age})"
            )
            self._cache.clear()

        self._last_load = time.monotonic()

    def _reload(self) -> None:
        if time.monotonic() - self._last_load >= RELOAD_INTERVAL:
            logger.info("GeoIP reload interval elapsed - reloading databases.")
            self._load_databases()

    def _lookup(self, ip: str) -> dict[str, Any]:
        if _is_private(ip):
            return dict(_EMPTY_GEO)

        if ip in self._cache:
            self._cache.move_to_end(ip)
            return self._cache[ip]

        geo = dict(_EMPTY_GEO)

        try:
            if self._city_reader:
                city_data = self._city_reader.get(ip)
                if city_data:
                    country = city_data.get("country") or city_data.get("registered_country") or {}
                    city = city_data.get("city", {})
                    geo["country_code"] = country.get("iso_code", "")
                    geo["country_name"] = country.get("names", {}).get("en", "")
                    geo["city"] = city.get("names", {}).get("en", "")
        except Exception as e:
            logger.debug(f"City lookup failed for {ip}: {e}")

        try:
            if self._asn_reader:
                asn_data = self._asn_reader.get(ip)
                if asn_data:
                    geo["asn"] = str(asn_data.get("autonomous_system_number", ""))
                    geo["asn_name"] = asn_data.get("autonomous_system_organization", "")
        except Exception as e:
            logger.debug(f"ASN lookup failed for {ip}: {e}")

        if len(self._cache) >= CACHE_MAX_SIZE:
            self._cache.popitem(last=False)
        self._cache[ip] = geo

        return geo

    def enrich_batch(self, packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not packets:
            return packets

        self._reload()

        enriched = []
        for pkt in packets:
            geo = self._lookup(pkt.get("src_ip", ""))
            enriched.append({
                **pkt,
                "src_country_code": geo["country_code"],
                "src_country_name": geo["country_name"],
                "src_city": geo["city"],
                "src_asn": geo["asn"],
                "src_asn_name": geo["asn_name"],
            })

        return enriched

    def close(self) -> None:
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()

    @property
    def cache_size(self) -> int:
        return len(self._cache)