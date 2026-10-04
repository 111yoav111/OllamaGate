"""Offline country lookup and country allow/deny lists.

Reads a local ``.mmdb`` file (DB-IP "IP to Country Lite" or MaxMind
GeoLite2-Country); no lookup ever leaves the machine.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from .config import GeoIPConfig


def _address(ip: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse ``ip``; "::ffff:1.2.3.4" (IPv4 on a dual-stack socket) counts as 1.2.3.4."""
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return None
    return getattr(addr, "ipv4_mapped", None) or addr


class GeoIP:
    def __init__(self, reader: Any, allow: list[str], deny: list[str]) -> None:
        self.reader = reader  # anything with .get(ip) -> record, like maxminddb.Reader
        self.allow = set(allow)
        self.deny = set(deny)

    def country(self, ip: str | None) -> str | None:
        """ISO 3166 code ("DE"), or None for private/unknown addresses."""
        addr = _address(ip)
        if addr is None or not addr.is_global:
            return None
        try:
            record = self.reader.get(str(addr))
        except (ValueError, OSError, RuntimeError):  # RuntimeError: maxminddb's InvalidDatabaseError
            return None
        country = record.get("country") if isinstance(record, dict) else None
        code = country.get("iso_code") if isinstance(country, dict) else None
        return code if isinstance(code, str) else None

    def permits(self, ip: str | None) -> bool:
        """Non-global addresses (loopback, LAN, Tailscale) always pass; an
        address the database can't place fails an allowlist (fail closed)."""
        if not (self.allow or self.deny):
            return True
        addr = _address(ip)
        if addr is None:
            return not self.allow
        if not addr.is_global:
            return True
        code = self.country(ip)
        if code in self.deny:
            return False
        return not self.allow or code in self.allow


def load(config: GeoIPConfig) -> GeoIP | None:
    """Open the configured database; raises OSError/ValueError if it's unusable."""
    if not config.database:
        return None
    import maxminddb

    try:
        reader = maxminddb.open_database(config.database)
    except maxminddb.InvalidDatabaseError as exc:  # a RuntimeError: callers expect ValueError
        raise ValueError(f"{config.database} is not a valid MaxMind DB file") from exc
    return GeoIP(reader, config.allow_countries, config.deny_countries)
