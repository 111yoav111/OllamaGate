"""Client IP resolution that only trusts forwarding headers from configured proxies."""

from __future__ import annotations

import ipaddress
from typing import Mapping, Sequence

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(cidrs: Sequence[str]) -> list[IPNetwork]:
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


def _trusted(ip: str, trusted: Sequence[IPNetwork]) -> bool:
    addr = _parse_ip(ip)
    return addr is not None and any(addr in net for net in trusted)


def resolve_client_ip(
    peer_ip: str | None,
    headers: Mapping[str, str],
    trusted: Sequence[IPNetwork],
    network_mode: str,
) -> str | None:
    """Return the real client IP.

    Forwarding headers are ignored unless the direct peer is a trusted proxy.
    For X-Forwarded-For we walk from the right and return the first hop that is
    not itself a trusted proxy, so a client cannot spoof its address by
    prepending entries.
    """
    if peer_ip is None or not trusted or not _trusted(peer_ip, trusted):
        return peer_ip
    if network_mode == "cloudflare":
        cf = _parse_ip(headers.get("cf-connecting-ip", ""))
        return str(cf) if cf else peer_ip
    xff = headers.get("x-forwarded-for", "")
    for hop in reversed([h for h in xff.split(",") if h.strip()]):
        addr = _parse_ip(hop)
        if addr is None:
            break
        if not any(addr in net for net in trusted):
            return str(addr)
    return peer_ip
