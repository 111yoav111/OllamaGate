"""Small sliding-window rate limiter with a bounded number of tracked keys."""

from __future__ import annotations

import ipaddress
import time
from collections import OrderedDict, deque


def client_key(ip: str | None) -> str:
    """Rate-limit key for an IP: IPv6 clients are grouped by /64, since one
    host usually controls a whole /64 and could otherwise rotate addresses."""
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float, max_keys: int = 10_000) -> None:
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()

    def _prune(self, hits: deque[float], now: float) -> None:
        cutoff = now - self.window
        while hits and hits[0] <= cutoff:
            hits.popleft()

    def hit(self, key: str, now: float | None = None, limit: int | None = None) -> bool:
        """Record a hit for ``key``. Returns False if the key is over its limit.

        ``limit`` overrides the default for this key (e.g. per-device limits).
        """
        now = time.monotonic() if now is None else now
        limit = self.limit if limit is None else limit
        hits = self._hits.get(key)
        if hits is None:
            if len(self._hits) >= self.max_keys:
                self._hits.popitem(last=False)  # forget the least recently seen key
            hits = self._hits[key] = deque()
        else:
            self._hits.move_to_end(key)
        self._prune(hits, now)
        if len(hits) >= limit:
            return False
        hits.append(now)
        return True

    def retry_after(self, key: str, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        hits = self._hits.get(key)
        if not hits:
            return 0
        return max(1, int(hits[0] + self.window - now) + 1)
