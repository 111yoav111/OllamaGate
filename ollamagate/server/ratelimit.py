"""Small sliding-window rate limiter with a bounded number of tracked keys."""

from __future__ import annotations

import time
from collections import OrderedDict, deque


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

    def hit(self, key: str, now: float | None = None) -> bool:
        """Record a hit for ``key``. Returns False if the key is over its limit."""
        now = time.monotonic() if now is None else now
        hits = self._hits.get(key)
        if hits is None:
            if len(self._hits) >= self.max_keys:
                self._hits.popitem(last=False)  # forget the least recently seen key
            hits = self._hits[key] = deque()
        else:
            self._hits.move_to_end(key)
        self._prune(hits, now)
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True

    def retry_after(self, key: str, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        hits = self._hits.get(key)
        if not hits:
            return 0
        return max(1, int(hits[0] + self.window - now) + 1)
