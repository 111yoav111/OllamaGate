"""fail2ban-style IP bans.

Too many failed logins / pairing attempts from one client within a window
bans it for a while; each further ban (a "strike") doubles the duration, up
to a maximum. Strikes are forgotten a quiet day after the last ban ends. Only
distinct wrong credentials count (see ``record_failure``). The owner can also ban
and unban manually. IPv6 clients are handled per /64 (see ``client_key``).
Loopback clients are never banned automatically, so the owner can't lock
themselves out while testing.
"""

from __future__ import annotations

import ipaddress
import time
from collections import OrderedDict, deque
from dataclasses import dataclass

from .ratelimit import client_key

STRIKE_MEMORY_SECONDS = 86400
MAX_TRACKED_CLIENTS = 20_000


@dataclass
class Ban:
    key: str  # IP, or IPv6 /64
    reason: str
    created_at: float
    until: float | None  # None = until the owner lifts it
    manual: bool
    strikes: int = 1

    def active(self, now: float) -> bool:
        return self.until is None or now < self.until


def _is_loopback(ip: str | None) -> bool:
    try:
        return ip is not None and ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


class BanList:
    def __init__(
        self,
        threshold: int = 10,
        window_seconds: float = 600,
        ban_seconds: float = 3600,
        max_ban_seconds: float = 7 * 86400,
    ) -> None:
        self.threshold = threshold
        self.window = window_seconds
        self.ban_seconds = ban_seconds
        self.max_ban_seconds = max_ban_seconds
        self.bans: dict[str, Ban] = {}
        self._failures: OrderedDict[str, deque[tuple[float, str]]] = OrderedDict()  # (time, fingerprint)
        self._strikes: dict[str, tuple[int, float]] = {}  # key -> (count, when the last ban ended)

    def configure(self, threshold: int, window_seconds: float, ban_seconds: float, max_ban_seconds: float) -> None:
        self.threshold = threshold
        self.window = window_seconds
        self.ban_seconds = ban_seconds
        self.max_ban_seconds = max_ban_seconds

    def banned(self, ip: str | None, now: float | None = None) -> Ban | None:
        if ip is None:
            return None
        now = time.time() if now is None else now
        ban = self.bans.get(client_key(ip))
        if ban is None:
            return None
        if not ban.active(now):
            del self.bans[ban.key]
            return None
        return ban

    def record_failure(
        self, ip: str | None, reason: str, fingerprint: str = "", now: float | None = None
    ) -> Ban | None:
        """Count a failure; returns the new Ban if this one tipped the client over.

        ``fingerprint`` identifies what was tried (e.g. a hash of the wrong
        token). Only *distinct* attempts count: a guesser tries many, while a
        device still using its token from before a restart repeats the same one
        and must not get its owner's IP banned.
        """
        if ip is None or _is_loopback(ip):
            return None
        now = time.time() if now is None else now
        key = client_key(ip)
        hits = self._failures.get(key)
        if hits is None:
            if len(self._failures) >= MAX_TRACKED_CLIENTS:
                self._failures.popitem(last=False)
            hits = self._failures[key] = deque()
        else:
            self._failures.move_to_end(key)
        while hits and hits[0][0] <= now - self.window:
            hits.popleft()
        if fingerprint and any(fp == fingerprint for _, fp in hits):
            return None  # the same wrong credential again
        hits.append((now, fingerprint))
        if len(hits) < self.threshold:
            return None
        del self._failures[key]
        count, last_until = self._strikes.get(key, (0, 0.0))
        if now - last_until > STRIKE_MEMORY_SECONDS:
            count = 0  # quiet for a day after the last ban ended: start over
        count += 1
        duration = min(self.ban_seconds * 2 ** (count - 1), self.max_ban_seconds)
        self._strikes[key] = (count, now + duration)
        ban = Ban(key=key, reason=reason, created_at=now, until=now + duration, manual=False, strikes=count)
        self.bans[key] = ban
        return ban

    def ban(self, ip: str, reason: str, seconds: float | None, now: float | None = None) -> Ban:
        now = time.time() if now is None else now
        key = client_key(ip)
        ban = Ban(key=key, reason=reason, created_at=now, until=None if seconds is None else now + seconds, manual=True)
        self.bans[key] = ban
        return ban

    def unban(self, ip_or_key: str) -> bool:
        key = ip_or_key if ip_or_key in self.bans else client_key(ip_or_key)
        self._failures.pop(key, None)
        self._strikes.pop(key, None)
        return self.bans.pop(key, None) is not None

    def sweep(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        for key in [k for k, b in self.bans.items() if not b.active(now)]:
            del self.bans[key]
        for key in [k for k, (_, last) in self._strikes.items() if now - last > STRIKE_MEMORY_SECONDS]:
            del self._strikes[key]
