"""In-memory state store.

All runtime state lives here and nowhere else. Nothing is persisted: a restart
clears every device, counter, ban and log entry (by design, see the spec).

The server, the admin control channel and the TUI all run on the same asyncio
event loop, so plain (non-async) method calls are atomic with respect to each
other. Code that needs to hold state consistent across an ``await`` must take
``lock``. Mutations bump ``version`` so the TUI can cheaply detect changes.
"""

from __future__ import annotations

import asyncio
import enum
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any

from .ratelimit import RateLimiter, client_key
from .textsafe import safe_text

MAX_IP_HISTORY = 20
MAX_AUDIT_FIELD = 200
NOISY_EVENTS_PER_MINUTE = 10
USAGE_KEEP_DAYS = 62


class DeviceStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


@dataclass
class IPRecord:
    first_seen: float
    last_seen: float
    count: int = 1


@dataclass
class Device:
    id: str
    name: str
    token_hash: str
    token_prefix: str
    paired_via: str
    paired_at: float
    status: DeviceStatus = DeviceStatus.ACTIVE
    notes: str = ""
    token_expires_at: float | None = None
    token_rotated_at: float | None = None
    # During a rotation grace period the previous token keeps working until this time.
    previous_token_hash: str | None = None
    previous_token_valid_until: float | None = None
    last_seen: float | None = None
    last_ip: str | None = None
    last_port: int | None = None
    user_agent: str = ""
    allow_model_management: bool = False
    ip_history: "OrderedDict[str, IPRecord]" = field(default_factory=OrderedDict)


class WindowState(str, enum.Enum):
    OPEN = "open"
    USED = "used"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    DESTROYED = "destroyed"  # too many wrong attempts


@dataclass
class PairingWindow:
    id: str
    created_at: float
    expires_at: float
    max_attempts: int
    # method ("code" | "qr" | "link") -> sha256 hex of that method's secret
    secret_hashes: dict[str, str]
    attempts: int = 0  # wrong codes
    link_attempts: int = 0  # wrong QR/link secrets
    state: WindowState = WindowState.OPEN
    device_id: str | None = None  # set when used


@dataclass
class AuditEntry:
    ts: float
    event: str
    seq: int = 0  # monotonically increasing; survives the ring buffer wrapping
    ip: str | None = None
    device_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class RequestLogEntry:
    ts: float
    device_id: str
    ip: str | None
    method: str
    path: str
    status: int
    duration_ms: int
    bytes_out: int
    outcome: str  # complete | client_disconnect | killed | upstream_error
    model: str = ""


@dataclass
class UsageDay:
    """Daily usage rollup for one device (tokens are filled in from Phase 4)."""

    requests: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class ActiveStream:
    id: str
    device_id: str
    method: str
    path: str
    started_at: float
    token_hash: str = ""  # which credential opened it (matters during rotation grace)
    model: str = ""
    bytes_out: int = 0
    killed: asyncio.Event = field(default_factory=asyncio.Event)
    kill_reason: str = ""

    def kill(self, reason: str) -> None:
        if not self.killed.is_set():
            self.kill_reason = reason
            self.killed.set()


def _clean(value: Any) -> Any:
    """Escape control characters and bound the length of audit strings."""
    if isinstance(value, str):
        return safe_text(value, MAX_AUDIT_FIELD)
    return value


_ZERO_USAGE = UsageDay()  # returned by reads with no data; never mutated


class State:
    def __init__(self, audit_size: int = 5000, request_log_size: int = 5000) -> None:
        self._devices: dict[str, Device] = {}
        self._device_by_token_hash: dict[str, str] = {}
        self.audit_log: deque[AuditEntry] = deque(maxlen=audit_size)
        self.request_log: deque[RequestLogEntry] = deque(maxlen=request_log_size)
        self.streams: dict[str, ActiveStream] = {}
        self.pairing_window: PairingWindow | None = None
        self.pairing_history: deque[PairingWindow] = deque(maxlen=50)
        self.lock = asyncio.Lock()
        # Unauthenticated noise (failed logins etc.) is capped per client so an
        # attacker can't flush real events out of the bounded audit log.
        self._noise_limiter = RateLimiter(NOISY_EVENTS_PER_MINUTE, 60.0)
        self.audit_suppressed = 0
        self.audit_seq = 0
        self.started_at = time.time()
        self.version = 0
        # Lockdown: reject all proxied traffic and pairing, but keep every device.
        self.lockdown = False
        # (device_id, "YYYY-MM-DD") -> usage for that local day
        self.usage: dict[tuple[str, str], UsageDay] = {}
        self._usage_month: dict[tuple[str, str], UsageDay] = {}  # (device_id, "YYYY-MM")
        self._usage_total: dict[str, UsageDay] = {}
        self._usage_all_day: dict[str, UsageDay] = {}  # "YYYY-MM-DD" -> all devices

    def _changed(self) -> None:
        self.version += 1

    # ----- audit / request log -------------------------------------------------

    def audit(
        self, event: str, *, ip: str | None = None, device_id: str | None = None, **detail: Any
    ) -> AuditEntry:
        self.audit_seq += 1
        entry = AuditEntry(
            seq=self.audit_seq,
            ts=time.time(),
            event=event,
            ip=_clean(ip),
            device_id=device_id,
            detail={k: _clean(v) for k, v in detail.items()},
        )
        self.audit_log.append(entry)
        self._changed()
        return entry

    def audit_noisy(self, event: str, *, ip: str | None, **detail: Any) -> AuditEntry | None:
        """Audit an event an unauthenticated client can trigger at will, at most
        NOISY_EVENTS_PER_MINUTE times per client per event; the rest are counted."""
        if not self._noise_limiter.hit(f"{event}|{client_key(ip)}"):
            self.audit_suppressed += 1
            return None
        return self.audit(event, ip=ip, **detail)

    def log_request(self, entry: RequestLogEntry) -> None:
        self.request_log.append(entry)
        self.add_usage(entry.device_id, requests=1)
        self._changed()

    def add_usage(self, device_id: str, requests: int = 0, prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
        """Count usage into the day, month, lifetime and all-devices-today buckets.

        Keeping running totals makes every read O(1), which matters because the
        TUI reads them for every device on every redraw, on the proxy's loop.
        """
        day = time.strftime("%Y-%m-%d")
        for key, bucket in (
            ((device_id, day), self.usage),
            ((device_id, day[:7]), self._usage_month),
            (device_id, self._usage_total),
            (day, self._usage_all_day),
        ):
            u = bucket.setdefault(key, UsageDay())
            u.requests += requests
            u.prompt_tokens += prompt_tokens
            u.completion_tokens += completion_tokens

    def usage_today(self, device_id: str) -> UsageDay:
        return self.usage.get((device_id, time.strftime("%Y-%m-%d")), _ZERO_USAGE)

    def usage_month(self, device_id: str) -> UsageDay:
        return self._usage_month.get((device_id, time.strftime("%Y-%m")), _ZERO_USAGE)

    def usage_lifetime(self, device_id: str) -> UsageDay:
        return self._usage_total.get(device_id, _ZERO_USAGE)

    def usage_all_today(self) -> UsageDay:
        return self._usage_all_day.get(time.strftime("%Y-%m-%d"), _ZERO_USAGE)

    def requests_last_minute(self, now: float | None = None) -> int:
        cutoff = (time.time() if now is None else now) - 60
        count = 0
        for entry in reversed(self.request_log):
            if entry.ts < cutoff:
                break
            count += 1
        return count

    def set_lockdown(self, on: bool) -> None:
        self.lockdown = on
        if on:
            self.kill_all_streams("lockdown")
        self._changed()

    # ----- devices -------------------------------------------------------------

    def add_device(
        self,
        *,
        name: str,
        token_hash: str,
        token_prefix: str,
        paired_via: str,
        allow_model_management: bool = False,
        token_expires_at: float | None = None,
    ) -> Device:
        if token_hash in self._device_by_token_hash:
            raise ValueError("token hash collision")
        device = Device(
            id=str(uuid.uuid4()),
            name=name,
            token_hash=token_hash,
            token_prefix=token_prefix,
            paired_via=paired_via,
            paired_at=time.time(),
            allow_model_management=allow_model_management,
            token_expires_at=token_expires_at,
        )
        self._devices[device.id] = device
        self._device_by_token_hash[token_hash] = device.id
        self._changed()
        return device

    def list_devices(self) -> list[Device]:
        return list(self._devices.values())

    def get_device(self, device_id: str) -> Device | None:
        return self._devices.get(device_id)

    def find_device(self, ref: str) -> Device:
        """Find a device by full id or a unique id prefix (>= 4 chars). Raises KeyError."""
        if ref in self._devices:
            return self._devices[ref]
        if len(ref) >= 4:
            matches = [d for d in self._devices.values() if d.id.startswith(ref)]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise KeyError(f"device id prefix {ref!r} is ambiguous")
        raise KeyError(f"no device {ref!r}")

    def device_by_token_hash(self, token_hash: str) -> Device | None:
        device_id = self._device_by_token_hash.get(token_hash)
        return self._devices.get(device_id) if device_id else None

    def update_device(self, device_id: str, **fields: Any) -> Device:
        """Change plain descriptive fields (name, notes, expiry, permissions)."""
        allowed = {"name", "notes", "token_expires_at", "allow_model_management"}
        if not set(fields) <= allowed:
            raise ValueError(f"cannot update {set(fields) - allowed}")
        device = self._devices[device_id]
        for key, value in fields.items():
            setattr(device, key, value)
        self._changed()
        return device

    def touch_device(self, device: Device, ip: str | None, port: int | None, user_agent: str) -> bool:
        """Record activity. Returns True if ``ip`` is new for this device."""
        now = time.time()
        device.last_seen = now
        device.last_ip = ip
        device.last_port = port
        if user_agent:
            device.user_agent = safe_text(user_agent, 512)
        new_ip = False
        if ip is not None:
            record = device.ip_history.get(ip)
            if record is None:
                new_ip = bool(device.ip_history)  # the pairing IP itself isn't "new"
                if len(device.ip_history) >= MAX_IP_HISTORY:
                    device.ip_history.popitem(last=False)
                device.ip_history[ip] = IPRecord(first_seen=now, last_seen=now)
            else:
                record.last_seen = now
                record.count += 1
                device.ip_history.move_to_end(ip)
        self._changed()
        return new_ip

    def set_status(self, device_id: str, status: DeviceStatus) -> Device:
        device = self._devices[device_id]
        if device.status is DeviceStatus.REVOKED:
            raise ValueError("a revoked device cannot change status")
        device.status = status
        if status is not DeviceStatus.ACTIVE:
            self.kill_device_streams(device_id, status.value)
        self._changed()
        return device

    def revoke_device(self, device_id: str) -> Device:
        device = self._devices[device_id]
        device.status = DeviceStatus.REVOKED
        self._device_by_token_hash.pop(device.token_hash, None)
        if device.previous_token_hash:
            self._device_by_token_hash.pop(device.previous_token_hash, None)
        device.previous_token_hash = device.previous_token_valid_until = None
        self.kill_device_streams(device_id, "revoked")
        self._changed()
        return device

    def rotate_token(self, device_id: str, new_hash: str, new_prefix: str, grace_seconds: int = 0) -> Device:
        device = self._devices[device_id]
        if new_hash in self._device_by_token_hash:
            raise ValueError("token hash collision")
        now = time.time()
        # Only one previous token is kept; an older one stops working now.
        if device.previous_token_hash:
            self._device_by_token_hash.pop(device.previous_token_hash, None)
        if grace_seconds > 0:
            device.previous_token_hash = device.token_hash
            device.previous_token_valid_until = now + grace_seconds
        else:
            self._device_by_token_hash.pop(device.token_hash, None)
            device.previous_token_hash = device.previous_token_valid_until = None
            self.kill_device_streams(device_id, "token rotated")
        device.token_hash = new_hash
        device.token_prefix = new_prefix
        device.token_rotated_at = now
        self._device_by_token_hash[new_hash] = device_id
        self._changed()
        return device

    # ----- active streams ------------------------------------------------------

    def register_stream(self, device_id: str, method: str, path: str, token_hash: str = "") -> ActiveStream:
        stream = ActiveStream(
            id=uuid.uuid4().hex,
            device_id=device_id,
            method=method,
            path=path,
            started_at=time.time(),
            token_hash=token_hash,
        )
        self.streams[stream.id] = stream
        self._changed()
        return stream

    def unregister_stream(self, stream: ActiveStream) -> None:
        if self.streams.pop(stream.id, None) is not None:
            self._changed()

    def device_streams(self, device_id: str) -> list[ActiveStream]:
        return [s for s in self.streams.values() if s.device_id == device_id]

    def kill_device_streams(self, device_id: str, reason: str) -> int:
        streams = self.device_streams(device_id)
        for s in streams:
            s.kill(reason)
        return len(streams)

    def kill_all_streams(self, reason: str) -> int:
        streams = list(self.streams.values())
        for s in streams:
            s.kill(reason)
        return len(streams)

    # ----- housekeeping --------------------------------------------------------

    def sweep(self, now: float | None = None) -> None:
        """Enforce time-based rules: expired tokens lose their streams, grace periods end."""
        now = time.time() if now is None else now
        # Daily buckets older than ~2 months are no longer shown anywhere.
        cutoff = time.strftime("%Y-%m-%d", time.localtime(now - USAGE_KEEP_DAYS * 86400))
        for key in [k for k in self.usage if k[1] < cutoff]:
            del self.usage[key]
        for key in [k for k in self._usage_all_day if k < cutoff]:
            del self._usage_all_day[key]
        for device in self._devices.values():
            if device.previous_token_hash and (device.previous_token_valid_until or 0) <= now:
                old = device.previous_token_hash
                self._device_by_token_hash.pop(old, None)
                device.previous_token_hash = device.previous_token_valid_until = None
                for s in self.device_streams(device.id):
                    if s.token_hash == old:
                        s.kill("token rotated")
                self._changed()
            expired = device.token_expires_at is not None and now >= device.token_expires_at
            if (expired or device.status is not DeviceStatus.ACTIVE) and self.device_streams(device.id):
                self.kill_device_streams(device.id, "expired" if expired else device.status.value)
