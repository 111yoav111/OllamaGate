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

MAX_IP_HISTORY = 20
MAX_AUDIT_FIELD = 200


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
    attempts: int = 0
    state: WindowState = WindowState.OPEN
    device_id: str | None = None  # set when used


@dataclass
class AuditEntry:
    ts: float
    event: str
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


@dataclass
class ActiveStream:
    id: str
    device_id: str
    method: str
    path: str
    started_at: float
    killed: asyncio.Event = field(default_factory=asyncio.Event)
    kill_reason: str = ""

    def kill(self, reason: str) -> None:
        if not self.killed.is_set():
            self.kill_reason = reason
            self.killed.set()


def _truncate(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_AUDIT_FIELD:
        return value[:MAX_AUDIT_FIELD] + "…"
    return value


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
        self.started_at = time.time()
        self.version = 0

    def _changed(self) -> None:
        self.version += 1

    # ----- audit / request log -------------------------------------------------

    def audit(
        self, event: str, *, ip: str | None = None, device_id: str | None = None, **detail: Any
    ) -> AuditEntry:
        entry = AuditEntry(
            ts=time.time(),
            event=event,
            ip=ip,
            device_id=device_id,
            detail={k: _truncate(v) for k, v in detail.items()},
        )
        self.audit_log.append(entry)
        self._changed()
        return entry

    def log_request(self, entry: RequestLogEntry) -> None:
        self.request_log.append(entry)
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
            device.user_agent = user_agent[:512]
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

    def register_stream(self, device_id: str, method: str, path: str) -> ActiveStream:
        stream = ActiveStream(
            id=uuid.uuid4().hex, device_id=device_id, method=method, path=path, started_at=time.time()
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
        for device in self._devices.values():
            if device.previous_token_hash and (device.previous_token_valid_until or 0) <= now:
                self._device_by_token_hash.pop(device.previous_token_hash, None)
                device.previous_token_hash = device.previous_token_valid_until = None
                self._changed()
            expired = device.token_expires_at is not None and now >= device.token_expires_at
            if (expired or device.status is not DeviceStatus.ACTIVE) and self.device_streams(device.id):
                self.kill_device_streams(device.id, "expired" if expired else device.status.value)
