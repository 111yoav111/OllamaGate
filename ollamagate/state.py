"""In-memory state store.

All runtime state lives here and nowhere else. Nothing is persisted: a restart
clears every device, counter, ban and log entry (by design, see the spec).

The server, the admin control socket and the TUI all run on the same asyncio
event loop, so plain method calls are atomic with respect to each other. Code
that needs to hold state consistent across an ``await`` must take ``lock``.
"""

from __future__ import annotations

import asyncio
import enum
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any


class DeviceStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


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
    last_seen: float | None = None
    last_ip: str | None = None
    last_port: int | None = None
    user_agent: str = ""
    allow_model_management: bool = False


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


class State:
    def __init__(self, audit_size: int = 5000, request_log_size: int = 5000) -> None:
        self.devices: dict[str, Device] = {}
        self._device_by_token_hash: dict[str, str] = {}
        self.audit_log: deque[AuditEntry] = deque(maxlen=audit_size)
        self.request_log: deque[RequestLogEntry] = deque(maxlen=request_log_size)
        self.streams: dict[str, ActiveStream] = {}
        self.lock = asyncio.Lock()
        self.started_at = time.time()

    # ----- audit / request log -------------------------------------------------

    def audit(
        self, event: str, *, ip: str | None = None, device_id: str | None = None, **detail: Any
    ) -> AuditEntry:
        entry = AuditEntry(ts=time.time(), event=event, ip=ip, device_id=device_id, detail=detail)
        self.audit_log.append(entry)
        return entry

    def log_request(self, entry: RequestLogEntry) -> None:
        self.request_log.append(entry)

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
        self.devices[device.id] = device
        self._device_by_token_hash[token_hash] = device.id
        return device

    def device_by_token_hash(self, token_hash: str) -> Device | None:
        device_id = self._device_by_token_hash.get(token_hash)
        return self.devices.get(device_id) if device_id else None

    def touch_device(self, device: Device, ip: str | None, port: int | None, user_agent: str) -> None:
        device.last_seen = time.time()
        device.last_ip = ip
        device.last_port = port
        if user_agent:
            device.user_agent = user_agent[:512]

    def revoke_device(self, device_id: str) -> Device:
        device = self.devices[device_id]
        device.status = DeviceStatus.REVOKED
        self._device_by_token_hash.pop(device.token_hash, None)
        self.kill_device_streams(device_id, "revoked")
        return device

    # ----- active streams ------------------------------------------------------

    def register_stream(self, device_id: str, method: str, path: str) -> ActiveStream:
        stream = ActiveStream(
            id=uuid.uuid4().hex, device_id=device_id, method=method, path=path, started_at=time.time()
        )
        self.streams[stream.id] = stream
        return stream

    def unregister_stream(self, stream: ActiveStream) -> None:
        self.streams.pop(stream.id, None)

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
