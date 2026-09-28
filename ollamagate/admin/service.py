"""Admin actions, shared by the TUI and the CLI control channel.

Every owner action goes through here so there is exactly one code path to
audit, and every action writes an audit entry.
"""

from __future__ import annotations

import time
from typing import Any

from ..config import Config
from ..server import auth, pairing
from ..state import Device, DeviceStatus, State, WindowState
from .ipc import AdminError

EXPIRY_PRESETS = {"never": None, "1d": 86400, "7d": 7 * 86400, "30d": 30 * 86400}


def device_view(device: Device, state: State) -> dict[str, Any]:
    """A JSON-safe view of a device. Never includes the token hash."""
    return {
        "id": device.id,
        "name": device.name,
        "status": device.status.value,
        "notes": device.notes,
        "paired_via": device.paired_via,
        "paired_at": device.paired_at,
        "last_seen": device.last_seen,
        "last_ip": device.last_ip,
        "last_port": device.last_port,
        "user_agent": device.user_agent,
        "token_prefix": device.token_prefix,
        "token_expires_at": device.token_expires_at,
        "token_rotated_at": device.token_rotated_at,
        "allow_model_management": device.allow_model_management,
        "active_streams": len(state.device_streams(device.id)),
        "ip_history": [
            {"ip": ip, "first_seen": h.first_seen, "last_seen": h.last_seen, "count": h.count}
            for ip, h in device.ip_history.items()
        ],
    }


class Admin:
    def __init__(self, state: State, config: Config, fingerprint: str | None) -> None:
        self.state = state
        self.config = config
        self.fingerprint = fingerprint

    # ----- helpers -------------------------------------------------------------

    def _device(self, ref: object) -> Device:
        if not isinstance(ref, str) or not ref:
            raise AdminError("device id required")
        try:
            return self.state.find_device(ref)
        except KeyError as exc:
            raise AdminError(str(exc.args[0])) from None

    def _audit(self, action: str, device: Device | None = None, **detail: Any) -> None:
        self.state.audit(f"admin_{action}", device_id=device.id if device else None, **detail)

    # ----- devices ---------------------------------------------------------------

    def list_devices(self) -> list[dict[str, Any]]:
        return [device_view(d, self.state) for d in self.state.list_devices()]

    def show_device(self, ref: str) -> dict[str, Any]:
        return device_view(self._device(ref), self.state)

    def rename(self, ref: str, name: str) -> dict[str, Any]:
        device = self._device(ref)
        clean = pairing.clean_device_name(name)
        if clean is None:
            raise AdminError("invalid name (1-64 printable characters)")
        old = device.name
        self.state.update_device(device.id, name=clean)
        self._audit("rename", device, old=old, new=clean)
        return device_view(device, self.state)

    def set_notes(self, ref: str, notes: str) -> dict[str, Any]:
        device = self._device(ref)
        if not isinstance(notes, str) or len(notes) > 2000:
            raise AdminError("notes must be text up to 2000 characters")
        self.state.update_device(device.id, notes=notes)
        self._audit("notes", device)
        return device_view(device, self.state)

    def revoke(self, ref: str) -> dict[str, Any]:
        device = self._device(ref)
        killed = len(self.state.device_streams(device.id))
        self.state.revoke_device(device.id)
        self._audit("revoke", device, streams_killed=killed)
        return device_view(device, self.state)

    def rotate(self, ref: str, grace_seconds: int = 0) -> dict[str, Any]:
        device = self._device(ref)
        if device.status is DeviceStatus.REVOKED:
            raise AdminError("device is revoked; it must pair again")
        if not isinstance(grace_seconds, int) or not (0 <= grace_seconds <= 7 * 86400):
            raise AdminError("grace_seconds must be between 0 and 604800")
        token = auth.new_device_token()
        self.state.rotate_token(
            device.id, auth.hash_token(token), auth.display_prefix(token), grace_seconds=grace_seconds
        )
        self._audit("rotate", device, grace_seconds=grace_seconds)
        # The new token is returned to the owner exactly once, to hand to the device.
        return {"device": device_view(device, self.state), "token": token}

    def suspend(self, ref: str) -> dict[str, Any]:
        device = self._device(ref)
        if device.status is DeviceStatus.REVOKED:
            raise AdminError("device is revoked")
        self.state.set_status(device.id, DeviceStatus.SUSPENDED)
        self.state.kill_device_streams(device.id, "suspended")
        self._audit("suspend", device)
        return device_view(device, self.state)

    def resume(self, ref: str) -> dict[str, Any]:
        device = self._device(ref)
        if device.status is not DeviceStatus.SUSPENDED:
            raise AdminError("device is not suspended")
        self.state.set_status(device.id, DeviceStatus.ACTIVE)
        self._audit("resume", device)
        return device_view(device, self.state)

    def kick(self, ref: str) -> dict[str, Any]:
        device = self._device(ref)
        killed = self.state.kill_device_streams(device.id, "kicked")
        self._audit("kick", device, streams_killed=killed)
        return {"streams_killed": killed}

    def set_expiry(self, ref: str, expiry: str | int | None) -> dict[str, Any]:
        """``expiry`` is a preset ("never", "1d", "7d", "30d") or seconds from now."""
        device = self._device(ref)
        if isinstance(expiry, str) and expiry in EXPIRY_PRESETS:
            seconds = EXPIRY_PRESETS[expiry]
        elif isinstance(expiry, int) and not isinstance(expiry, bool) and 60 <= expiry <= 3650 * 86400:
            seconds = expiry
        else:
            raise AdminError("expiry must be never, 1d, 7d, 30d or 60..315360000 seconds")
        expires_at = None if seconds is None else time.time() + seconds
        self.state.update_device(device.id, token_expires_at=expires_at)
        self._audit("expiry", device, expires_at=expires_at)
        return device_view(device, self.state)

    # ----- pairing ---------------------------------------------------------------

    def open_pairing(self, methods: list[str] | None = None, ttl: int | None = None) -> dict[str, Any]:
        methods_t = tuple(methods) if methods else pairing.METHODS
        if any(m not in pairing.METHODS for m in methods_t):
            raise AdminError("methods must be code, qr and/or link")
        ttl = self.config.pairing.ttl_seconds if ttl is None else ttl
        if not isinstance(ttl, int) or not (30 <= ttl <= 3600):
            raise AdminError("ttl must be between 30 and 3600 seconds")
        secrets_ = pairing.open_window(
            self.state,
            base_url=self.config.base_url,
            fingerprint=self.fingerprint,
            ttl_seconds=ttl,
            max_attempts=self.config.pairing.max_attempts,
            methods=methods_t,
        )
        return {
            "window_id": secrets_.window_id,
            "expires_at": secrets_.expires_at,
            "code": secrets_.code_display,
            "qr_url": secrets_.qr_url,
            "link_url": secrets_.link_url,
            "fingerprint": self.fingerprint,
        }

    def cancel_pairing(self) -> dict[str, Any]:
        was_open = pairing.current_window(self.state) is not None
        pairing.close_window(self.state, WindowState.CANCELLED, reason="owner")
        return {"cancelled": was_open}

    def pairing_status(self, window_id: str) -> dict[str, Any]:
        window = pairing.current_window(self.state)
        if window is not None and window.id == window_id:
            return {"state": "open", "expires_at": window.expires_at, "attempts": window.attempts}
        for past in reversed(self.state.pairing_history):
            if past.id == window_id:
                result: dict[str, Any] = {"state": past.state.value, "attempts": past.attempts}
                device = self.state.get_device(past.device_id) if past.device_id else None
                if device is not None:
                    result["device"] = device_view(device, self.state)
                return result
        raise AdminError("unknown pairing window")

    # ----- logs --------------------------------------------------------------------

    def audit_log(self, limit: int = 50, event: str | None = None) -> list[dict[str, Any]]:
        if not isinstance(limit, int) or not (1 <= limit <= 5000):
            raise AdminError("limit must be 1..5000")
        entries = [e for e in self.state.audit_log if event is None or e.event.startswith(event)]
        return [
            {"ts": e.ts, "event": e.event, "ip": e.ip, "device_id": e.device_id, "detail": e.detail}
            for e in entries[-limit:]
        ]

    # ----- dispatch for the control channel ------------------------------------------

    COMMANDS = {
        "devices.list": "list_devices",
        "devices.show": "show_device",
        "devices.rename": "rename",
        "devices.notes": "set_notes",
        "devices.revoke": "revoke",
        "devices.rotate": "rotate",
        "devices.suspend": "suspend",
        "devices.resume": "resume",
        "devices.kick": "kick",
        "devices.expiry": "set_expiry",
        "pairing.open": "open_pairing",
        "pairing.cancel": "cancel_pairing",
        "pairing.status": "pairing_status",
        "audit.list": "audit_log",
    }

    async def dispatch(self, cmd: str, args: dict[str, Any]) -> Any:
        method_name = self.COMMANDS.get(cmd)
        if method_name is None:
            raise AdminError(f"unknown command {cmd!r}")
        try:
            return getattr(self, method_name)(**args)
        except TypeError as exc:
            raise AdminError(f"bad arguments for {cmd}") from exc
