"""Admin actions, shared by the TUI and the CLI control channel.

Every owner action goes through here so there is exactly one code path to
audit, and every action writes an audit entry.
"""

from __future__ import annotations

import copy
import inspect
import ipaddress
import time
from dataclasses import asdict, fields, replace
from typing import Any
from urllib.parse import urlsplit

from ..config import Config, ConfigError, is_loopback_host
from ..server import auth, pairing
from ..state import PRIORITIES, Device, DeviceLimits, DeviceStatus, State, WindowState
from ..uaparse import summarize as summarize_ua
from .ipc import AdminError

# "Seen recently" threshold for the yellow status dot.
RECENT_SECONDS = 300

# Settings that are safe to change while running: (section, key) -> type.
RUNTIME_SETTINGS: dict[str, type] = {
    "server.public_url": str,
    "pairing.ttl_seconds": int,
    "pairing.max_attempts": int,
    "limits.max_concurrent": int,
    "limits.allow_model_management": bool,
}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


EXPIRY_PRESETS = {"never": None, "1d": 86400, "7d": 7 * 86400, "30d": 30 * 86400}


def activity(device: Device, state: State, now: float | None = None) -> str:
    """streaming | recent | idle | suspended | revoked (the TUI's colored dot)."""
    if device.status is not DeviceStatus.ACTIVE:
        return device.status.value
    if state.device_streams(device.id):
        return "streaming"
    now = time.time() if now is None else now
    if device.last_seen is not None and now - device.last_seen < RECENT_SECONDS:
        return "recent"
    return "idle"


def device_view(device: Device, state: State) -> dict[str, Any]:
    """A JSON-safe view of a device. Never includes the token hash."""
    streams = state.device_streams(device.id)
    today = state.usage_today(device.id)
    month = state.usage_month(device.id)
    total = state.usage_lifetime(device.id)
    return {
        "activity": activity(device, state),
        "client": summarize_ua(device.user_agent),
        "current_models": sorted({s.model for s in streams if s.model}),
        "requests_today": today.requests,
        "requests_month": month.requests,
        "requests_total": total.requests,
        "tokens_today": today.prompt_tokens + today.completion_tokens,
        "tokens_month": month.prompt_tokens + month.completion_tokens,
        "tokens_total": total.prompt_tokens + total.completion_tokens,
        "tokens_per_second": round(
            sum(s.usage.chunks / max(time.time() - s.started_at, 0.001) for s in streams if s.usage is not None), 1
        ),
        "limits": asdict(device.limits),
        "id": device.id,
        "name": device.name,
        "status": device.status.value,
        "notes": device.notes,
        "paired_via": device.paired_via,
        "paired_at": device.paired_at,
        "last_seen": device.last_seen,
        "last_ip": device.last_ip,
        "last_country": state.geo.country(device.last_ip) if state.geo is not None else None,
        "last_port": device.last_port,
        "user_agent": device.user_agent,
        "token_prefix": device.token_prefix,
        "token_expires_at": device.token_expires_at,
        "token_rotated_at": device.token_rotated_at,
        "client_cert": device.client_cert_fp[:16] if device.client_cert_fp else None,
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
        if not _is_int(grace_seconds) or not (0 <= grace_seconds <= 7 * 86400):
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
        self._audit("suspend", device)
        return device_view(device, self.state)

    def resume(self, ref: str) -> dict[str, Any]:
        device = self._device(ref)
        if device.status is not DeviceStatus.SUSPENDED:
            raise AdminError("device is not suspended")
        self.state.set_status(device.id, DeviceStatus.ACTIVE)
        self._audit("resume", device)
        return device_view(device, self.state)

    def set_model_management(self, ref: str, allowed: bool) -> dict[str, Any]:
        """Grant or deny model management endpoints (pull/push/delete/create/copy)."""
        device = self._device(ref)
        if not isinstance(allowed, bool):
            raise AdminError("allowed must be true or false")
        self.state.update_device(device.id, allow_model_management=allowed)
        self._audit("model_management", device, allowed=allowed)
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
        elif _is_int(expiry) and 60 <= expiry <= 3650 * 86400:
            seconds = expiry
        else:
            raise AdminError("expiry must be never, 1d, 7d, 30d or 60..315360000 seconds")
        expires_at = None if seconds is None else time.time() + seconds
        self.state.update_device(device.id, token_expires_at=expires_at)
        self._audit("expiry", device, expires_at=expires_at)
        return device_view(device, self.state)

    def set_limits(self, ref: str, **changes: Any) -> dict[str, Any]:
        """Change some of a device's limits (live, until restart)."""
        device = self._device(ref)
        known = {f.name for f in fields(DeviceLimits)}
        unknown = set(changes) - known
        if unknown:
            raise AdminError(f"unknown limit(s) {', '.join(sorted(unknown))}; known: {', '.join(sorted(known))}")
        clean: dict[str, Any] = {}
        for key, value in changes.items():
            if key == "allowed_models":
                if isinstance(value, str):
                    value = [v.strip() for v in value.split(",") if v.strip()]
                if not isinstance(value, list) or not all(isinstance(v, str) and 0 < len(v) <= 200 for v in value):
                    raise AdminError("allowed_models must be a list of model names (empty = all)")
                if len(value) > 100:
                    raise AdminError("at most 100 allowed models")
                clean[key] = value
            elif key == "priority":
                if value not in PRIORITIES:
                    raise AdminError("priority must be low, normal or high")
                clean[key] = value
            else:
                if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 12:
                    value = int(value)
                if not _is_int(value) or not (0 <= value <= 10**12):
                    raise AdminError(f"{key} must be a whole number >= 0")
                if key == "max_concurrent" and value < 1:
                    raise AdminError("max_concurrent must be at least 1")
                clean[key] = value
        new = replace(device.limits, **clean)
        self.state.update_device(device.id, limits=new)
        self._audit("limits", device, **{k: str(v) for k, v in clean.items()})
        return device_view(device, self.state)

    # ----- bans ------------------------------------------------------------------

    def list_bans(self) -> list[dict[str, Any]]:
        now = time.time()
        return [
            {"key": b.key, "reason": b.reason, "created_at": b.created_at, "until": b.until,
             "manual": b.manual, "strikes": b.strikes}
            for b in self.state.bans.bans.values()
            if b.active(now)
        ]

    def add_ban(self, ip: str, seconds: int | None = None, reason: str = "manual") -> dict[str, Any]:
        if not isinstance(ip, str):
            raise AdminError("ip must be text")
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            raise AdminError(f"not an IP address: {ip!r}") from None
        if addr.is_loopback:
            raise AdminError("refusing to ban loopback (that's you)")
        if seconds is not None and (not _is_int(seconds) or seconds < 60):
            raise AdminError("seconds must be at least 60 (or omitted for until-lifted)")
        if not isinstance(reason, str) or len(reason) > 200:
            raise AdminError("reason must be short text")
        ban = self.state.bans.ban(str(addr), reason, seconds)
        # Cut everything that is currently streaming from that client.
        killed = 0
        for d in self.state.list_devices():
            if d.last_ip is not None and self.state.bans.banned(d.last_ip) is ban:
                killed += self.state.kill_device_streams(d.id, "IP banned")
        self._audit("ban", ip=str(addr), key=ban.key, seconds=seconds, reason=reason, streams_killed=killed)
        self.state._changed()
        return {"key": ban.key, "until": ban.until, "streams_killed": killed}

    def remove_ban(self, ip: str) -> dict[str, Any]:
        if not isinstance(ip, str):
            raise AdminError("ip must be text")
        removed = self.state.bans.unban(ip.strip())
        if removed:
            self._audit("unban", ip=ip.strip())
            self.state._changed()
        return {"removed": removed}

    def ban_device_ip(self, ref: str, seconds: int | None = None) -> dict[str, Any]:
        device = self._device(ref)
        if not device.last_ip:
            raise AdminError("this device has no known IP yet")
        return self.add_ban(device.last_ip, seconds, reason=f"banned from device {device.id[:8]}")

    # ----- pairing ---------------------------------------------------------------

    def open_pairing(self, methods: list[str] | None = None, ttl: int | None = None) -> dict[str, Any]:
        if self.state.lockdown:
            raise AdminError("server is in lockdown; turn it off before pairing")
        if methods is not None and not isinstance(methods, list):
            raise AdminError("methods must be a list")
        methods_t = tuple(methods) if methods else pairing.METHODS
        if any(m not in pairing.METHODS for m in methods_t):
            raise AdminError("methods must be code, qr and/or link")
        ttl = self.config.pairing.ttl_seconds if ttl is None else ttl
        if not _is_int(ttl) or not (30 <= ttl <= 3600):
            raise AdminError("ttl must be between 30 and 3600 seconds")
        secrets_ = pairing.open_window(
            self.state,
            base_url=self.config.base_url,
            fingerprint=self.fingerprint,
            ttl_seconds=ttl,
            max_attempts=self.config.pairing.max_attempts,
            methods=methods_t,
        )
        host = urlsplit(self.config.base_url).hostname or ""
        warning = None
        if is_loopback_host(host):
            warning = (
                f"Pairing links point at {self.config.base_url}, which other devices can't reach. "
                "Set server.public_url (and server.host) in config.toml."
            )
        return {
            "warning": warning,
            "window_id": secrets_.window_id,
            "expires_at": secrets_.expires_at,
            "code": secrets_.code_display,
            "qr_url": secrets_.qr_url,
            "link_url": secrets_.link_url,
            "fingerprint": self.fingerprint,
        }

    def cancel_pairing(self, window_id: str | None = None) -> dict[str, Any]:
        """Close the open window (only if it is ``window_id``, when given)."""
        window = pairing.current_window(self.state)
        if window is None or (window_id is not None and window.id != window_id):
            return {"cancelled": False}
        pairing.close_window(self.state, WindowState.CANCELLED, reason="owner")
        return {"cancelled": True}

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

    # ----- lockdown ------------------------------------------------------------------

    def set_lockdown(self, on: bool) -> dict[str, Any]:
        """Reject all traffic and close pairing, keeping every device and setting."""
        if not isinstance(on, bool):
            raise AdminError("on must be true or false")
        if on:
            pairing.close_window(self.state, WindowState.CANCELLED, reason="lockdown")
        killed = len(self.state.streams) if on else 0
        self.state.set_lockdown(on)
        self._audit("lockdown_on" if on else "lockdown_off", streams_killed=killed)
        return {"lockdown": self.state.lockdown, "streams_killed": killed}

    # ----- settings ------------------------------------------------------------------

    def get_settings(self) -> dict[str, Any]:
        out = {}
        for dotted in RUNTIME_SETTINGS:
            section, key = dotted.split(".")
            out[dotted] = getattr(getattr(self.config, section), key)
        return out

    def set_setting(self, key: str, value: Any) -> dict[str, Any]:
        """Change a runtime-safe setting until restart (config.toml is not modified)."""
        if key not in RUNTIME_SETTINGS:
            raise AdminError(f"not changeable at runtime; allowed: {', '.join(RUNTIME_SETTINGS)}")
        wanted = RUNTIME_SETTINGS[key]
        if isinstance(value, str) and wanted is not str:
            if wanted is bool and value.lower() in ("true", "false", "on", "off", "yes", "no"):
                value = value.lower() in ("true", "on", "yes")
            elif wanted is int and len(value) <= 12 and value.strip().isascii() and value.strip().lstrip("-").isdigit():
                value = int(value)
        if wanted is int and not _is_int(value) or wanted is not int and not isinstance(value, wanted):
            raise AdminError(f"{key} must be {wanted.__name__}")
        section, attr = key.split(".")
        trial = copy.deepcopy(self.config)
        setattr(getattr(trial, section), attr, value)
        try:
            trial.validate()
        except ConfigError as exc:
            raise AdminError(str(exc)) from None
        old = getattr(getattr(self.config, section), attr)
        setattr(getattr(self.config, section), attr, value)
        self._audit("setting", key=key, old=str(old), new=str(value))
        return self.get_settings()

    # ----- dashboard -------------------------------------------------------------------

    def dashboard(self) -> dict[str, Any]:
        state = self.state
        window = pairing.current_window(state)
        today = state.usage_all_today()
        return {
            "base_url": self.config.base_url,
            "tls_mode": self.config.tls.mode + (" + client certificates" if self.config.tls.client_certs else ""),
            "network_mode": self.config.network.mode,
            "fingerprint": self.fingerprint,
            "uptime": time.time() - state.started_at,
            "lockdown": state.lockdown,
            "devices": len(state.list_devices()),
            "devices_active": sum(1 for d in state.list_devices() if d.status is DeviceStatus.ACTIVE),
            "active_streams": len(state.streams),
            "requests_last_minute": state.requests_last_minute(),
            "requests_today": today.requests,
            "tokens_today": today.prompt_tokens + today.completion_tokens,
            "pairing": None if window is None else {"expires_at": window.expires_at, "attempts": window.attempts},
            "audit_suppressed": state.audit_suppressed,
            "bans": len(self.list_bans()),
        }

    # ----- logs --------------------------------------------------------------------

    def audit_log(self, limit: int = 50, event: str | None = None) -> list[dict[str, Any]]:
        if not _is_int(limit) or not (1 <= limit <= 5000):
            raise AdminError("limit must be 1..5000")
        if event is not None and not isinstance(event, str):
            raise AdminError("event must be text")
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
        "devices.model_management": "set_model_management",
        "devices.limits": "set_limits",
        "devices.ban_ip": "ban_device_ip",
        "bans.list": "list_bans",
        "bans.add": "add_ban",
        "bans.remove": "remove_ban",
        "lockdown.set": "set_lockdown",
        "settings.get": "get_settings",
        "settings.set": "set_setting",
        "dashboard": "dashboard",
        "pairing.open": "open_pairing",
        "pairing.cancel": "cancel_pairing",
        "pairing.status": "pairing_status",
        "audit.list": "audit_log",
    }

    async def dispatch(self, cmd: str, args: dict[str, Any]) -> Any:
        method_name = self.COMMANDS.get(cmd)
        if method_name is None:
            raise AdminError(f"unknown command {cmd!r}")
        method = getattr(self, method_name)
        try:
            inspect.signature(method).bind(**args)
        except TypeError as exc:
            raise AdminError(f"bad arguments for {cmd}") from exc
        return method(**args)
