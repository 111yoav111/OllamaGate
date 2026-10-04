"""Owner notifications for security-relevant events.

Configured in ``[notify]``; every channel is off by default. Messages contain
metadata only (device name, IP, reason) - never tokens, pairing secrets or
prompt content. Sending is asynchronous, rate-limited and best effort: a slow
or failing channel never delays or breaks request handling.

Channels:

* ``ntfy_url``: an ntfy topic URL (https://ntfy.sh/<topic> or your own server);
  pick an unguessable topic name, since anyone who knows it can read it.
* ``telegram_bot_token`` + ``telegram_chat_id``: a Telegram bot.
* ``desktop = true``: notify-send (Linux) / osascript (macOS) on this machine.
"""

from __future__ import annotations

import asyncio
import html
import logging
import shutil
import subprocess
import sys
import time
from typing import Any

import httpx

from .config import NotifyConfig
from .state import AuditEntry, State
from .textsafe import safe_text

log = logging.getLogger("ollamagate.notify")

MAX_PER_MINUTE = 20
QUEUE_SIZE = 100

# audit event -> (notify.events name, message builder)
EVENTS = {
    "pairing_succeeded": "pairing",
    "device_new_ip": "new_ip",
    "ban_auto": "ban",
    "admin_ban": "ban",
    "admin_lockdown_on": "lockdown",
    "admin_lockdown_off": "lockdown",
    "pairing_destroyed": "pairing",
}


def describe(entry: AuditEntry, state: State) -> str | None:
    """A short, secret-free sentence for an audit entry (None = not notifiable)."""
    device = state.get_device(entry.device_id) if entry.device_id else None
    # Quoted, so a device named e.g. "Lockdown lifted" can't pose as a system message.
    name = f'"{safe_text(device.name, 64)}"' if device else "a device"
    d = entry.detail
    ip = safe_text(entry.ip or "?", 64) + (f" ({safe_text(str(d['country']), 8)})" if d.get("country") else "")
    if entry.event == "pairing_succeeded":
        return f"New device paired: {name} (via {d.get('method', '?')}) from {ip}"
    if entry.event == "device_new_ip":
        return f"{name} connected from a new IP: {ip}"
    if entry.event == "ban_auto":
        return f"Auto-banned {ip} ({d.get('reason', '?')}, strike {d.get('strikes', 1)})"
    if entry.event == "admin_ban":
        return f"Owner banned {safe_text(str(d.get('key', ip)), 64)}"
    if entry.event == "admin_lockdown_on":
        return "LOCKDOWN enabled: all traffic is rejected"
    if entry.event == "admin_lockdown_off":
        return "Lockdown lifted"
    if entry.event == "pairing_destroyed":
        return "A pairing window was destroyed after too many wrong attempts"
    return None


# Events that are always delivered (not subject to the rate limit): the ones an
# attacker can't mass-produce and the owner must never miss.
PRIORITY = {"pairing", "lockdown"}
SUMMARY_INTERVAL = 60.0


class Notifier:
    def __init__(self, config: NotifyConfig, state: State, client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self.state = state
        self.client = client
        self.queue: asyncio.Queue[tuple[bool, str]] = asyncio.Queue(maxsize=QUEUE_SIZE)  # (priority, text)
        self._sent: list[float] = []
        self.dropped = 0
        # Bans can be mass-produced (e.g. many IPv6 /64s): count them and send one
        # summary per interval instead of a push per ban.
        self.pending_bans = 0
        self._last_summary = time.monotonic()

    @property
    def enabled(self) -> bool:
        c = self.config
        return bool(c.ntfy_url or (c.telegram_bot_token and c.telegram_chat_id) or c.desktop)

    def on_audit(self, entry: AuditEntry) -> None:
        """State listener: called synchronously for every audit entry. Must not block."""
        kind = EVENTS.get(entry.event)
        if kind is None or kind not in self.config.events:
            return
        if entry.event == "ban_auto":
            self.pending_bans += 1
            return
        message = describe(entry, self.state)
        if message is None:
            return
        try:
            self.queue.put_nowait((kind in PRIORITY, message))
        except asyncio.QueueFull:
            self.dropped += 1

    def _summary(self) -> str | None:
        parts = []
        if self.pending_bans:
            parts.append(f"{self.pending_bans} client(s) auto-banned in the last minute")
            self.pending_bans = 0
        if self.dropped:
            parts.append(f"{self.dropped} notification(s) dropped (too many events)")
            self.dropped = 0
        return "; ".join(parts) or None

    async def run(self) -> None:
        """Deliver queued messages until cancelled. Never dies on a delivery error."""
        own_client = self.client is None
        client = self.client or httpx.AsyncClient(timeout=10)
        try:
            while True:
                try:
                    item = await asyncio.wait_for(self.queue.get(), SUMMARY_INTERVAL / 4)
                except asyncio.TimeoutError:
                    item = None
                now = time.monotonic()
                if now - self._last_summary >= SUMMARY_INTERVAL:
                    summary = self._summary()
                    if summary:
                        self._last_summary = now
                        await self._deliver(client, summary)
                if item is None:
                    continue
                priority, message = item
                self._sent = [t for t in self._sent if now - t < 60]
                if not priority and len(self._sent) >= MAX_PER_MINUTE:
                    self.dropped += 1
                    continue
                self._sent.append(now)
                await self._deliver(client, message)
        finally:
            if own_client:
                await client.aclose()

    async def _deliver(self, client: httpx.AsyncClient, message: str) -> None:
        c = self.config
        text = "OllamaGate: " + message
        channels = []
        if c.ntfy_url:
            channels.append(("ntfy", lambda: client.post(c.ntfy_url, content=text.encode(), headers={"Title": "OllamaGate"})))
        if c.telegram_bot_token and c.telegram_chat_id:
            channels.append(("telegram", lambda: client.post(
                f"https://api.telegram.org/bot{c.telegram_bot_token}/sendMessage",
                json={"chat_id": c.telegram_chat_id, "text": text},
            )))
        if c.desktop:
            channels.append(("desktop", lambda: asyncio.to_thread(desktop_notify, text)))
        for name, send in channels:
            try:
                response = await send()
                if isinstance(response, httpx.Response) and response.status_code >= 400:
                    log.warning("%s notification rejected: HTTP %d", name, response.status_code)
            except Exception as exc:  # noqa: BLE001 - one broken channel must not stop the others
                # Only the type: URLs/messages may contain the bot token or topic.
                log.warning("%s notification failed: %s", name, type(exc).__name__)


def desktop_notify(text: str) -> None:
    """Show a desktop notification on this machine (best effort)."""
    cmd: list[str] | None = None
    if sys.platform.startswith("linux") and shutil.which("notify-send"):
        # notify-send renders Pango markup in the body: escape it.
        cmd = ["notify-send", "OllamaGate", html.escape(text)]
    elif sys.platform == "darwin" and shutil.which("osascript"):
        # Passed as an argument, never interpolated into the script: no injection.
        script = 'on run argv\ndisplay notification (item 1 of argv) with title "OllamaGate"\nend run'
        cmd = ["osascript", "-e", script, text]
    if cmd is None:
        return
    try:
        subprocess.run(cmd, timeout=10, check=False, capture_output=True)
    except (OSError, subprocess.SubprocessError):
        pass


def attach(state: State, config: NotifyConfig, **kwargs: Any) -> Notifier | None:
    """Create a notifier and subscribe it to the audit log, if any channel is configured."""
    notifier = Notifier(config, state, **kwargs)
    if not notifier.enabled:
        return None
    state.audit_listeners.append(notifier.on_audit)
    return notifier
