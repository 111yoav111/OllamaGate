"""The admin TUI.

It runs in the same process and on the same event loop as the proxy, and acts
only through ``Admin`` - the same audited code path the CLI uses. It is never
reachable over the network.

Live updates: the screen polls ``state.version`` twice a second and redraws
only when something changed, so a flood of requests can't make it spin.
"""

from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlsplit
from collections import deque
from typing import Any, Callable

import httpx
from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Static, TabbedContent, TabPane

from .. import qr
from ..admin.ipc import AdminError
from ..config import is_loopback_host
from ..admin.service import RUNTIME_SETTINGS, Admin
from ..ollama_status import OllamaStatus, human_bytes, probe
from ..server.tls import format_fingerprint
from ..textsafe import safe
from .widgets import ACTIVITY_DOT, ConfirmScreen, InputScreen, MessageScreen, ago, duration, t, ts

log = logging.getLogger("ollamagate.tui")


def _quota(used: int, limit: int) -> str:
    """ "1200", or "1200/5000 (24%)" when there is a daily quota."""
    if not limit:
        return str(used)
    return f"{used}/{limit} ({min(100, used * 100 // limit)}%)"

REFRESH_INTERVAL = 1.0  # redraws share the proxy's event loop; keep them rare
OLLAMA_POLL_INTERVAL = 5.0



class DeviceTable(DataTable):
    """Devices table; device actions are bound here and on the detail screen."""

    BINDINGS = [
        Binding("enter", "app.device_detail", "Details"),
        Binding("r", "app.device_revoke", "Revoke"),
        Binding("t", "app.device_rotate", "Rotate token"),
        Binding("s", "app.device_suspend", "Suspend/resume"),
        Binding("k", "app.device_kick", "Kick"),
        Binding("n", "app.device_rename", "Rename"),
        Binding("l", "app.device_limits", "Limits"),
        Binding("b", "app.device_ban", "Ban IP"),
    ]


class BanTable(DataTable):
    BINDINGS = [Binding("u", "app.unban", "Lift ban")]


class GateTUI(App[None]):
    TITLE = "OllamaGate"
    CSS_PATH = "gate.tcss"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [
        Binding("p", "pair", "Pair"),
        Binding("/", "search", "Search"),
        Binding("ctrl+l", "lockdown", "LOCKDOWN", priority=True),
        Binding("q", "quit_gate", "Quit"),
        # Textual's default Ctrl+Q would quit (and stop the server) without asking.
        Binding("ctrl+q", "quit_gate", "Quit", show=False, priority=True),
        Binding("1", "tab('dashboard')", "Dashboard", show=False),
        Binding("2", "tab('devices')", "Devices", show=False),
        Binding("3", "tab('pairing')", "Pairing", show=False),
        Binding("4", "tab('audit')", "Audit", show=False),
        Binding("5", "tab('bans')", "Bans", show=False),
        Binding("6", "tab('settings')", "Settings", show=False),
    ]

    def __init__(
        self,
        admin: Admin,
        *,
        services: asyncio.Future[Any] | None = None,  # the running server; the TUI exits when it stops
        warnings: list[str] | None = None,
        log_lines: deque[str] | None = None,
        ollama_url: str | None = None,
    ) -> None:
        super().__init__()
        self.admin = admin
        self.state = admin.state
        self.services = services
        self.warnings = warnings or []
        self.log_lines = log_lines if log_lines is not None else deque(maxlen=200)
        self.ollama_url = ollama_url
        self.ollama = OllamaStatus(reachable=False, error="not checked yet")
        self._seen_version = -1
        self._last_audit_seq = 0
        self._audit_rendered_seq = -1
        self._search = ""
        self._audit_filter = ""
        # Plaintext pairing secrets live only here, only while the window is open.
        self._pairing: dict[str, Any] | None = None
        self._pairing_result: Text | None = None  # outcome of the last window we opened
        self._exit_requested = False
        self.quit_confirmed = False  # True only when the owner chose to quit

    # ----- layout ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="dashboard"):
            with TabPane("Dashboard", id="dashboard"):
                with VerticalScroll():
                    yield Static(id="lockdown-banner", classes="banner")
                    yield Static(id="warnings", classes="warnings")
                    yield Static(id="status")
                    yield Static(id="ollama")
                    yield Static(id="log")
            with TabPane("Devices", id="devices"):
                yield Input(placeholder="Search name, id, IP, client…  (Esc to clear)", id="device-search")
                yield DeviceTable(id="device-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Pairing", id="pairing"):
                with VerticalScroll():
                    yield Static(id="pairing-info")
                    with Horizontal(classes="buttons"):
                        yield Button("Open pairing window (P)", id="pair-open", variant="primary")
                        yield Button("Cancel window", id="pair-cancel", variant="error")
                    yield Static(id="pairing-qr", classes="qr")
            with TabPane("Audit log", id="audit"):
                yield Input(placeholder="Filter by event or text, e.g. pairing, auth_failed, 203.0.113.", id="audit-filter")
                yield DataTable(id="audit-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Bans", id="bans"):
                with Horizontal(classes="buttons"):
                    yield Button("Ban an IP…", id="ban-add", variant="error")
                    yield Button("Lift selected ban (U)", id="ban-remove")
                yield BanTable(id="ban-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Settings", id="settings"):
                with VerticalScroll():
                    yield Static(
                        Text(
                            "Runtime changes last until restart; edit config.toml to keep them.\n"
                            "limits.* are defaults for devices paired from now on; "
                            "change an existing device's limits with L on the Devices tab.",
                            style="dim",
                        )
                    )
                    for key in RUNTIME_SETTINGS:
                        with Horizontal(classes="setting"):
                            yield Label(key, classes="setting-key")
                            yield Input(id="set-" + key.replace(".", "-"), classes="setting-value")
                            yield Button("Save", id="save-" + key.replace(".", "-"))
        yield Footer()

    def on_mount(self) -> None:
        devices = self._q("#device-table", DataTable)
        self._device_columns = devices.add_columns(
            "", "Name", "ID", "IP", "Client", "Via", "Last seen", "Now", "Req today", "Tokens today"
        )
        self._q("#ban-table", DataTable).add_columns("Client", "Until", "Kind", "Reason")
        audit = self._q("#audit-table", DataTable)
        audit.add_columns("Time", "Event", "IP", "Device", "Detail")
        self._fill_settings()
        self.set_interval(REFRESH_INTERVAL, self.refresh_if_changed)
        self.set_interval(1.0, self._tick)
        if self.ollama_url:
            self._ollama_client = httpx.AsyncClient(base_url=self.ollama_url, trust_env=False)
            self.set_interval(OLLAMA_POLL_INTERVAL, self.poll_ollama)
            self.call_later(self.poll_ollama)
        if self.services is not None:
            self.run_worker(self._run_services(), exclusive=True, group="services")
        self.refresh_all()

    async def _run_services(self) -> None:
        assert self.services is not None
        try:
            # shield: when the TUI exits it cancels this worker, which must not cancel the server.
            await asyncio.shield(self.services)
        except asyncio.CancelledError:
            raise
        except BaseException:  # noqa: BLE001 - the server crashed; show nothing more here
            pass
        self.exit()  # the server stopped (signal or error): leave the TUI too

    # ----- refresh -------------------------------------------------------------------

    def refresh_if_changed(self) -> None:
        if not self._is_live():
            return
        if self.state.version != self._seen_version:
            self.refresh_all()

    def _is_live(self) -> bool:
        return self.is_running and bool(self.screen_stack) and not self._exit_requested

    def _tick(self) -> None:
        """Once a second: countdowns, "x seconds ago" and pairing state change."""
        if not self._is_live():
            return
        self._update_pairing()
        self._update_dashboard()

    def refresh_all(self) -> None:
        """Redraw what is visible. Hidden tabs are redrawn when they are shown."""
        self._seen_version = self.state.version
        tab = self._q(TabbedContent).active
        if tab == "dashboard":
            self._update_dashboard()
        elif tab == "devices":
            self._update_devices()
        elif tab == "audit":
            self._update_audit()
        elif tab == "bans":
            self._update_bans()
        elif tab == "settings":
            self._fill_settings(only_unfocused=True)
        self._update_pairing()
        self._notify_new_events()

    async def poll_ollama(self) -> None:
        try:
            self.ollama = await probe(self._ollama_client)
        except Exception as exc:  # noqa: BLE001 - whatever Ollama returns, keep running
            self.ollama = OllamaStatus(reachable=False, error=type(exc).__name__)
        if self._is_live():
            self._update_dashboard()

    def _notify_new_events(self) -> None:
        """Toasts for events the owner should notice right away.

        Tracks the audit sequence number, not the log length: the log is a ring
        buffer whose length stops changing once it is full.
        """
        new = [e for e in self.state.audit_log if e.seq > self._last_audit_seq][-5:]
        self._last_audit_seq = self.state.audit_seq
        for e in new:
            name = self._device_name(e.device_id)
            if e.event == "pairing_succeeded":
                self.say(f"New device paired: {name}", title="Pairing", timeout=8)
            elif e.event == "device_new_ip":
                self.say(f"{name} connected from a new IP: {e.ip}", title="New IP", severity="warning", timeout=8)
            elif e.event == "ban_auto":
                self.say(f"Banned {e.detail.get('reason', '')}: {e.ip}", title="Auto-ban", severity="warning", timeout=8)
            elif e.event == "pairing_destroyed":
                self.say("Pairing window destroyed after too many wrong attempts", severity="error")

    def _device_name(self, device_id: str | None) -> str:
        device = self.state.get_device(device_id) if device_id else None
        return t(device.name).plain if device else (device_id or "-")[:8]

    def _update_dashboard(self) -> None:
        d = self.admin.dashboard()
        banner = self._q("#lockdown-banner", Static)
        banner.update(Text("  LOCKDOWN — all traffic is rejected. Press Ctrl+L to lift.  ", style="bold white on red") if d["lockdown"] else "")
        banner.display = d["lockdown"]

        warn = self._q("#warnings", Static)
        warnings = list(self.warnings)
        if is_loopback_host(urlsplit(self.admin.config.base_url).hostname or ""):
            warnings.append("server.public_url is not set: pairing links point at loopback, phones can't reach them.")
        if self.ollama.reachable is False and self.ollama_url:
            warnings.append(f"Ollama not reachable at {self.ollama_url} ({self.ollama.error})")
        warn.update(Text("\n".join("⚠ " + w for w in warnings), style="bold red") if warnings else "")
        warn.display = bool(warnings)

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold")
        grid.add_column()
        pairing = d["pairing"]
        rows = [
            ("Public URL", d["base_url"]),
            ("TLS", d["tls_mode"] + (f"  SHA-256 {format_fingerprint(d['fingerprint'])}" if d["fingerprint"] else "")),
            ("Network mode", d["network_mode"]),
            ("Uptime", duration(d["uptime"])),
            ("Devices", f"{d['devices_active']} active / {d['devices']} total"),
            ("Active streams", str(d["active_streams"])),
            ("Requests", f"{d['requests_last_minute']}/min · {d['requests_today']} today"),
            ("Tokens today", str(d["tokens_today"])),
            ("Banned clients", str(d["bans"])),
            ("Pairing", "closed" if pairing is None else f"OPEN · {int(pairing['expires_at'] - time.time())}s left"),
        ]
        if d["audit_suppressed"]:
            rows.append(("Noisy events", f"{d['audit_suppressed']} not logged (rate-capped)"))
        for label, value in rows:
            grid.add_row(label, t(value))
        self._q("#status", Static).update(grid)

        o = self.ollama
        if o.reachable:
            models = Table("Loaded model", "Size", "VRAM", box=None, header_style="bold")
            for m in o.models:
                models.add_row(t(m.name), human_bytes(m.size), human_bytes(m.size_vram))
            body: Any = Group(Text(f"Ollama {o.version} · {len(o.models)} model(s) loaded", style="bold green"), models)
        else:
            body = Text(f"Ollama: {'not checked' if not self.ollama_url else 'unreachable'}", style="bold red")
        self._q("#ollama", Static).update(body)

        lines = list(self.log_lines)[-8:]
        log_box = self._q("#log", Static)
        log_box.update(Group(Text("Recent log", style="bold"), *(t(line, "dim") for line in lines)) if lines else "")
        log_box.display = bool(lines)

    def _update_devices(self) -> None:
        table = self._q("#device-table", DataTable)
        needle = self._search.lower()
        rows: list[tuple[str, list[Text]]] = []
        for d in sorted(self.admin.list_devices(), key=lambda v: v["paired_at"]):
            haystack = " ".join(str(d[k] or "") for k in ("name", "id", "last_ip", "client", "user_agent")).lower()
            if needle and needle not in haystack:
                continue
            now = ", ".join(d["current_models"]) or (f"{d['active_streams']} stream(s)" if d["active_streams"] else "")
            if d["tokens_per_second"]:
                now += f" · {d['tokens_per_second']} tok/s"
            cells = [
                ACTIVITY_DOT.get(d["activity"], Text("?")),
                t(d["name"]),
                t(d["id"][:8]),
                t(d["last_ip"]),
                t(d["client"]),
                t(d["paired_via"]),
                t(ago(d["last_seen"])),
                t(now),
                t(d["requests_today"]),
                t(_quota(d["tokens_today"], d["limits"]["tokens_per_day"])),
            ]
            rows.append((d["id"], cells))
        current = [row.key.value for row in table.ordered_rows]
        if current == [key for key, _ in rows]:
            # Same devices in the same order: update cells in place (cursor stays put).
            for key, cells in rows:
                for column, cell in zip(self._device_columns, cells):
                    table.update_cell(key, column, cell)
            return
        selected = self._selected_device_id()
        table.clear()
        for key, cells in rows:
            table.add_row(*cells, key=key)
        if selected is not None and selected in [key for key, _ in rows]:
            table.move_cursor(row=table.get_row_index(selected))

    def _update_audit(self, force: bool = False) -> None:
        if not force and self.state.audit_seq == self._audit_rendered_seq:
            return  # rebuilding 1000 rows is costly; only do it when the log changed
        self._audit_rendered_seq = self.state.audit_seq
        table = self._q("#audit-table", DataTable)
        # Keep the cursor on the same entry (new rows appear above it).
        selected = None
        if table.row_count:
            try:
                selected = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
            except Exception:  # noqa: BLE001
                selected = None
        table.clear()
        needle = self._audit_filter.lower()
        for e in reversed(list(self.state.audit_log)[-1000:]):
            detail = " ".join(f"{k}={v}" for k, v in e.detail.items())
            if needle and needle not in f"{e.event} {e.ip} {e.device_id} {detail}".lower():
                continue
            style = "red" if e.event in ("auth_failed", "pairing_failed", "pairing_destroyed") or "lockdown" in e.event else ""
            table.add_row(
                t(ts(e.ts)), t(e.event, style), t(e.ip), t((e.device_id or "")[:8]), t(detail), key=str(e.seq)
            )
        if selected is not None:
            try:
                table.move_cursor(row=table.get_row_index(selected), scroll=False)
            except Exception:  # noqa: BLE001 - the entry fell out of the view
                pass

    def _update_bans(self) -> None:
        table = self._q("#ban-table", DataTable)
        bans = sorted(self.admin.list_bans(), key=lambda b: b["created_at"], reverse=True)
        if [row.key.value for row in table.ordered_rows] == [b["key"] for b in bans]:
            return  # unchanged: don't rebuild (keeps the cursor where the owner put it)
        selected = None
        if table.row_count:
            selected = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        table.clear()
        for b in bans:
            until = "until lifted" if b["until"] is None else ts(b["until"])
            kind = "manual" if b["manual"] else f"auto (strike {b['strikes']})"
            table.add_row(t(b["key"]), t(until), t(kind), t(b["reason"]), key=b["key"])
        if selected in [b["key"] for b in bans]:
            table.move_cursor(row=table.get_row_index(selected))

    def _update_pairing(self) -> None:
        info = self._q("#pairing-info", Static)
        qr_box = self._q("#pairing-qr", Static)
        window = self.state.pairing_window
        mine = self._pairing
        if mine is not None and (window is None or window.id != mine["window_id"]):
            # Our window closed: used, expired, cancelled or replaced (e.g. from the CLI).
            try:
                status = self.admin.pairing_status(mine["window_id"])
            except AdminError:
                status = {"state": "gone"}
            if status["state"] == "used" and status.get("device"):
                dev = status["device"]
                result = Text.assemble(("✓ Paired: ", "bold green"), t(dev["name"]), f"  from {dev['last_ip'] or '?'}")
            elif window is not None:
                result = Text("This window was replaced by another one (opened elsewhere, e.g. the CLI).", style="yellow")
            else:
                result = Text(f"Pairing window {status['state']}.", style="yellow")
            self._pairing = None
            self._pairing_result = result
            qr_box.update("")
            mine = None
        if mine is None:
            lines: list[Any] = [self._pairing_result] if self._pairing_result is not None else []
            if window is not None:
                left = int(window.expires_at - time.time())
                lines.append(Text(f"A pairing window opened elsewhere is open ({left}s left).", style="yellow"))
            else:
                lines.append(Text("Pairing is closed. Press P to open a window.", style="dim"))
            info.update(Group(*lines))
            return
        left = max(0, int(mine["expires_at"] - time.time()))
        parts: list[Any] = [Text(f"Pairing window open — {left // 60}:{left % 60:02d} left, one device only", style="bold")]
        if mine.get("warning"):
            parts.append(Text("⚠ " + mine["warning"], style="bold yellow"))
        if mine.get("code"):
            parts.append(Text.assemble("Code:  ", (mine["code"], "bold reverse"), f"   → type it at {self.admin.config.base_url}/pair"))
        if mine.get("link_url"):
            parts.append(Text.assemble("Link:  ", (mine["link_url"], "underline")))
        if mine.get("fingerprint"):
            parts.append(Text(f"Cert SHA-256: {format_fingerprint(mine['fingerprint'])}", style="dim"))
        if window is not None and window.attempts:
            parts.append(Text(f"Wrong code attempts: {window.attempts}/{window.max_attempts}", style="red"))
        info.update(Group(*parts))
        if mine.get("qr_url") and not qr_box.content:
            qr_box.update(Text(qr.render_text(mine["qr_url"], invert=False), no_wrap=True))

    # ----- settings -------------------------------------------------------------------

    def _fill_settings(self, only_unfocused: bool = False) -> None:
        """Show current values; with ``only_unfocused``, don't clobber the field being edited."""
        for key, value in self.admin.get_settings().items():
            field = self._q("#set-" + key.replace(".", "-"), Input)
            if only_unfocused and field.has_focus:
                continue
            field.value = str(value)

    # ----- helpers --------------------------------------------------------------------

    def say(self, message: str, **kwargs: Any) -> None:
        """A toast. Never markup: messages can contain device names and other client text."""
        self.notify(safe(message), markup=False, **kwargs)

    def _q(self, selector: str, expect_type: Any = None) -> Any:
        """Query the main screen, even while a dialog or detail screen is on top.

        (``App.query_one`` only searches the active screen.)
        """
        base = self.screen_stack[0]
        return base.query_one(selector, expect_type) if expect_type else base.query_one(selector)

    def _selected_device_id(self) -> str | None:
        table = self._q("#device-table", DataTable)
        if table.row_count == 0:
            return None
        try:
            return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:  # noqa: BLE001
            return None

    def _run_admin(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        try:
            result = fn(*args, **kwargs)
        except AdminError as exc:
            self.say(str(exc), severity="error")
            return None
        except Exception:  # noqa: BLE001 - a TUI bug must never take the server down
            log.exception("admin action failed in the TUI")
            self.say("That action failed unexpectedly (see the log on the dashboard).", severity="error")
            return None
        self.refresh_all()
        return result

    def _with_device(self, action: Callable[[dict[str, Any]], None]) -> None:
        device_id = self._selected_device_id()
        if device_id is None:
            self.say("Select a device first (Devices tab)", severity="warning")
            return
        device = self._run_admin(self.admin.show_device, device_id)
        if device is not None:
            action(device)

    # ----- global actions ---------------------------------------------------------------

    def _to_base(self) -> bool:
        """Close the detail screen/dialogs so tab changes happen where the owner can see them.

        Returns True if anything was closed.
        """
        popped = False
        while len(self.screen_stack) > 1:
            self.pop_screen()
            popped = True
        return popped

    def action_tab(self, tab: str) -> None:
        if self._to_base():
            # Switch once the base screen is active again, or the change is lost.
            self.call_after_refresh(self.action_tab, tab)
            return
        self._q(TabbedContent).active = tab
        self._focus_tab(tab)
        self.call_after_refresh(self._focus_tab, tab)  # again, after any focus restore

    def _focus_tab(self, tab: str) -> None:
        # Move focus into the shown tab: tables so their keys (r, t, s, k…) work, and
        # always *something* in the tab, because Textual switches back to whichever tab
        # holds the focused widget (e.g. after closing the detail screen).
        # Leave focus in the tab's own search box: a late TabActivated (e.g. the first
        # one after startup) must not undo "/".
        own_input = {"devices": "device-search", "audit": "audit-filter"}.get(tab)
        if own_input is not None and isinstance(self.focused, Input) and self.focused.id == own_input:
            return
        target = {
            "devices": "#device-table",
            "audit": "#audit-table",
            "pairing": "#pair-open",
            "bans": "#ban-table",
            "settings": "#set-server-public_url",
        }.get(tab)
        if target:
            self._q(target).focus()
        else:
            self.screen_stack[0].set_focus(None)

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        tab = event.pane.id or ""
        if tab == "audit":
            self._update_audit(force=True)
        self.refresh_all()  # draw the newly visible tab now
        self._focus_tab(tab)

    def action_pair(self) -> None:
        self.action_tab("pairing")
        result = self._run_admin(self.admin.open_pairing)
        if result is not None:
            self._pairing = result
            self._pairing_result = None
            self._q("#pairing-qr", Static).update("")
            self._update_pairing()

    def action_search(self) -> None:
        if self._to_base():
            self.call_after_refresh(self.action_search)  # once the main screen is back
            return
        tab = self._q(TabbedContent).active
        target = "#audit-filter" if tab == "audit" else "#device-search"
        if tab != "audit":
            self.action_tab("devices")
        # After the tab switch has been processed (it focuses the table).
        self.call_after_refresh(lambda: self._q(target, Input).focus())

    def action_lockdown(self) -> None:
        if isinstance(self.screen, ConfirmScreen):
            return  # Ctrl+L has priority; don't stack a second question on top of one
        if self.state.lockdown:
            self.push_screen(
                ConfirmScreen("Lift lockdown and accept traffic again?", danger=False),
                lambda ok: ok and self._run_admin(self.admin.set_lockdown, False),
            )
        else:
            self.push_screen(
                ConfirmScreen("LOCKDOWN: reject all traffic, cut every stream and close pairing?\nDevices are kept."),
                lambda ok: ok and self._run_admin(self.admin.set_lockdown, True),
            )

    def action_quit_gate(self) -> None:
        if isinstance(self.screen, ConfirmScreen):
            return

        def done(ok: bool | None) -> None:
            if ok:
                self._exit_requested = True
                self.quit_confirmed = True
                self.exit()

        self.push_screen(
            ConfirmScreen("Quit OllamaGate? The server stops and every device must pair again."), done
        )

    # ----- device actions ----------------------------------------------------------------

    def action_device_detail(self) -> None:
        from .detail import DeviceDetailScreen

        self._with_device(lambda d: self.push_screen(DeviceDetailScreen(d["id"])))

    def action_device_revoke(self) -> None:
        def ask(d: dict[str, Any]) -> None:
            self.push_screen(
                ConfirmScreen(f"Revoke {t(d['name']).plain}? It must pair again."),
                lambda ok: ok and self._run_admin(self.admin.revoke, d["id"]),
            )

        self._with_device(ask)

    def action_device_rotate(self) -> None:
        def ask(d: dict[str, Any]) -> None:
            def go(ok: bool | None) -> None:
                if not ok:
                    return
                result = self._run_admin(self.admin.rotate, d["id"])
                if result:
                    body = Text.assemble(
                        "New token (shown once — give it to the device, the old one no longer works):\n\n",
                        (result["token"], "bold"),
                    )
                    self.push_screen(MessageScreen("Token rotated", body))

            self.push_screen(ConfirmScreen(f"Issue a new token for {t(d['name']).plain}?", danger=False), go)

        self._with_device(ask)

    def action_device_suspend(self) -> None:
        def ask(d: dict[str, Any]) -> None:
            name = t(d["name"]).plain
            if d["status"] == "suspended":
                self.push_screen(
                    ConfirmScreen(f"Resume {name}?", danger=False),
                    lambda ok: ok and self._run_admin(self.admin.resume, d["id"]),
                )
            elif d["status"] == "active":
                self.push_screen(
                    ConfirmScreen(f"Suspend {name}? Its requests are cut until you resume it."),
                    lambda ok: ok and self._run_admin(self.admin.suspend, d["id"]),
                )
            else:
                self.say("Revoked devices can't be suspended", severity="warning")

        self._with_device(ask)

    def action_device_kick(self) -> None:
        def ask(d: dict[str, Any]) -> None:
            def go(ok: bool | None) -> None:
                result = self._run_admin(self.admin.kick, d["id"]) if ok else None
                if result is not None:
                    self.say(f"Terminated {result['streams_killed']} request(s)")

            self.push_screen(ConfirmScreen(f"End all active requests of {t(d['name']).plain}?"), go)

        self._with_device(ask)

    def action_device_rename(self) -> None:
        def ask(d: dict[str, Any]) -> None:
            self.push_screen(
                InputScreen("New name:", t(d["name"]).plain),
                lambda name: name is not None and self._run_admin(self.admin.rename, d["id"], name),
            )

        self._with_device(ask)

    def action_device_limits(self) -> None:
        from .detail import LimitsScreen

        self._with_device(lambda d: self.push_screen(LimitsScreen(d["id"])))

    def action_device_ban(self) -> None:
        def ask(d: dict[str, Any]) -> None:
            if not d["last_ip"]:
                self.say("This device has no known IP yet", severity="warning")
                return
            self.push_screen(
                ConfirmScreen(f"Ban {d['last_ip']} (last IP of {t(d['name']).plain}) until you lift it?"),
                lambda ok: ok and self._run_admin(self.admin.ban_device_ip, d["id"]),
            )

        self._with_device(ask)

    def action_unban(self) -> None:
        table = self._q("#ban-table", DataTable)
        if table.row_count == 0:
            return
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        self.push_screen(
            ConfirmScreen(f"Lift the ban on {key}?", danger=False),
            lambda ok: ok and self._run_admin(self.admin.remove_ban, key),
        )

    # ----- events -------------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "device-search":
            self._search = event.value
            self._update_devices()
        elif event.input.id == "audit-filter":
            self._audit_filter = event.value
            self._update_audit(force=True)

    def on_key(self, event: Any) -> None:
        if event.key == "escape" and isinstance(self.focused, Input) and self.focused.id in ("device-search", "audit-filter"):
            self.focused.value = ""
            other = "#device-table" if self.focused.id == "device-search" else "#audit-table"
            self._q(other).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id and event.input.id.startswith("set-"):
            self._save_setting(event.input.id.removeprefix("set-"))
        elif event.input.id == "device-search":
            self._q("#device-table").focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "pair-open":
            self.action_pair()
        elif bid == "pair-cancel":
            window_id = self._pairing["window_id"] if self._pairing else None
            if self._run_admin(self.admin.cancel_pairing, window_id) is not None and window_id is None:
                self.say("No pairing window of yours is open")
        elif bid == "ban-add":
            self.push_screen(
                InputScreen("IP address to ban (until lifted):", placeholder="203.0.113.7"),
                lambda ip: ip and self._run_admin(self.admin.add_ban, ip.strip()),
            )
        elif bid == "ban-remove":
            self.action_unban()
        elif bid.startswith("save-"):
            self._save_setting(bid.removeprefix("save-"))

    def _save_setting(self, slug: str) -> None:
        key = next(k for k in RUNTIME_SETTINGS if k.replace(".", "-") == slug)
        field = self._q("#set-" + slug, Input)
        if self._run_admin(self.admin.set_setting, key, field.value) is not None:
            self.say(f"{key} = {field.value} (until restart)")
        # Only reset the field that was saved; other fields may hold unsaved edits.
        field.value = str(self.admin.get_settings()[key])

    async def on_unmount(self) -> None:
        client = getattr(self, "_ollama_client", None)
        if client is not None:
            await client.aclose()

