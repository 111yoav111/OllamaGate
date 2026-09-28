"""The admin TUI.

It runs in the same process and on the same event loop as the proxy, and acts
only through ``Admin`` - the same audited code path the CLI uses. It is never
reachable over the network.

Live updates: the screen polls ``state.version`` twice a second and redraws
only when something changed, so a flood of requests can't make it spin.
"""

from __future__ import annotations

import asyncio
import time
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
from ..admin.errors import AdminError
from ..admin.service import RUNTIME_SETTINGS, Admin
from ..ollama_status import OllamaStatus, human_bytes, probe
from ..server.tls import format_fingerprint
from .widgets import ACTIVITY_DOT, ConfirmScreen, InputScreen, MessageScreen, ago, duration, t, ts

REFRESH_INTERVAL = 0.5
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


class GateTUI(App[None]):
    TITLE = "OllamaGate"
    CSS_PATH = "gate.tcss"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [
        Binding("p", "pair", "Pair"),
        Binding("/", "search", "Search"),
        Binding("ctrl+l", "lockdown", "LOCKDOWN", priority=True),
        Binding("q", "quit_gate", "Quit"),
        Binding("1", "tab('dashboard')", "Dashboard", show=False),
        Binding("2", "tab('devices')", "Devices", show=False),
        Binding("3", "tab('pairing')", "Pairing", show=False),
        Binding("4", "tab('audit')", "Audit", show=False),
        Binding("5", "tab('settings')", "Settings", show=False),
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
        self._last_audit_len = 0
        self._search = ""
        self._audit_filter = ""
        # Plaintext pairing secrets live only here, only while the window is open.
        self._pairing: dict[str, Any] | None = None
        self._pairing_result: Text | None = None  # outcome of the last window we opened
        self._exit_requested = False

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
            with TabPane("Settings", id="settings"):
                with VerticalScroll():
                    yield Static(
                        Text("Runtime changes last until restart; edit config.toml to keep them.", style="dim")
                    )
                    for key in RUNTIME_SETTINGS:
                        with Horizontal(classes="setting"):
                            yield Label(key, classes="setting-key")
                            yield Input(id="set-" + key.replace(".", "-"), classes="setting-value")
                            yield Button("Save", id="save-" + key.replace(".", "-"))
        yield Footer()

    def on_mount(self) -> None:
        devices = self._q("#device-table", DataTable)
        devices.add_columns("", "Name", "ID", "IP", "Client", "Via", "Last seen", "Now", "Req today")
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
        self._seen_version = self.state.version
        self._update_dashboard()
        self._update_devices()
        self._update_audit()
        self._update_pairing()
        self._notify_new_events()

    async def poll_ollama(self) -> None:
        self.ollama = await probe(self._ollama_client)
        if self._is_live():
            self._update_dashboard()

    def _notify_new_events(self) -> None:
        """Toasts for events the owner should notice right away."""
        entries = list(self.state.audit_log)
        new = entries[self._last_audit_len :] if len(entries) >= self._last_audit_len else entries[-5:]
        self._last_audit_len = len(entries)
        for e in new[-5:]:
            name = self._device_name(e.device_id)
            if e.event == "pairing_succeeded":
                self.notify(f"New device paired: {name}", title="Pairing", timeout=8)
            elif e.event == "device_new_ip":
                self.notify(f"{name} connected from a new IP: {e.ip}", title="New IP", severity="warning", timeout=8)
            elif e.event == "pairing_destroyed":
                self.notify("Pairing window destroyed after too many wrong attempts", severity="error")

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
            ("Tokens today", f"{d['tokens_today']}" if d["tokens_today"] else "- (counted from Phase 4)"),
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
        selected = self._selected_device_id()
        table.clear()
        needle = self._search.lower()
        for d in sorted(self.admin.list_devices(), key=lambda v: v["paired_at"]):
            haystack = " ".join(str(d[k] or "") for k in ("name", "id", "last_ip", "client", "user_agent")).lower()
            if needle and needle not in haystack:
                continue
            now = ", ".join(d["current_models"]) or (f"{d['active_streams']} stream(s)" if d["active_streams"] else "")
            table.add_row(
                ACTIVITY_DOT.get(d["activity"], Text("?")),
                t(d["name"]),
                t(d["id"][:8]),
                t(d["last_ip"]),
                t(d["client"]),
                t(d["paired_via"]),
                t(ago(d["last_seen"])),
                t(now),
                t(d["requests_today"]),
                key=d["id"],
            )
        if selected is not None:
            try:
                table.move_cursor(row=table.get_row_index(selected))
            except Exception:  # noqa: BLE001 - the device is gone or filtered out
                pass

    def _update_audit(self) -> None:
        table = self._q("#audit-table", DataTable)
        table.clear()
        needle = self._audit_filter.lower()
        for e in reversed(list(self.state.audit_log)[-1000:]):
            detail = " ".join(f"{k}={v}" for k, v in e.detail.items())
            if needle and needle not in f"{e.event} {e.ip} {e.device_id} {detail}".lower():
                continue
            style = "red" if e.event in ("auth_failed", "pairing_failed", "pairing_destroyed") or "lockdown" in e.event else ""
            table.add_row(t(ts(e.ts)), t(e.event, style), t(e.ip), t((e.device_id or "")[:8]), t(detail))

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

    def _fill_settings(self) -> None:
        for key, value in self.admin.get_settings().items():
            self._q("#set-" + key.replace(".", "-"), Input).value = str(value)

    # ----- helpers --------------------------------------------------------------------

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
            self.notify(str(exc), severity="error")
            return None
        self.refresh_all()
        return result

    def _with_device(self, action: Callable[[dict[str, Any]], None]) -> None:
        device_id = self._selected_device_id()
        if device_id is None:
            self.notify("Select a device first (Devices tab)", severity="warning")
            return
        device = self._run_admin(self.admin.show_device, device_id)
        if device is not None:
            action(device)

    # ----- global actions ---------------------------------------------------------------

    def action_tab(self, tab: str) -> None:
        self._q(TabbedContent).active = tab
        self._focus_tab(tab)

    def _focus_tab(self, tab: str) -> None:
        # Focus the table so its action keys (r, t, s, k…) work and show in the footer.
        target = {"devices": "#device-table", "audit": "#audit-table"}.get(tab)
        if target:
            self._q(target).focus()

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        self._focus_tab(event.pane.id or "")

    def action_pair(self) -> None:
        self.action_tab("pairing")
        result = self._run_admin(self.admin.open_pairing)
        if result is not None:
            self._pairing = result
            self._pairing_result = None
            self._q("#pairing-qr", Static).update("")
            self._update_pairing()

    def action_search(self) -> None:
        tab = self._q(TabbedContent).active
        target = "#audit-filter" if tab == "audit" else "#device-search"
        if tab != "audit":
            self.action_tab("devices")
        # After the tab switch has been processed (it focuses the table).
        self.call_after_refresh(lambda: self._q(target, Input).focus())

    def action_lockdown(self) -> None:
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
        def done(ok: bool | None) -> None:
            if ok:
                self._exit_requested = True
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
        def go(d: dict[str, Any]) -> None:
            if d["status"] == "suspended":
                self._run_admin(self.admin.resume, d["id"])
            elif d["status"] == "active":
                self._run_admin(self.admin.suspend, d["id"])
            else:
                self.notify("Revoked devices can't be suspended", severity="warning")

        self._with_device(go)

    def action_device_kick(self) -> None:
        def go(d: dict[str, Any]) -> None:
            result = self._run_admin(self.admin.kick, d["id"])
            if result is not None:
                self.notify(f"Terminated {result['streams_killed']} request(s)")

        self._with_device(go)

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
        self.notify("IP bans arrive in Phase 4 (policy & auto-bans).", severity="warning")

    # ----- events -------------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "device-search":
            self._search = event.value
            self._update_devices()
        elif event.input.id == "audit-filter":
            self._audit_filter = event.value
            self._update_audit()

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
                self.notify("No pairing window of yours is open")
        elif bid.startswith("save-"):
            self._save_setting(bid.removeprefix("save-"))

    def _save_setting(self, slug: str) -> None:
        key = next(k for k in RUNTIME_SETTINGS if k.replace(".", "-") == slug)
        value = self._q("#set-" + slug, Input).value
        if self._run_admin(self.admin.set_setting, key, value) is not None:
            self.notify(f"{key} = {value} (until restart)")
        self._fill_settings()

    async def on_unmount(self) -> None:
        client = getattr(self, "_ollama_client", None)
        if client is not None:
            await client.aclose()

