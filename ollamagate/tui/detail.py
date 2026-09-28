"""Device detail and limits screens."""

from __future__ import annotations

from typing import Any

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Header, Input, Label, Select, Static, Switch

from ..admin.errors import AdminError
from .widgets import ACTIVITY_DOT, InputScreen, ago, t, ts


class DeviceDetailScreen(Screen[None]):
    """Everything known about one device, with the same action keys as the table."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("r", "act('revoke')", "Revoke"),
        Binding("t", "act('rotate')", "Rotate token"),
        Binding("s", "act('suspend')", "Suspend/resume"),
        Binding("k", "act('kick')", "Kick"),
        Binding("n", "act('rename')", "Rename"),
        Binding("l", "act('limits')", "Limits"),
        Binding("o", "notes", "Notes"),
    ]

    def __init__(self, device_id: str) -> None:
        super().__init__()
        self.device_id = device_id
        self._seen = -1

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll():
            yield Static(id="detail")
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(0.5, self._refresh_if_changed)
        self._render_detail()

    def _refresh_if_changed(self) -> None:
        if self.app.state.version != self._seen:  # type: ignore[attr-defined]
            self._render_detail()

    def _render_detail(self) -> None:
        app: Any = self.app
        self._seen = app.state.version
        try:
            d = app.admin.show_device(self.device_id)
        except AdminError:
            self.query_one("#detail", Static).update(Text("Device no longer exists.", style="red"))
            return
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold", min_width=18)
        grid.add_column()
        status = Text.assemble(ACTIVITY_DOT.get(d["activity"], Text("?")), " ", d["status"], f" ({d['activity']})")
        expires = ts(d["token_expires_at"]) if d["token_expires_at"] else "never"
        rows: list[tuple[str, Any]] = [
            ("Name", t(d["name"])),
            ("Device ID", t(d["id"])),
            ("Status", status),
            ("Paired via", t(f"{d['paired_via']} at {ts(d['paired_at'])}")),
            ("Last seen", t(f"{ago(d['last_seen'])} ({ts(d['last_seen'])})")),
            ("Current IP", t(f"{d['last_ip'] or '-'}:{d['last_port'] or '-'}")),
            ("Client", t(d["client"])),
            ("User agent", t(d["user_agent"])),
            ("Active now", t(", ".join(d["current_models"]) or f"{d['active_streams']} stream(s)")),
            ("Requests", t(f"{d['requests_today']} today · {d['requests_month']} this month · {d['requests_total']} total")),
            ("Tokens", t(f"{d['tokens_today']} today" if d["tokens_today"] else "- (counted from Phase 4)")),
            ("Token", t(d["token_prefix"])),
            ("Token expires", t(expires)),
            ("Token rotated", t(ts(d["token_rotated_at"]))),
            ("Model management", t("allowed" if d["allow_model_management"] else "blocked")),
            ("Notes", t(d["notes"])),
        ]
        for label, value in rows:
            grid.add_row(label, value)
        ips = Table("IP", "First seen", "Last seen", "Requests", title="IP history", box=None, header_style="bold")
        for h in reversed(d["ip_history"]):
            ips.add_row(t(h["ip"]), ts(h["first_seen"]), ts(h["last_seen"]), str(h["count"]))
        self.query_one("#detail", Static).update(Group(grid, Text(""), ips))

    def action_act(self, name: str) -> None:
        app: Any = self.app
        # Reuse the app's actions; they operate on the table's selected row.
        table = app._q("#device-table")
        try:
            table.move_cursor(row=table.get_row_index(self.device_id))
        except Exception:  # noqa: BLE001 - filtered out of the table; clear the search
            app._search = ""
            app._update_devices()
            table.move_cursor(row=table.get_row_index(self.device_id))
        getattr(app, f"action_device_{name}")()

    def action_notes(self) -> None:
        app: Any = self.app
        d = app.admin.show_device(self.device_id)
        self.app.push_screen(
            InputScreen("Notes:", d["notes"]),
            lambda notes: notes is not None and app._run_admin(app.admin.set_notes, self.device_id, notes),
        )


class LimitsScreen(ModalScreen[None]):
    """Per-device limits editable today: token expiry and model management.

    Token/rate quotas, model allowlists etc. are added here in Phase 4.
    """

    BINDINGS = [Binding("escape", "close", "Close")]
    EXPIRY_CHOICES = [("Never", "never"), ("1 day", "1d"), ("7 days", "7d"), ("30 days", "30d"), ("Custom (seconds)", "custom")]

    def __init__(self, device_id: str) -> None:
        super().__init__()
        self.device_id = device_id

    def compose(self) -> ComposeResult:
        app: Any = self.app
        d = app.admin.show_device(self.device_id)
        with Vertical(classes="dialog wide"):
            yield Label(Text.assemble("Limits for ", t(d["name"]), style="bold"))
            with Horizontal(classes="setting"):
                yield Label("Model management (pull/push/delete…)", classes="setting-key")
                yield Switch(value=d["allow_model_management"], id="mm")
            with Horizontal(classes="setting"):
                yield Label("Token expiry (from now)", classes="setting-key")
                yield Select(self.EXPIRY_CHOICES, prompt="unchanged", id="expiry")
                yield Input(placeholder="seconds", id="expiry-custom", disabled=True)
            yield Static(Text("Quotas, rate limits and model allowlists arrive in Phase 4.", style="dim"))
            with Horizontal(classes="buttons"):
                yield Button("Apply", id="apply", variant="primary")
                yield Button("Close", id="close")

    def on_select_changed(self, event: Select.Changed) -> None:
        self.query_one("#expiry-custom", Input).disabled = event.value != "custom"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            self.dismiss(None)
            return
        app: Any = self.app
        allowed = self.query_one("#mm", Switch).value
        ok = app._run_admin(app.admin.set_model_management, self.device_id, allowed) is not None
        choice = self.query_one("#expiry", Select).value
        if ok and choice not in (Select.BLANK, None):
            value: Any = choice
            if choice == "custom":
                raw = self.query_one("#expiry-custom", Input).value.strip()
                value = int(raw) if raw.isascii() and raw.isdigit() else raw
            ok = app._run_admin(app.admin.set_expiry, self.device_id, value) is not None
        if ok:
            app.notify("Limits updated")
            self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)
