"""Drive the admin TUI headlessly with Textual's pilot."""

from __future__ import annotations

import asyncio
import os

import pytest

from ollamagate.admin.service import Admin
from ollamagate.config import Config
from ollamagate.server import auth, pairing
from ollamagate.state import DeviceStatus, State
from textual.widgets import TabbedContent

from ollamagate.tui.app import GateTUI
from ollamagate.tui.widgets import ConfirmScreen

SHOTS = os.environ.get("OLLAMAGATE_TUI_SHOTS")  # set to a directory to save SVG screenshots


def make_admin() -> Admin:
    cfg = Config()
    cfg.server.public_url = "https://gate.example:8443"
    return Admin(State(), cfg, "ab" * 32)


def add_device(state: State, name: str = "phone", ua: str = "Mozilla/5.0 (iPhone) Safari/605") -> str:
    token = auth.new_device_token()
    d = state.add_device(name=name, token_hash=auth.hash_token(token), token_prefix=auth.display_prefix(token), paired_via="qr")
    state.touch_device(d, "203.0.113.7", 50000, ua)
    return d.id


async def shot(app: GateTUI, name: str) -> None:
    if SHOTS:
        app.save_screenshot(filename=f"{name}.svg", path=SHOTS)


def plain(app: GateTUI, selector: str) -> str:
    from rich.console import Console

    console = Console(width=200, record=True, file=open(os.devnull, "w"))
    console.print(app.query_one(selector).content)
    return console.export_text()


async def test_dashboard_and_devices_render():
    admin = make_admin()
    add_device(admin.state, "Anna's phone")
    app = GateTUI(admin, warnings=["Ollama port 11434 is reachable on 192.168.1.5"])
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        text = plain(app, "#status")
        assert "https://gate.example:8443" in text and "1 active / 1 total" in text
        assert "reachable on 192.168.1.5" in plain(app, "#warnings")
        await shot(app, "dashboard")
        await pilot.press("2")
        table = app.query_one("#device-table")
        assert table.row_count == 1
        row = table.get_row_at(0)
        assert row[1].plain == "Anna's phone" and row[4].plain == "iPhone · Safari"
        await shot(app, "devices")


async def test_pairing_flow_shows_code_qr_and_success():
    admin = make_admin()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 60)) as pilot:
        await pilot.press("p")
        await pilot.pause()
        assert app._pairing is not None
        code = app._pairing["code"]
        info = plain(app, "#pairing-info")
        assert code in info and "/pair#t=" in info
        assert "█" in plain(app, "#pairing-qr")
        await shot(app, "pairing")
        result = pairing.claim(
            admin.state, secret=code, kind="code", device_name="Tablet", ip="198.51.100.4", user_agent="curl/8"
        )
        assert result.error is None
        await pilot.pause(0.7)
        assert "Paired" in plain(app, "#pairing-info") and "Tablet" in plain(app, "#pairing-info")
        assert app._pairing is None


async def test_pairing_replaced_elsewhere_is_detected():
    admin = make_admin()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 60)) as pilot:
        await pilot.press("p")
        admin.open_pairing()  # e.g. `ollamagate pair` from another terminal
        await pilot.pause(1.2)
        assert "replaced" in plain(app, "#pairing-info")


async def test_revoke_requires_confirmation():
    admin = make_admin()
    device_id = add_device(admin.state)
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("2")
        app.query_one("#device-table").focus()
        await pilot.press("r")
        await pilot.pause()
        await shot(app, "confirm-revoke")
        await pilot.press("enter")  # focus starts on "No"
        await pilot.pause()
        assert admin.state.get_device(device_id).status is DeviceStatus.ACTIVE
        await pilot.press("r")
        await pilot.press("y")
        await pilot.pause()
        assert admin.state.get_device(device_id).status is DeviceStatus.REVOKED
        assert any(e.event == "admin_revoke" for e in admin.state.audit_log)


async def test_rename_suspend_rotate():
    admin = make_admin()
    device_id = add_device(admin.state)
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("2")
        app.query_one("#device-table").focus()
        await pilot.press("n")
        await pilot.pause()
        inp = app.screen.query_one("Input")
        inp.value = "Work laptop"
        await pilot.press("enter")
        await pilot.pause()
        assert admin.state.get_device(device_id).name == "Work laptop"
        await pilot.press("s", "y")
        await pilot.pause()
        assert admin.state.get_device(device_id).status is DeviceStatus.SUSPENDED
        await pilot.press("s", "y")
        await pilot.pause()
        assert admin.state.get_device(device_id).status is DeviceStatus.ACTIVE
        old_hash = admin.state.get_device(device_id).token_hash
        await pilot.press("t", "y")
        await pilot.pause()
        assert admin.state.get_device(device_id).token_hash != old_hash
        assert "og_dev_" in plain(app.screen, "Static.selectable")
        await shot(app, "rotated")


async def test_detail_screen_and_limits():
    admin = make_admin()
    device_id = add_device(admin.state)
    app = GateTUI(admin)
    async with app.run_test(size=(140, 50)) as pilot:
        await pilot.press("2")
        app.query_one("#device-table").focus()
        await pilot.press("enter")
        await pilot.pause()
        text = plain(app.screen, "#detail")
        assert device_id in text and "203.0.113.7" in text and "iPhone" in text
        await shot(app, "detail")
        await pilot.pause(1.3)  # timers keep running while the detail screen is on top
        await pilot.press("s", "y")  # actions work from the detail screen
        await pilot.pause()
        assert admin.state.get_device(device_id).status is DeviceStatus.SUSPENDED
        await pilot.press("s", "y")
        await pilot.pause()
        await pilot.press("l")
        await pilot.pause()
        app.screen.query_one("#mm").value = True
        await pilot.click("#apply")
        await pilot.pause()
        assert admin.state.get_device(device_id).allow_model_management is True


async def test_markup_and_escapes_in_names_are_inert():
    admin = make_admin()
    add_device(admin.state, name="[bold red]pwn[/]", ua="\x1b]52;c;SGVsbG8=\x07evil")
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("2")
        await pilot.pause()
        row = app.query_one("#device-table").get_row_at(0)
        assert row[1].plain == "[bold red]pwn[/]"  # shown literally, not as markup
        assert "\x1b" not in row[4].plain


async def test_lockdown_toggle():
    admin = make_admin()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("ctrl+l", "y")
        await pilot.pause()
        assert admin.state.lockdown is True
        assert "LOCKDOWN" in plain(app, "#lockdown-banner")
        await shot(app, "lockdown")
        await pilot.press("p")  # pairing refused while locked down
        await pilot.pause()
        assert admin.state.pairing_window is None
        await pilot.press("ctrl+l", "y")
        await pilot.pause()
        assert admin.state.lockdown is False


async def test_search_filters_devices():
    admin = make_admin()
    add_device(admin.state, "Anna's phone")
    add_device(admin.state, "Office PC", ua="python-httpx/0.28")
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("/")
        await pilot.press(*"office")
        await pilot.pause()
        table = app.query_one("#device-table")
        assert table.row_count == 1 and table.get_row_at(0)[1].plain == "Office PC"
        await pilot.press("escape")
        await pilot.pause()
        assert table.row_count == 2


async def test_audit_tab_and_filter():
    admin = make_admin()
    admin.state.audit("auth_failed", ip="203.0.113.99", reason="invalid", path="/api/tags")
    admin.open_pairing()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("4")
        table = app.query_one("#audit-table")
        assert table.row_count == 2
        app.query_one("#audit-filter").value = "auth_failed"
        await pilot.pause()
        assert table.row_count == 1
        await shot(app, "audit")


async def test_settings_tab_changes_runtime_setting():
    admin = make_admin()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("5")
        app.query_one("#set-pairing-ttl_seconds").value = "120"
        await pilot.click("#save-pairing-ttl_seconds")
        await pilot.pause()
        assert admin.config.pairing.ttl_seconds == 120
        app.query_one("#set-pairing-ttl_seconds").value = "5"  # invalid
        await pilot.click("#save-pairing-ttl_seconds")
        await pilot.pause()
        assert admin.config.pairing.ttl_seconds == 120
        await shot(app, "settings")


async def test_quit_asks_first():
    admin = make_admin()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("q")
        await pilot.press("n")
        await pilot.pause()
        assert app.is_running
        await pilot.press("q", "y")
        await pilot.pause()
    assert not app.is_running


async def test_tui_exits_when_server_stops():
    admin = make_admin()
    loop = asyncio.get_running_loop()
    server = loop.create_future()
    app = GateTUI(admin, services=server)
    async with app.run_test(size=(140, 45)) as pilot:
        server.set_result(None)
        await pilot.pause(0.3)
    assert not app.is_running
    assert server.done() and not server.cancelled()


@pytest.mark.parametrize("n", [3])
async def test_live_update_on_new_device(n):
    admin = make_admin()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("2")
        for i in range(n):
            add_device(admin.state, f"dev{i}")
        await pilot.pause(0.7)
        assert app.query_one("#device-table").row_count == n


# ----- Phase 3 council regressions -------------------------------------------------------


async def test_markup_in_device_name_cannot_crash_toasts():
    """A device named "[/x]" used to raise MarkupError in notify() and kill the server."""
    admin = make_admin()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45), notifications=True) as pilot:
        s = admin.open_pairing()
        pairing.claim(admin.state, secret=s["code"], kind="code", device_name="[/x] [b]x", ip="1.2.3.4", user_agent="")
        await pilot.pause(1.3)
        assert app.is_running
        assert any("[/x]" in n.message for n in app._notifications)


async def test_toasts_keep_working_when_audit_log_is_full():
    admin = Admin(State(audit_size=20), Config(), None)
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45), notifications=True) as pilot:
        for i in range(50):
            admin.state.audit("auth_failed", ip=f"203.0.113.{i}")
        await pilot.pause(1.2)
        device_id = add_device(admin.state, "late")
        admin.state.audit("pairing_succeeded", device_id=device_id)
        await pilot.pause(1.3)
        assert any("late" in n.message for n in app._notifications)


async def test_ctrl_q_asks_first():
    admin = make_admin()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("ctrl+q")
        await pilot.pause()
        assert app.is_running and isinstance(app.screen, ConfirmScreen)
        await pilot.press("n")


async def test_pair_from_detail_screen_shows_pairing_tab():
    admin = make_admin()
    add_device(admin.state)
    app = GateTUI(admin)
    async with app.run_test(size=(140, 50)) as pilot:
        await pilot.press("2", "enter")
        await pilot.pause()
        await pilot.press("p")
        await pilot.pause()
        assert len(app.screen_stack) == 1
        assert app._q(TabbedContent).active == "pairing"


async def test_ctrl_l_does_not_stack_dialogs():
    admin = make_admin()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("ctrl+l", "ctrl+l")
        await pilot.pause()
        assert len(app.screen_stack) == 2


async def test_audit_cursor_stays_on_entry():
    admin = make_admin()
    for i in range(10):
        admin.state.audit("admin_test", n=i)
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("4")
        table = app._q("#audit-table")
        table.move_cursor(row=5)
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        admin.state.audit("admin_test", n=99)
        await pilot.pause(1.3)
        assert table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value == key


async def test_device_rows_update_in_place():
    admin = make_admin()
    device_id = add_device(admin.state)
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("2")
        admin.state.add_usage(device_id, requests=7)
        admin.state._changed()
        await pilot.pause(1.3)
        assert app._q("#device-table").get_row_at(0)[8].plain == "7"


async def test_settings_tab_reflects_cli_changes():
    admin = make_admin()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("5")
        admin.set_setting("pairing.max_attempts", 3)  # e.g. via `ollamagate settings set`
        await pilot.pause(1.3)
        assert app._q("#set-pairing-max_attempts").value == "3"


async def test_unexpected_error_in_action_does_not_kill_tui(monkeypatch):
    admin = make_admin()
    add_device(admin.state)
    app = GateTUI(admin)
    monkeypatch.setattr(admin, "kick", lambda ref: 1 / 0)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("2", "k", "y")
        await pilot.pause()
        assert app.is_running
