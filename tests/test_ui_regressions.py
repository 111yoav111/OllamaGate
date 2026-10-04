"""Regression checks for the admin TUI and the static browser pages."""

from __future__ import annotations

import re
from importlib import resources

import pytest

from ollamagate.admin.service import Admin
from ollamagate.config import Config
from ollamagate.state import State
from ollamagate.tui.app import GateTUI


def make_admin() -> Admin:
    cfg = Config()
    cfg.server.public_url = "https://gate.example:8443"
    return Admin(State(), cfg, "ab" * 32)


def _web(name: str) -> str:
    return resources.files("ollamagate.web").joinpath(name).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", ["app.html", "pair.html"])
def test_pages_comply_with_strict_csp(name):
    # The pages are served with script-src/style-src 'self' and no 'unsafe-inline'.
    html = _web(name)
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "inline <script>"
    assert "<style" not in html and " style=" not in html, "inline style"
    assert not re.search(r"\son[a-z]+\s*=", html), "inline event handler"
    assert not re.search(r"(src|href)=\"(https?:)?//", html), "external resource"


@pytest.mark.parametrize("name", ["app.js", "pair.js"])
def test_scripts_never_build_html_from_strings(name):
    js = _web(name)
    for sink in (".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in js, sink


async def test_ban_table_refreshes_when_a_ban_changes_in_place():
    admin = make_admin()
    admin.add_ban("198.51.100.9", seconds=3600, reason="first")
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.press("5")
        await pilot.pause()
        table = app._q("#ban-table")
        assert table.get_row_at(0)[3].plain == "first"
        admin.add_ban("198.51.100.9", reason="second")  # same key, now until lifted
        await pilot.pause(1.5)
        row = table.get_row_at(0)
        assert table.row_count == 1 and row[3].plain == "second" and row[1].plain == "until lifted"


async def test_new_event_toasts_are_capped_and_in_order():
    admin = make_admin()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 45), notifications=True) as pilot:
        await pilot.pause()
        for i in range(8):
            admin.state.audit("ban_auto", ip=f"198.51.100.{i}", reason="failed logins", strikes=1, until=0)
        await pilot.pause(1.5)
        messages = [n.message for n in app._notifications if "Auto" in (n.title or "") or "Banned" in n.message]
        assert [m.rsplit(".", 1)[1] for m in messages] == ["3", "4", "5", "6", "7"]
