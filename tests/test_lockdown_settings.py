"""Lockdown, runtime settings, usage rollup and dashboard data."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ollamagate.__main__ import cli
from ollamagate.admin.service import Admin
from ollamagate.config import Config
from ollamagate.server import pairing
from ollamagate.state import State
from ollamagate.uaparse import summarize

from .test_admin import admin_gate  # noqa: F401 - fixture
from .test_proxy_stream import bearer, wait_for


def test_lockdown_rejects_everything_but_keeps_devices(admin_gate, client):  # noqa: F811
    gate, _ = admin_gate
    gate.call(lambda: pairing.open_window(gate.state, base_url=gate.url, fingerprint=None, ttl_seconds=60, max_attempts=5))
    r = CliRunner().invoke(cli, ["lockdown", "on"])
    assert r.exit_code == 0 and "LOCKDOWN on" in r.output
    assert client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 503
    assert client.get(gate.url + "/api/tags").status_code == 503  # before auth
    assert client.get(gate.url + "/me", headers=bearer(gate.token)).status_code == 503
    assert client.get(gate.url + "/pair").status_code == 404
    assert gate.state.pairing_window is None
    assert gate.state.get_device(gate.device.id) is not None
    assert client.get(gate.url + "/healthz").status_code == 503  # not even "alive"
    r = CliRunner().invoke(cli, ["pair", "--no-wait"])
    assert r.exit_code == 1 and "lockdown" in r.output
    assert CliRunner().invoke(cli, ["lockdown", "off"]).exit_code == 0
    assert client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 200


def test_lockdown_cuts_active_stream(gate, client):
    admin = Admin(gate.state, gate.app.state.config, None)
    with client.stream(
        "POST", gate.url + "/api/chat", headers=bearer(gate.token),
        json={"model": "m", "fake_chunks": 400, "fake_delay": 0.05},
    ) as r:
        lines = r.iter_lines()
        next(lines)
        gate.call(lambda: admin.set_lockdown(True))
        rest = [line for line in lines if line]
    assert json.loads(rest[-1]) == {"error": "stream terminated: lockdown"}


def test_settings_cli(admin_gate):  # noqa: F811
    gate, _ = admin_gate
    r = CliRunner().invoke(cli, ["settings", "list"])
    assert "pairing.ttl_seconds" in r.output
    assert CliRunner().invoke(cli, ["settings", "set", "pairing.ttl_seconds", "90"]).exit_code == 0
    assert gate.app.state.config.pairing.ttl_seconds == 90
    r = CliRunner().invoke(cli, ["settings", "set", "tls.mode", "off"])
    assert r.exit_code == 1 and "not changeable" in r.output
    r = CliRunner().invoke(cli, ["settings", "set", "limits.max_concurrent", "0"])
    assert r.exit_code == 1
    assert CliRunner().invoke(cli, ["settings", "set", "server.public_url", "https://pc.tailnet.ts.net:8443"]).exit_code == 0
    assert gate.app.state.config.base_url == "https://pc.tailnet.ts.net:8443"


def test_settings_type_checks():
    admin = Admin(State(), Config(), None)
    import pytest

    from ollamagate.admin.ipc import AdminError

    for key, value in [("pairing.ttl_seconds", True), ("pairing.ttl_seconds", "abc"), ("limits.allow_model_management", "maybe")]:
        with pytest.raises(AdminError):
            admin.set_setting(key, value)
    assert admin.set_setting("limits.allow_model_management", "on")["limits.allow_model_management"] is True


def test_usage_rollup_and_model_capture(gate, client):
    for _ in range(3):
        client.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "llama3:8b", "stream": False})
    assert wait_for(lambda: gate.state.usage_today(gate.device.id).requests == 3)
    assert gate.state.request_log[-1].model == "llama3:8b"
    admin = Admin(gate.state, gate.app.state.config, None)
    view = admin.show_device(gate.device.id)
    assert view["requests_today"] == 3 and view["requests_total"] == 3
    dash = admin.dashboard()
    assert dash["requests_today"] == 3 and dash["requests_last_minute"] == 3


def test_current_model_shown_while_streaming(gate, client):
    admin = Admin(gate.state, gate.app.state.config, None)
    with client.stream(
        "POST", gate.url + "/api/chat", headers=bearer(gate.token),
        json={"model": "qwen2:7b", "fake_chunks": 50, "fake_delay": 0.05},
    ) as r:
        lines = r.iter_lines()
        next(lines)
        view = gate.call(lambda: admin.show_device(gate.device.id))
    assert view["current_models"] == ["qwen2:7b"] and view["activity"] == "streaming"


def test_model_name_is_escaped(gate, client):
    client.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "\x1b[31mevil", "stream": False})
    assert wait_for(lambda: len(gate.state.request_log) == 1)
    assert "\x1b" not in gate.state.request_log[-1].model


def test_ua_summaries():
    assert summarize("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit Safari/604.1") == "iPhone · Safari"
    assert summarize("Mozilla/5.0 (Linux; Android 14) Chrome/120 Mobile Safari/537") == "Android · Chrome"
    assert summarize("Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537 Edg/120") == "Windows · Edge"
    assert summarize("python-httpx/0.28.1") == "Python"
    assert summarize("") == "-"


# ----- regressions -------------------------------------------------------------------


def test_public_url_validation():
    import pytest

    from ollamagate.config import ConfigError, validate_public_url

    validate_public_url("https://pc.tailnet.ts.net:8443")
    validate_public_url("https://gate.example/")
    validate_public_url("http://127.0.0.1:8443")
    for bad in [
        "javascript:alert(1)",
        "http://evil.example",
        "https://gate.example/path",
        "https://gate.example?x=1",
        "https://gate.example#frag",
        "https://user:pw@gate.example",
        "https://gate example",
        "https://gate.example\n",
        "https://gate.example:99999",
        "ftp://gate.example",
    ]:
        with pytest.raises(ConfigError):
            validate_public_url(bad)
    admin = Admin(State(), Config(), None)
    from ollamagate.admin.ipc import AdminError

    with pytest.raises(AdminError):
        admin.set_setting("server.public_url", "javascript:alert(1)")


def test_huge_model_name_is_cheap(gate, client):
    import time as _time

    from ollamagate.server.app import requested_model

    body = json.dumps({"model": "a" * 5_000_000}).encode()
    start = _time.perf_counter()
    assert len(requested_model(body)) <= 101
    assert _time.perf_counter() - start < 0.5


def test_probe_tolerates_garbage():
    import asyncio

    import httpx

    from ollamagate.ollama_status import probe

    def handler(request):
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.9"})
        return httpx.Response(200, json={"models": [{"name": "x", "size": "huge", "size_vram": True}, "junk"]})

    async def run():
        async with httpx.AsyncClient(base_url="http://o", transport=httpx.MockTransport(handler)) as c:
            return await probe(c)

    status = asyncio.run(run())
    assert status.reachable and status.models[0].size == 0


def test_usage_reads_do_not_create_rows():
    state = State()
    admin = Admin(state, Config(), None)
    from ollamagate.server import auth

    token = auth.new_device_token()
    d = state.add_device(name="x", token_hash=auth.hash_token(token), token_prefix="p", paired_via="t")
    admin.show_device(d.id)
    admin.dashboard()
    assert state.usage == {}


def test_status_cli(admin_gate):  # noqa: F811
    r = CliRunner().invoke(cli, ["status"])
    assert r.exit_code == 0 and "Devices:" in r.output and "Lockdown:" in r.output
