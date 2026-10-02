"""Hardening regressions: escaping, the admin channel, pairing and device edge cases."""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
import time

import pytest
from typer.testing import CliRunner

from ollamagate.__main__ import cli
from ollamagate.admin import ipc
from ollamagate.admin.ipc import AdminError
from ollamagate.admin.service import Admin
from ollamagate.config import Config
from ollamagate.ratelimit import client_key
from ollamagate.server import auth, pairing
from ollamagate.state import DeviceStatus, State
from ollamagate.textsafe import safe_text

from .test_admin import admin_gate  # noqa: F401 - fixture
from .test_proxy_stream import bearer

ESC = "\x1b]52;c;SGVsbG8=\x07\x1b[31m"


# ----- terminal escape injection ----------------------------------------------------


def test_safe_text_escapes_controls():
    assert safe_text("a\x1b[31mb\x07‮") == "a\\x1b[31mb\\x07\\u202e"
    assert safe_text("x" * 10, 4) == "xxxx…"


def test_audit_and_user_agent_are_stored_escaped(gate, client):
    client.get(gate.url + "/api/%1b%5b31mRED%1b%5d52%3bc%3bSGVsbG8%3d%07")
    entry = gate.state.audit_log[-1]
    assert "\x1b" not in entry.detail["path"] and "\\x1b" in entry.detail["path"]
    client.get(gate.url + "/api/tags", headers={**bearer(gate.token), "User-Agent": "evil" + ESC.replace("\x07", "")})
    assert "\x1b" not in gate.device.user_agent


def test_cli_output_is_escaped(admin_gate):  # noqa: F811
    gate, _ = admin_gate
    gate.call(lambda: gate.state.audit("pairing_failed", ip="1.2.3.4", note=ESC))
    gate.call(lambda: setattr(gate.device, "user_agent", ESC))  # even if storage missed it
    out = CliRunner().invoke(cli, ["audit"]).output + CliRunner().invoke(cli, ["devices", "show", gate.device.id]).output
    assert "\x1b" not in out and "\x07" not in out


# ----- pairing abuse ------------------------------------------------------------------


def test_nested_json_claim_is_400(gate, client):
    gate.call(lambda: pairing.open_window(gate.state, base_url=gate.url, fingerprint=None, ttl_seconds=60, max_attempts=5))
    r = client.post(gate.url + "/pair/claim", content=b"[" * 4000, headers={"Content-Type": "application/json"})
    assert r.status_code == 400


def test_ipv6_clients_grouped_by_64():
    assert client_key("2001:db8:1:2:aaaa::1") == client_key("2001:db8:1:2:bbbb::9") == "2001:db8:1:2::/64"
    assert client_key("::ffff:203.0.113.5") == "203.0.113.5"
    assert client_key("203.0.113.5") == "203.0.113.5"
    assert client_key(None) == "unknown"


def test_noisy_audit_is_capped_per_client():
    state = State()
    for _ in range(50):
        state.audit_noisy("auth_failed", ip="203.0.113.5")
    state.audit_noisy("auth_failed", ip="203.0.113.6")
    assert len(state.audit_log) == 11
    assert state.audit_suppressed == 40


def test_cancel_only_named_window():
    state = State()
    admin = Admin(state, Config(), None)
    first = admin.open_pairing()
    second = admin.open_pairing()
    assert admin.cancel_pairing(window_id=first["window_id"]) == {"cancelled": False}
    assert state.pairing_window.id == second["window_id"]
    assert admin.cancel_pairing(window_id=second["window_id"]) == {"cancelled": True}


def test_loopback_pairing_url_warns():
    info = Admin(State(), Config(), None).open_pairing()
    assert info["warning"] and "public_url" in info["warning"]


# ----- state / service ------------------------------------------------------------------


def _device(state):
    token = auth.new_device_token()
    return token, state.add_device(name="d", token_hash=auth.hash_token(token), token_prefix="p", paired_via="t")


def test_grace_period_end_kills_old_token_streams():
    async def run():
        state = State()
        old, dev = _device(state)
        old_stream = state.register_stream(dev.id, "POST", "/api/chat", auth.hash_token(old))
        new = auth.new_device_token()
        state.rotate_token(dev.id, auth.hash_token(new), "p", grace_seconds=60)
        new_stream = state.register_stream(dev.id, "POST", "/api/chat", auth.hash_token(new))
        state.sweep(now=time.time() + 61)
        return old_stream.killed.is_set(), new_stream.killed.is_set()

    assert asyncio.run(run()) == (True, False)


def test_suspend_kills_streams_in_state():
    async def run():
        state = State()
        _, dev = _device(state)
        s = state.register_stream(dev.id, "POST", "/api/chat")
        state.set_status(dev.id, DeviceStatus.SUSPENDED)
        return s.killed.is_set(), s.kill_reason

    assert asyncio.run(run()) == (True, "suspended")


@pytest.mark.parametrize(
    "cmd,args",
    [
        ("devices.rotate", {"grace_seconds": True}),
        ("devices.rotate", {"grace_seconds": 1.5}),
        ("pairing.open", {"ttl": True}),
        ("pairing.open", {"methods": {"code": 1}}),
        ("audit.list", {"limit": True}),
        ("audit.list", {"event": 5}),
        ("devices.model_management", {"allowed": "yes"}),
        ("devices.show", {"bogus": 1}),
    ],
)
def test_dispatch_rejects_bad_types(cmd, args):
    state = State()
    _, dev = _device(state)
    if cmd.startswith("devices."):
        args = {"ref": dev.id, **args}
    with pytest.raises(AdminError):
        asyncio.run(Admin(state, Config(), None).dispatch(cmd, args))


def test_model_management_grant(admin_gate, client):  # noqa: F811
    gate, _ = admin_gate
    assert client.post(gate.url + "/api/pull", headers=bearer(gate.token), json={"model": "x"}).status_code == 403
    r = CliRunner().invoke(cli, ["devices", "model-management", gate.device.id, "--allow"])
    assert r.exit_code == 0 and "allowed" in r.output
    assert client.post(gate.url + "/api/pull", headers=bearer(gate.token), json={"model": "x"}).status_code == 200


# ----- control channel ------------------------------------------------------------------


def test_shutdown_not_blocked_by_idle_connection(tmp_path):
    async def run():
        server = await ipc.start_control_server(tmp_path, lambda c, a: asyncio.sleep(0))
        info = json.loads((ipc.run_dir(tmp_path) / "admin.json").read_text())
        if info["transport"] == "unix":
            reader, writer = await asyncio.open_unix_connection(info["path"])
        else:
            reader, writer = await asyncio.open_connection("127.0.0.1", info["port"])
        await asyncio.sleep(0.1)
        await asyncio.wait_for(server.close(), 3)
        writer.close()
        return (ipc.run_dir(tmp_path) / "admin.json").exists()

    assert asyncio.run(run()) is False


def test_client_rejects_impostor_without_proof(tmp_path):
    """A process squatting on the channel can't feed the CLI fake replies."""
    rdir = ipc.run_dir(tmp_path)
    rdir.mkdir(parents=True)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    (rdir / "admin.json").write_text(json.dumps({"transport": "tcp", "port": port, "secret": "s"}))

    def impostor():
        conn, _ = listener.accept()
        conn.recv(65536)
        conn.sendall(json.dumps({"ok": True, "result": {"qr_url": "https://evil"}}).encode() + b"\n")
        conn.close()

    t = threading.Thread(target=impostor, daemon=True)
    t.start()
    with pytest.raises(ipc.NotRunning, match="prove"):
        ipc.ControlClient(tmp_path).call("pairing.open")
    listener.close()


def test_non_ascii_secret_and_nested_json(tmp_path):
    async def run():
        server = await ipc.start_control_server(tmp_path, lambda c, a: asyncio.sleep(0))
        info = json.loads((ipc.run_dir(tmp_path) / "admin.json").read_text())
        if info["transport"] == "unix":
            reader, writer = await asyncio.open_unix_connection(info["path"])
        else:
            reader, writer = await asyncio.open_connection("127.0.0.1", info["port"])
        writer.write(b"[" * 5000 + b"\n")
        first = json.loads(await reader.readline())
        writer.write(json.dumps({"secret": "sécret", "nonce": "n", "cmd": "x"}).encode() + b"\n")
        second = json.loads(await reader.readline())
        writer.close()
        await server.close()
        return first, second

    first, second = asyncio.run(run())
    assert first == {"ok": False, "error": "malformed request"}
    assert second == {"ok": False, "error": "unauthorized"}


@pytest.mark.skipif(sys.platform == "win32", reason="unix sockets")
def test_long_config_dir_uses_short_socket_path(tmp_path):
    deep = tmp_path / ("x" * 60) / ("y" * 60)

    async def run():
        server = await ipc.start_control_server(deep, lambda c, a: asyncio.sleep(0))
        path = json.loads((ipc.run_dir(deep) / "admin.json").read_text())["path"]
        await server.close()
        return path

    path = asyncio.run(run())
    assert len(path) <= ipc.MAX_UNIX_PATH


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership")
def test_run_dir_symlink_refused(tmp_path):
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "run").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(RuntimeError, match="symlink"):
        asyncio.run(ipc.start_control_server(tmp_path / "cfg", lambda c, a: asyncio.sleep(0)))


def test_expiry_unicode_digit_does_not_crash(admin_gate):  # noqa: F811
    gate, _ = admin_gate
    r = CliRunner().invoke(cli, ["devices", "expiry", gate.device.id, "²"])
    assert r.exit_code == 1 and "Traceback" not in r.output
