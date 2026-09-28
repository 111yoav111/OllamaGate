"""The admin control channel and CLI, against a live gate."""

from __future__ import annotations

import json
import socket
import sys

import pytest
from typer.testing import CliRunner

from ollamagate.__main__ import cli
from ollamagate.admin import ipc
from ollamagate.admin.service import Admin
from ollamagate.state import DeviceStatus

from .test_proxy_stream import bearer


@pytest.fixture
def admin_gate(gate, tmp_path, monkeypatch):
    admin = Admin(gate.state, gate.app.state.config, "ab" * 32)
    control = gate.run(ipc.start_control_server(tmp_path, admin.dispatch))
    monkeypatch.setenv("OLLAMAGATE_CONFIG_DIR", str(tmp_path))
    yield gate, tmp_path
    gate.run(control.close())


def run_cli(*args, input=None):
    result = CliRunner().invoke(cli, list(args), input=input)
    return result


def test_control_files_are_private(admin_gate):
    _, cfg_dir = admin_gate
    info_path = ipc.run_dir(cfg_dir) / "admin.json"
    info = json.loads(info_path.read_text())
    assert len(info["secret"]) >= 43
    if sys.platform != "win32":
        assert info_path.stat().st_mode & 0o077 == 0
        assert ipc.run_dir(cfg_dir).stat().st_mode & 0o077 == 0
        assert info["transport"] == "unix"
        assert (ipc.run_dir(cfg_dir) / "admin.sock").stat().st_mode & 0o077 == 0


def test_wrong_secret_rejected(admin_gate):
    _, cfg_dir = admin_gate
    client = ipc.ControlClient(cfg_dir)
    client.info = {**client.info, "secret": "wrong"}
    with pytest.raises(ipc.AdminError, match="unauthorized"):
        client.call("devices.list")
    client.close()


def test_unknown_command_and_bad_args(admin_gate):
    _, cfg_dir = admin_gate
    with ipc.ControlClient(cfg_dir) as client:
        with pytest.raises(ipc.AdminError, match="unknown command"):
            client.call("__init__")
        with pytest.raises(ipc.AdminError, match="bad arguments"):
            client.call("devices.show", nope=1)
        with pytest.raises(ipc.AdminError, match="no device"):
            client.call("devices.show", ref="zzzzzzzz")


def test_not_running(tmp_path, monkeypatch):
    monkeypatch.setenv("OLLAMAGATE_CONFIG_DIR", str(tmp_path))
    r = run_cli("devices", "list")
    assert r.exit_code == 3 and "not running" in r.output


def test_device_views_never_include_hash(admin_gate):
    gate, cfg_dir = admin_gate
    with ipc.ControlClient(cfg_dir) as client:
        devices = client.call("devices.list")
    assert devices[0]["name"] == "phone"
    assert "token_hash" not in json.dumps(devices)
    assert gate.device.token_hash not in json.dumps(devices)


def test_cli_list_show_rename(admin_gate):
    gate, _ = admin_gate
    short = gate.device.id[:8]
    r = run_cli("devices", "list")
    assert r.exit_code == 0 and "phone" in r.output and short in r.output
    r = run_cli("devices", "rename", short, "Work laptop")
    assert r.exit_code == 0 and gate.device.name == "Work laptop"
    r = run_cli("devices", "show", short)
    assert "Work laptop" in r.output and "og_dev_" in r.output
    assert any(e.event == "admin_rename" for e in gate.state.audit_log)


def test_cli_revoke_cuts_access(admin_gate, client):
    gate, _ = admin_gate
    r = run_cli("devices", "revoke", gate.device.id, "--yes")
    assert r.exit_code == 0
    assert gate.device.status is DeviceStatus.REVOKED
    assert client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 401


def test_cli_revoke_asks_for_confirmation(admin_gate):
    gate, _ = admin_gate
    r = run_cli("devices", "revoke", gate.device.id, input="n\n")
    assert r.exit_code != 0 and gate.device.status is DeviceStatus.ACTIVE


def test_cli_rotate(admin_gate, client):
    gate, _ = admin_gate
    r = run_cli("devices", "rotate", gate.device.id)
    assert r.exit_code == 0
    new_token = next(w for w in r.output.split() if w.startswith("og_dev_") and len(w) > 40)
    assert client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 401
    assert client.get(gate.url + "/api/tags", headers=bearer(new_token)).status_code == 200
    assert new_token not in json.dumps([vars(e) for e in gate.state.audit_log], default=str)


def test_cli_suspend_resume(admin_gate, client):
    gate, _ = admin_gate
    assert run_cli("devices", "suspend", gate.device.id).exit_code == 0
    assert client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 403
    assert run_cli("devices", "resume", gate.device.id).exit_code == 0
    assert client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 200
    r = run_cli("devices", "resume", gate.device.id)
    assert r.exit_code == 1 and "not suspended" in r.output


def test_cli_expiry(admin_gate, client):
    gate, _ = admin_gate
    assert run_cli("devices", "expiry", gate.device.id, "7d").exit_code == 0
    assert gate.device.token_expires_at is not None
    assert run_cli("devices", "expiry", gate.device.id, "never").exit_code == 0
    assert gate.device.token_expires_at is None
    assert run_cli("devices", "expiry", gate.device.id, "5").exit_code == 1  # too short


def test_cli_pair_no_wait_then_claim(admin_gate, client):
    gate, _ = admin_gate
    r = run_cli("pair", "--no-wait")
    assert r.exit_code == 0
    code = next(w for w in r.output.split() if len(w) == 9 and w[4] == "-")
    assert "/pair#t=" in r.output and "█" in r.output  # link and QR shown
    claim = client.post(gate.url + "/pair/claim", json={"code": code, "device_name": "tablet"})
    assert claim.status_code == 200
    assert run_cli("pair", "--cancel").output.startswith("No pairing window")


def test_cli_pair_single_method(admin_gate):
    r = run_cli("pair", "--no-wait", "--method", "code")
    assert r.exit_code == 0 and "/pair#t=" not in r.output
    assert run_cli("pair", "--method", "fax", "--no-wait").exit_code == 1


def test_cli_audit(admin_gate):
    run_cli("pair", "--no-wait")
    r = run_cli("audit", "--event", "pairing")
    assert "pairing_opened" in r.output


@pytest.mark.skipif(sys.platform == "win32", reason="unix sockets")
def test_second_instance_refused(admin_gate):
    gate, cfg_dir = admin_gate
    with pytest.raises(RuntimeError, match="already running"):
        gate.run(ipc.start_control_server(cfg_dir, lambda c, a: None))


def test_oversized_message_closes_connection(admin_gate):
    _, cfg_dir = admin_gate
    info = json.loads((ipc.run_dir(cfg_dir) / "admin.json").read_text())
    if info["transport"] == "unix":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(info["path"])
    else:
        s = socket.create_connection(("127.0.0.1", info["port"]))
    s.settimeout(5)
    try:
        s.sendall(b"x" * (ipc.MAX_MESSAGE + 10) + b"\n")
    except OSError:
        pass
    try:
        assert s.recv(100) in (b"",)
    except ConnectionResetError:
        pass
    s.close()
