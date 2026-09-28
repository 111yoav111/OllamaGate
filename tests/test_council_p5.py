"""Regression tests for issues found in the Phase 5 council review."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import ssl
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from ollamagate import notify, service
from ollamagate.config import Config, ConfigError, NotifyConfig
from ollamagate.network import apply_network_mode
from ollamagate.server import auth, tls
from ollamagate.state import State

from .conftest import ThreadedServer
from .fake_ollama import make_fake_ollama
from .test_phase5 import fake_tailscale


def test_mismatched_renewal_keeps_serving_the_old_certificate(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    tls.generate_self_signed(cert, key, ["127.0.0.1"])
    ctx = tls.build_server_context(cert, key)
    reloader = tls.CertReloader(ctx, cert, key)
    # A renewer wrote the new certificate but not yet the matching key.
    other_cert, other_key = tmp_path / "c2.pem", tmp_path / "k2.pem"
    tls.generate_self_signed(other_cert, other_key, ["127.0.0.1"])
    cert.write_bytes(other_cert.read_bytes())
    os.utime(cert, (time.time() + 5, time.time() + 5))
    assert reloader.check() is False
    app, _ = make_fake_ollama()
    server = ThreadedServer(app, ssl_context=ctx).start()
    try:
        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw:
            with client_ctx.wrap_socket(raw) as s:  # handshakes still work
                assert s.version() in ("TLSv1.2", "TLSv1.3")
    finally:
        server.stop()


def test_tailscale_never_listens_on_all_interfaces(tmp_path):
    cfg = Config()
    cfg.config_dir = tmp_path
    cfg.network.mode = "tailscale"
    cfg.server.host = "0.0.0.0"
    run, _ = fake_tailscale(tmp_path)
    apply_network_mode(cfg, run)
    assert cfg.server.host == "100.101.102.103"
    cfg.server.host = "192.168.1.10"
    with pytest.raises(ConfigError, match="not a Tailscale address"):
        apply_network_mode(cfg, run)


def test_tailscale_bad_dns_name_is_refused(tmp_path):
    def weird(cmd):
        status = {"BackendState": "Running", "Self": {"DNSName": "--evil-flag.", "TailscaleIPs": ["100.64.0.1"]}}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(status), "")

    cfg = Config()
    cfg.config_dir = tmp_path
    cfg.network.mode = "tailscale"
    with pytest.raises(ConfigError, match="unexpected Tailscale DNS name"):
        apply_network_mode(cfg, weird)


def test_tailscale_permission_error_suggests_operator(tmp_path):
    status_run, _ = fake_tailscale(tmp_path)

    def denied(cmd):
        if cmd[:2] == ["tailscale", "status"]:
            return status_run(cmd)
        return subprocess.CompletedProcess(cmd, 1, "", "Access denied: cert access denied")

    cfg = Config()
    cfg.config_dir = tmp_path
    cfg.network.mode = "tailscale"
    with pytest.raises(ConfigError, match="--operator"):
        apply_network_mode(cfg, denied)


def test_systemd_exec_start_escapes_specifiers(tmp_path):
    p = service.plan(Path("/home/me/100%/$HOME/og.toml"), platform="linux", home=tmp_path)
    line = next(line for line in p.content.splitlines() if line.startswith("ExecStart="))
    assert "100%%" in line and "$$HOME" in line
    assert "PrivateTmp" not in p.content  # fails where user namespaces are blocked
    with pytest.raises(ValueError):
        service.plan(Path("/home/me/evil\nExecStartPre=/bin/evil"), platform="linux", home=tmp_path)


def test_serve_refuses_root_without_flag(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from ollamagate.__main__ import cli

    monkeypatch.setenv("OLLAMAGATE_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(service, "running_as_admin", lambda: True)
    r = CliRunner().invoke(cli, ["serve", "--no-tui"])
    assert r.exit_code == 2 and "Refusing" in r.output


@pytest.mark.parametrize("headless", [True, False])
def test_logging_setup(headless):
    """httpx logs request URLs at INFO (the Telegram URL holds the bot token), and
    headless mode must log to stderr while the TUI logs to memory."""
    from collections import deque

    from ollamagate.__main__ import _BufferHandler, configure_logging

    root = logging.getLogger()
    saved = (root.level, list(root.handlers))
    lines: deque[str] = deque(maxlen=10)
    try:
        configure_logging(headless, lines)
        assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
        assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING
        in_memory = any(isinstance(h, _BufferHandler) for h in root.handlers)
        assert in_memory is (not headless)
        logging.getLogger("httpx").info("POST https://api.telegram.org/botSECRET/sendMessage")
        assert not any("SECRET" in line for line in lines)
    finally:
        root.handlers[:] = saved[1]
        root.setLevel(saved[0])


def _run_notifier(events, cfg, handler, settle=0.05):
    async def run():
        state = State()
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        notifier = notify.attach(state, cfg, client=client)
        notifier._last_summary = time.monotonic()  # no summary during the test
        task = asyncio.create_task(notifier.run())
        for event, kw in events:
            state.audit(event, **kw)
        await asyncio.sleep(settle)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await client.aclose()
        return notifier

    return asyncio.run(run())


def test_ban_floods_are_summarised_and_priority_events_get_through():
    sent = []

    def handler(request):
        sent.append(request.content.decode())
        return httpx.Response(200)

    events = [("ban_auto", {"ip": f"2001:db8:{i}::1", "reason": "x"}) for i in range(500)]
    events.append(("admin_lockdown_on", {}))
    notifier = _run_notifier(events, NotifyConfig(ntfy_url="https://ntfy.example/t"), handler)
    assert sent == ["OllamaGate: LOCKDOWN enabled: all traffic is rejected"]  # one push, not 501
    assert notifier.pending_bans == 500
    assert "500 client(s) auto-banned" in notifier._summary()


def test_broken_channel_does_not_kill_the_notifier():
    calls = []

    def handler(request):
        calls.append(1)
        raise httpx.InvalidURL("bad token")  # not an httpx.HTTPError

    events = [("admin_lockdown_on", {}), ("admin_lockdown_off", {})]
    _run_notifier(events, NotifyConfig(ntfy_url="https://ntfy.example/t"), handler)
    assert len(calls) == 2  # kept going after the first failure


def test_device_names_are_quoted_in_notifications():
    state = State()
    d = state.add_device(
        name="Lockdown lifted", token_hash=auth.hash_token(auth.new_device_token()), token_prefix="p", paired_via="qr"
    )
    entry = state.audit("device_new_ip", ip="203.0.113.1", device_id=d.id)
    assert notify.describe(entry, state).startswith('"Lockdown lifted" connected')


def test_desktop_notification_escapes_pango_markup(monkeypatch):
    seen = []
    monkeypatch.setattr(notify.sys, "platform", "linux")
    monkeypatch.setattr(notify.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(notify.subprocess, "run", lambda cmd, **kw: seen.append(cmd))
    notify.desktop_notify('OllamaGate: "<b>x</b>" & more')
    assert seen[0][2] == "OllamaGate: &quot;&lt;b&gt;x&lt;/b&gt;&quot; &amp; more"
