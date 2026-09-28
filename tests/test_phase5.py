"""Phase 5: network modes, certificate reload, doctor, notifications and services."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from ollamagate import doctor, notify, service
from ollamagate.config import Config, ConfigError, NotifyConfig, load_config
from ollamagate.network import apply_network_mode
from ollamagate.server import tls
from ollamagate.state import State

# ----- network modes -------------------------------------------------------------------


def fake_tailscale(tmp_path: Path, state: str = "Running", cert_ok: bool = True):
    calls = []

    def run(cmd):
        calls.append(cmd)
        if cmd[:2] == ["tailscale", "status"]:
            status = {"BackendState": state, "Self": {"DNSName": "my-pc.tail1234.ts.net.", "TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::1"]}}
            return subprocess.CompletedProcess(cmd, 0, json.dumps(status), "")
        if cmd[:2] == ["tailscale", "cert"] and cert_ok:
            cert_file, key_file = Path(cmd[cmd.index("--cert-file") + 1]), Path(cmd[cmd.index("--key-file") + 1])
            tls.generate_self_signed(cert_file, key_file, ["my-pc.tail1234.ts.net"])
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 1, "", "HTTPS certificates are not enabled")

    return run, calls


def test_tailscale_mode_binds_to_tailnet_and_uses_its_cert(tmp_path):
    cfg = Config()
    cfg.config_dir = tmp_path
    cfg.network.mode = "tailscale"
    run, calls = fake_tailscale(tmp_path)
    result = apply_network_mode(cfg, run)
    assert cfg.server.host == "100.101.102.103"  # not the LAN, not 0.0.0.0
    assert cfg.server.public_url == "https://my-pc.tail1234.ts.net:8443"
    assert cfg.tls.mode == "files" and Path(cfg.tls.cert_file).exists()
    assert Path(cfg.tls.key_file).stat().st_mode & 0o077 == 0 or sys.platform == "win32"
    assert any("Tailscale" in n for n in result.notes)
    assert ["tailscale", "status", "--json"] in calls


def test_tailscale_mode_keeps_explicit_settings(tmp_path):
    cfg = Config()
    cfg.config_dir = tmp_path
    cfg.network.mode = "tailscale"
    cfg.server.host = "100.101.102.103"
    cfg.server.public_url = "https://gate.example"
    cfg.tls.mode = "files"
    cfg.tls.cert_file = cfg.tls.key_file = "x"
    run, calls = fake_tailscale(tmp_path)
    apply_network_mode(cfg, run)
    assert cfg.server.public_url == "https://gate.example" and cfg.tls.cert_file == "x"
    assert not any(c[:2] == ["tailscale", "cert"] for c in calls)


@pytest.mark.parametrize("state,cert_ok,match", [("Stopped", True, "not running"), ("Running", False, "HTTPS certificates")])
def test_tailscale_problems_are_explained(tmp_path, state, cert_ok, match):
    cfg = Config()
    cfg.config_dir = tmp_path
    cfg.network.mode = "tailscale"
    run, _ = fake_tailscale(tmp_path, state, cert_ok)
    with pytest.raises(ConfigError, match=match):
        apply_network_mode(cfg, run)


def test_cloudflare_mode(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('[network]\nmode = "cloudflare"\n[tls]\nmode = "off"\n[server]\npublic_url = "https://ai.example.com"\n')
    cfg = load_config(p, env={})
    assert cfg.network.trusted_proxies == ["127.0.0.1/32", "::1/128"]  # the local cloudflared
    apply_network_mode(cfg)
    cfg.server.host = "0.0.0.0"
    with pytest.raises(ConfigError, match="loopback"):
        apply_network_mode(cfg)
    cfg.server.host = "127.0.0.1"
    cfg.server.public_url = ""
    with pytest.raises(ConfigError, match="public_url"):
        apply_network_mode(cfg)


def test_letsencrypt_mode_needs_files_and_url():
    cfg = Config()
    cfg.network.mode = "letsencrypt"
    with pytest.raises(ConfigError, match="tls.mode"):
        apply_network_mode(cfg)


# ----- certificate hot reload --------------------------------------------------------------


def test_cert_reloader_picks_up_renewed_certificate(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    tls.generate_self_signed(cert, key, ["127.0.0.1"])
    ctx = tls.build_server_context(cert, key)
    reloader = tls.CertReloader(ctx, cert, key)
    assert reloader.check() is False  # unchanged
    time.sleep(0.01)
    tls.generate_self_signed(cert, key, ["127.0.0.1", "renewed.example"])
    os.utime(cert, (time.time() + 5, time.time() + 5))
    assert reloader.check() is True
    key.write_text("garbage")  # half-written renewal: keep serving the old cert
    os.utime(key, (time.time() + 10, time.time() + 10))
    assert reloader.check() is False


# ----- doctor ------------------------------------------------------------------------------------


def test_doctor_reports_unreachable_ollama_and_loopback_links(tmp_path):
    cfg = Config()
    cfg.config_dir = tmp_path
    cfg.ollama.url = "http://127.0.0.1:9"  # nothing listens here
    findings = doctor.run_all(cfg)
    titles = " | ".join(f.title for f in findings)
    assert "not answering" in titles
    assert "Pairing links will point at" in titles
    assert "self-signed" in titles


def test_doctor_tls_checks(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    tls.generate_self_signed(cert, key, ["gate.example"])
    cfg = Config()
    cfg.config_dir = tmp_path
    cfg.tls.mode, cfg.tls.cert_file, cfg.tls.key_file = "files", str(cert), str(key)
    cfg.server.public_url = "https://gate.example"
    tls_findings = doctor.check_tls(cfg)
    assert all(f.level == "ok" for f in tls_findings), tls_findings
    cfg.server.public_url = "https://other.example"
    assert any("not valid for other.example" in f.title for f in doctor.check_tls(cfg))


# ----- notifications --------------------------------------------------------------------------


def test_notifier_sends_secret_free_messages():
    sent = []

    def handler(request):
        sent.append((str(request.url), request.content.decode()))
        return httpx.Response(200)

    async def run():
        state = State()
        from ollamagate.server import auth

        token = auth.new_device_token()
        d = state.add_device(name="Anna's phone", token_hash=auth.hash_token(token), token_prefix="p", paired_via="qr")
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        cfg = NotifyConfig(ntfy_url="https://ntfy.example/topic", events=["pairing", "ban"])
        notifier = notify.attach(state, cfg, client=client)
        task = asyncio.create_task(notifier.run())
        state.audit("pairing_succeeded", ip="203.0.113.5", device_id=d.id, method="qr")
        state.audit("device_new_ip", ip="203.0.113.6", device_id=d.id)  # not subscribed
        state.audit("ban_auto", ip="198.51.100.1", reason="failed logins", strikes=2)
        state.audit("auth_failed", ip="198.51.100.1")  # never notified
        await asyncio.sleep(0.05)
        task.cancel()
        await client.aclose()
        return token

    token = asyncio.run(run())
    assert [url for url, _ in sent] == ["https://ntfy.example/topic"] * 2
    assert "New device paired: Anna's phone (via qr) from 203.0.113.5" in sent[0][1]
    assert "Auto-banned 198.51.100.1" in sent[1][1]
    assert all(token not in body for _, body in sent)


def test_notifier_rate_limited_and_off_by_default():
    assert notify.attach(State(), NotifyConfig()) is None
    state = State()
    notifier = notify.Notifier(NotifyConfig(ntfy_url="https://x"), state)
    for _ in range(200):
        notifier.on_audit(state.audit("admin_lockdown_on"))
    assert notifier.queue.qsize() == notify.QUEUE_SIZE and notifier.dropped == 200 - notify.QUEUE_SIZE


def test_notify_config_validation(tmp_path):
    p = tmp_path / "c.toml"
    for bad in ('[notify]\nntfy_url = "http://ntfy.sh/x"\n', '[notify]\ntelegram_bot_token = "t"\n',
                '[notify]\nevents = ["everything"]\n'):
        p.write_text(bad)
        with pytest.raises(ConfigError):
            load_config(p, env={})


# ----- services ---------------------------------------------------------------------------------


def test_systemd_unit(tmp_path):
    p = service.plan(Path("/home/me/og.toml"), platform="linux", home=tmp_path)
    assert p.path == tmp_path / ".config/systemd/user/ollamagate.service"
    assert "serve --no-tui --config /home/me/og.toml" in p.content
    assert "NoNewPrivileges=true" in p.content and "User=root" not in p.content
    assert ["systemctl", "--user", "enable", "--now", "ollamagate"] in p.activate


def test_launchd_plist_escapes_paths(tmp_path):
    p = service.plan(Path("/Users/me/a&b.toml"), platform="darwin", home=tmp_path)
    assert "<string>/Users/me/a&amp;b.toml</string>" in p.content
    assert p.activate == [["launchctl", "load", "-w", str(p.path)]]


def test_windows_task_runs_with_limited_rights():
    p = service.plan(None, platform="win32")
    create = p.activate[0]
    assert create[create.index("/RL") + 1] == "LIMITED" and "--no-tui" in create[create.index("/TR") + 1]


def test_service_install_refuses_root(monkeypatch):
    from typer.testing import CliRunner

    from ollamagate.__main__ import cli

    monkeypatch.setattr(service, "running_as_admin", lambda: True)
    r = CliRunner().invoke(cli, ["service", "install", "--dry-run"])
    assert r.exit_code == 2 and "Refusing" in r.output


def test_service_install_dry_run_writes_nothing(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from ollamagate.__main__ import cli

    monkeypatch.setattr(service, "running_as_admin", lambda: False)
    monkeypatch.setattr(service.Path, "home", classmethod(lambda cls: tmp_path))
    r = CliRunner().invoke(cli, ["service", "install", "--dry-run"])
    assert r.exit_code == 0 and "Would write" in r.output and "$ " in r.output
    assert not any(tmp_path.rglob("*.service")) and not any(tmp_path.rglob("*.plist"))
