"""Regressions for config, bans, state, services, GeoIP and text sanitising."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from ollamagate import doctor, geoip, network, service
from ollamagate.bans import BanList
from ollamagate.config import Config, ConfigError, GeoIPConfig, load_config
from ollamagate.ollama_status import probe
from ollamagate.state import State
from ollamagate.textsafe import safe_text

# ----- config ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "toml",
    [
        "[server\nport = 1\n",  # not TOML at all
        "[server]\nport = 8443.5\n",  # silently truncated before
        "[server]\nport = inf\n",  # OverflowError before
        "[pairing]\nrequests_per_minute_per_ip = 0\n",  # would refuse every pairing attempt
        "[logging]\naudit_size = -1\n",  # crashed at start-up (deque maxlen)
    ],
)
def test_bad_config_values_are_config_errors(tmp_path, toml):
    p = tmp_path / "c.toml"
    p.write_text(toml)
    with pytest.raises(ConfigError):
        load_config(p, env={})


def test_whole_float_is_accepted_for_int(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("[server]\nport = 9443.0\n")
    assert load_config(p, env={}).server.port == 9443


def test_unreadable_config_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path, env={})  # a directory


# ----- GeoIP ---------------------------------------------------------------------------------


def test_invalid_geoip_database_raises_value_error(tmp_path):
    db = tmp_path / "x.mmdb"
    db.write_bytes(b"not a database" * 10)
    with pytest.raises(ValueError, match="not a valid"):
        geoip.load(GeoIPConfig(database=str(db)))


def test_corrupt_geoip_record_reads_as_unknown():
    class Broken:
        def get(self, ip):
            raise RuntimeError("corrupt record")  # maxminddb.InvalidDatabaseError

    g = geoip.GeoIP(Broken(), ["DE"], [])
    assert g.country("8.8.8.8") is None and not g.permits("8.8.8.8")  # allowlist fails closed


# ----- textsafe ------------------------------------------------------------------------------


def test_safe_text_escapes_line_separators_and_astral_controls():
    assert safe_text("a b c") == "a\\u2028b\\u2029c"
    assert safe_text("x\U000e0001") == "x\\U000e0001"
    assert safe_text("\x1b" * 10, 8).endswith("…")  # cut by escaping: still marked


# ----- bans / state ----------------------------------------------------------------------------


def test_auto_ban_never_replaces_a_manual_ban():
    bans = BanList(threshold=2)
    manual = bans.ban("203.0.113.9", "manual", None, now=0)
    for i in range(5):
        assert bans.record_failure("203.0.113.9", "failed logins", f"t{i}", now=1 + i) is None
    assert bans.banned("203.0.113.9", now=10**9) is manual


def test_rotating_twice_cuts_streams_of_the_dropped_token():
    async def run():
        state = State()
        d = state.add_device(name="p", token_hash="h1", token_prefix="p", paired_via="qr")
        s1 = state.register_stream(d.id, "POST", "/api/chat", token_hash="h1")
        state.rotate_token(d.id, "h2", "p", grace_seconds=60)
        assert not s1.killed.is_set()  # still in its grace period
        s2 = state.register_stream(d.id, "POST", "/api/chat", token_hash="h2")
        state.rotate_token(d.id, "h3", "p", grace_seconds=60)
        return s1, s2, state

    s1, s2, state = asyncio.run(run())
    assert s1.killed.is_set() and not s2.killed.is_set()
    assert state.device_by_token_hash("h1") is None and state.device_by_token_hash("h2") is not None


# ----- services ---------------------------------------------------------------------------------


def test_systemd_quotes_awkward_paths(tmp_path):
    p = service.plan(Path("/home/o'brien/my dir/a\\b\".toml"), platform="linux", home=tmp_path)
    line = next(line for line in p.content.splitlines() if line.startswith("ExecStart="))
    # systemd syntax, not POSIX shell: double quotes with C escapes, no '"'"' splicing.
    assert line.endswith('--config "/home/o\'brien/my dir/a\\\\b\\".toml"')
    assert "serve --no-tui" in line


def test_windows_script_quotes_cmd_metacharacters(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("OLLAMAGATE_CONFIG_DIR", "/srv/R&D/100%")
    p = service.plan(Path("/srv/R&D/50%.toml"), platform="win32", home=tmp_path)
    assert '"/srv/R&D/50%%.toml"' in p.content
    assert 'set "OLLAMAGATE_CONFIG_DIR=/srv/R&D/100%%"' in p.content
    assert "serve --no-tui" in p.content


def test_control_characters_in_config_dir_are_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("OLLAMAGATE_CONFIG_DIR", str(tmp_path / "x\nExecStartPre=/bin/evil"))
    for platform in ("linux", "darwin", "win32"):
        with pytest.raises(ValueError):
            service.plan(None, platform=platform, home=tmp_path)


def test_service_install_reports_bad_paths_cleanly(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from ollamagate.__main__ import cli

    monkeypatch.setattr(service, "running_as_admin", lambda: False)
    monkeypatch.setenv("OLLAMAGATE_CONFIG_DIR", str(tmp_path / "x\ny"))
    r = CliRunner().invoke(cli, ["service", "install", "--dry-run"])
    assert r.exit_code == 1 and "control characters" in r.output  # a message, not a traceback


def test_write_service_file_is_utf8_on_posix(tmp_path):
    p = service.ServicePlan(path=tmp_path / "x.service", content="ExecStart=/home/josé/x\n", activate=[], deactivate=[])
    service.write_service_file(p)
    assert (tmp_path / "x.service").read_bytes() == "ExecStart=/home/josé/x\n".encode()


# ----- network / doctor / status ------------------------------------------------------------------


def test_hanging_tailscale_cli_is_a_config_error(monkeypatch):
    def hang(*a, **kw):
        raise subprocess.TimeoutExpired(a[0], 60)

    monkeypatch.setattr(network.subprocess, "run", hang)
    with pytest.raises(ConfigError, match="did not answer"):
        network._run(["tailscale", "status", "--json"])


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_doctor_checks_the_config_file_in_use(tmp_path):
    cfg = Config()
    cfg.config_dir = tmp_path / "dir"
    other = tmp_path / "elsewhere.toml"
    other.write_text("")
    other.chmod(0o644)
    assert any(str(other) in f.title for f in doctor.check_files(cfg, other))
    other.chmod(0o600)
    assert not any(str(other) in f.title for f in doctor.check_files(cfg, other))


def test_ollama_status_tolerates_odd_ps_output():
    def handler(request):
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.9"})
        return httpx.Response(200, json={"models": 5})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://o") as c:
            return await probe(c)

    status = asyncio.run(run())
    assert status.reachable and status.models == [] and status.version == "0.9"
