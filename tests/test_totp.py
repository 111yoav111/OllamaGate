"""TOTP for admin actions: RFC 6238 codes, replay/lockout, and gating in the CLI channel and TUI."""

from __future__ import annotations

import base64
import json

import pytest

from ollamagate import totp
from ollamagate.admin.ipc import AdminError
from ollamagate.admin.service import TOTP_REQUIRED, Admin
from ollamagate.config import Config
from ollamagate.state import State
from ollamagate.tui.app import GateTUI
from ollamagate.tui.widgets import InputScreen

SEED = base64.b32encode(b"12345678901234567890").decode()


def now_code(secret: str = SEED, offset: int = 0) -> str:
    import time

    return totp.code_at(secret, int(time.time() // totp.STEP) + offset)


@pytest.mark.parametrize("t, want", [(59, "287082"), (1111111109, "081804"), (1234567890, "005924"), (20000000000, "353130")])
def test_rfc6238_vectors(t, want):
    assert totp.code_at(SEED, t // totp.STEP) == want


def test_drift_replay_and_lockout():
    v = totp.Verifier(SEED)
    t = 1000 * totp.STEP + 5
    assert v.verify(totp.code_at(SEED, 999), now=t)  # one step of drift
    assert not v.verify(totp.code_at(SEED, 999), now=t)  # no replay
    assert not v.verify(totp.code_at(SEED, 998), now=t)  # nor anything older
    assert v.verify(totp.code_at(SEED, 1001), now=t)
    v = totp.Verifier(SEED)
    for _ in range(totp.MAX_FAILURES):
        assert not v.verify("000000", now=t)
    assert v.locked(t) and not v.verify(totp.code_at(SEED, 1000), now=t)  # even the right code
    assert v.verify(totp.code_at(SEED, 1000 + totp.LOCK_SECONDS // totp.STEP + 1), now=t + totp.LOCK_SECONDS + 31)
    assert not totp.Verifier(SEED).verify(None) and not totp.Verifier(SEED).verify(123456)


def test_key_file_roundtrip(tmp_path):
    assert totp.load(tmp_path) is None
    path = totp.save(tmp_path, SEED)
    assert totp.load(tmp_path).secret == SEED and json.loads(path.read_text()) == {"secret": SEED}
    if hasattr(__import__("os"), "geteuid"):
        assert path.stat().st_mode & 0o077 == 0
    assert "secret=" + SEED in totp.provisioning_uri(SEED, "my pc")


def make_admin(with_totp: bool = True) -> Admin:
    cfg = Config()
    cfg.server.public_url = "https://gate.example:8443"
    return Admin(State(), cfg, "ab" * 32, totp=totp.Verifier(SEED) if with_totp else None)


async def test_channel_requires_code_only_for_granting_actions():
    admin = make_admin()
    for cmd, args in (("pairing.open", {}), ("lockdown.set", {"on": False}), ("settings.set", {"key": "pairing.ttl_seconds", "value": 60})):
        with pytest.raises(AdminError, match=TOTP_REQUIRED):
            await admin.dispatch(cmd, args)
    # Protective and read-only actions never wait for a code.
    assert (await admin.dispatch("lockdown.set", {"on": True}))["lockdown"] is True
    await admin.dispatch("lockdown.set", {"on": False, "totp": now_code()})
    assert admin.state.lockdown is False
    with pytest.raises(AdminError, match="wrong TOTP code"):
        await admin.dispatch("pairing.open", {"totp": now_code()})  # already used
    assert any(e.event == "admin_totp_failed" for e in admin.state.audit_log)
    assert (await admin.dispatch("pairing.open", {"totp": now_code(offset=1)}))["code"]
    assert (await admin.dispatch("dashboard", {}))["admin_totp"] is True
    assert (await make_admin(with_totp=False).dispatch("pairing.open", {}))["code"]


async def test_tui_asks_for_a_code_then_unlocks():
    admin = make_admin()
    app = GateTUI(admin)
    async with app.run_test(size=(140, 60)) as pilot:
        await pilot.press("p")
        await pilot.pause()
        assert isinstance(app.screen, InputScreen) and app._pairing is None
        await pilot.press(*now_code(), "enter")
        await pilot.pause()
        await pilot.press("p")  # repeat the action, now unlocked
        await pilot.pause()
        assert app._pairing is not None
