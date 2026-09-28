from __future__ import annotations

import time

import pytest

from ollamagate.server import auth, pairing
from ollamagate.state import State, WindowState

BASE = "https://gate.example:8443"


def open_window(state, **kw):
    kw.setdefault("ttl_seconds", 300)
    kw.setdefault("max_attempts", 5)
    return pairing.open_window(state, base_url=BASE, fingerprint="ab" * 32, **kw)


def claim(state, secret, kind="code", name="phone", **kw):
    return pairing.claim(state, secret=secret, kind=kind, device_name=name, ip="203.0.113.7", user_agent="UA", **kw)


# ----- secrets & formatting ---------------------------------------------------------


def test_code_alphabet_and_format():
    code = pairing.new_code()
    assert len(code) == 8 and set(code) <= set(pairing.CROCKFORD)
    assert not set(code) & set("ILOU")
    assert pairing.format_code("ABCD2345") == "ABCD-2345"


@pytest.mark.parametrize("typed", ["abcd-1100", "ABCD 1100", "abcdIlOo", "ABCD-ILOO"])
def test_code_normalization(typed):
    assert pairing.normalize_code(typed) == "ABCD1100"


def test_link_secret_in_fragment_not_query():
    s = open_window(State())
    for url in (s.qr_url, s.link_url):
        assert url.startswith(BASE + "/pair#t=")
        assert "?" not in url
        assert url.endswith("&fp=" + "ab" * 32)
    assert s.qr_url != s.link_url  # separate secrets tell QR and link apart


def test_only_hashes_stored():
    state = State()
    s = open_window(state)
    stored = repr(state.pairing_window)
    for secret in (s.code, s.qr_url.split("t=")[1].split("&")[0], s.link_url.split("t=")[1].split("&")[0]):
        assert secret not in stored


@pytest.mark.parametrize(
    "raw,expected",
    [("  My   Phone ", "My Phone"), ("a‮evil", "aevil"), ("x\x00y\n", "xy"), ("", None), ("a" * 65, None), (5, None)],
)
def test_device_name_cleaning(raw, expected):
    assert pairing.clean_device_name(raw) == expected


# ----- claiming -------------------------------------------------------------------------


def test_claim_with_code_creates_device_with_hashed_token():
    state = State()
    s = open_window(state)
    r = claim(state, s.code_display.lower())
    assert r.error is None and r.token.startswith("og_dev_")
    assert r.device.paired_via == "code"
    assert r.device.token_hash == auth.hash_token(r.token)
    assert auth.authenticate(state, r.token).device is r.device
    assert state.pairing_window is None
    assert state.pairing_history[-1].state is WindowState.USED
    assert state.audit_log[-1].event == "pairing_succeeded"
    assert r.token not in repr(list(state.audit_log))


@pytest.mark.parametrize("method", ["qr", "link"])
def test_claim_with_link_secrets(method):
    state = State()
    s = open_window(state)
    url = s.qr_url if method == "qr" else s.link_url
    secret = url.split("#t=")[1].split("&")[0]
    r = claim(state, secret, kind="link")
    assert r.error is None and r.device.paired_via == method


def test_window_is_single_use():
    state = State()
    s = open_window(state)
    assert claim(state, s.code).error is None
    assert claim(state, s.code).error is pairing.ClaimError.CLOSED  # replay


def test_wrong_attempts_destroy_window():
    state = State()
    s = open_window(state, max_attempts=5)
    for i in range(4):
        r = claim(state, "ZZZZZZZZ")
        assert r.error is pairing.ClaimError.INVALID and r.attempts_left == 4 - i
    assert claim(state, "ZZZZZZZZ").error is pairing.ClaimError.INVALID
    # The real code no longer works after the window self-destructs.
    assert claim(state, s.code).error is pairing.ClaimError.CLOSED
    assert state.pairing_history[-1].state is WindowState.DESTROYED
    assert state.list_devices() == []


def test_code_cannot_be_used_as_link_secret_and_vice_versa():
    state = State()
    s = open_window(state)
    link_secret = s.link_url.split("#t=")[1].split("&")[0]
    assert claim(state, s.code, kind="link").error is pairing.ClaimError.INVALID
    assert claim(state, link_secret, kind="code").error is pairing.ClaimError.INVALID


def test_expired_window():
    state = State()
    s = open_window(state, ttl_seconds=60)
    r = pairing.claim(
        state, secret=s.code, kind="code", device_name="x", ip=None, user_agent="", now=time.time() + 61
    )
    assert r.error is pairing.ClaimError.CLOSED
    assert state.pairing_history[-1].state is WindowState.EXPIRED


def test_opening_new_window_cancels_old():
    state = State()
    old = open_window(state)
    open_window(state)
    assert claim(state, old.code).error is pairing.ClaimError.INVALID
    assert state.pairing_history[-1].state is WindowState.CANCELLED


def test_methods_subset():
    state = State()
    s = open_window(state, methods=("code",))
    assert s.qr_url is None and s.link_url is None
    assert set(state.pairing_window.secret_hashes) == {"code"}
    with pytest.raises(ValueError):
        open_window(state, methods=("carrier-pigeon",))


def test_bad_name_does_not_consume_attempt():
    state = State()
    s = open_window(state)
    assert claim(state, s.code, name="").error is pairing.ClaimError.BAD_NAME
    assert state.pairing_window.attempts == 0
    assert claim(state, s.code).error is None


def test_oversized_secrets_rejected_cheaply():
    state = State()
    open_window(state)
    assert claim(state, "A" * 10_000).error is pairing.ClaimError.INVALID
    assert claim(state, "A" * 10_000, kind="link").error is pairing.ClaimError.INVALID


def test_qr_rendering(tmp_path):
    from ollamagate import qr

    text = qr.render_text(BASE + "/pair#t=abc")
    lines = text.splitlines()
    assert len(lines) > 10 and len(set(map(len, lines))) == 1  # square-ish, even rows
    svg = tmp_path / "pair.svg"
    qr.write_svg(BASE + "/pair#t=abc", svg)
    assert svg.read_text().lstrip().startswith("<?xml") or "<svg" in svg.read_text()
