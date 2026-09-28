from __future__ import annotations

import time

import pytest

from ollamagate.server import auth
from ollamagate.state import DeviceStatus, State


def test_token_format_and_entropy():
    token = auth.new_device_token()
    assert token.startswith("og_dev_")
    assert len(token) == len("og_dev_") + 43  # 32 bytes base64url, no padding
    assert auth.new_device_token() != token
    assert auth.display_prefix(token) == token[:11] + "…"


def test_only_hash_is_stored():
    state = State()
    token = auth.new_device_token()
    dev = state.add_device(
        name="x", token_hash=auth.hash_token(token), token_prefix=auth.display_prefix(token), paired_via="test"
    )
    assert token not in repr(vars(dev))
    assert auth.authenticate(state, token).device is dev


@pytest.mark.parametrize(
    "header,expected",
    [
        ("Bearer abc", "abc"),
        ("bearer   abc  ", "abc"),
        ("Basic abc", None),
        ("Bearer", None),
        ("", None),
    ],
)
def test_extract_bearer(header, expected):
    assert auth.extract_bearer({"authorization": header} if header else {}) == expected


def _state_with_device(**kwargs):
    state = State()
    token = auth.new_device_token()
    dev = state.add_device(
        name="x", token_hash=auth.hash_token(token), token_prefix="p", paired_via="test", **kwargs
    )
    return state, token, dev


def test_rejects_missing_wrong_malformed():
    state, token, _ = _state_with_device()
    assert auth.authenticate(state, None).result is auth.AuthResult.MISSING
    assert auth.authenticate(state, "og_dev_" + "A" * 43).result is auth.AuthResult.INVALID
    assert auth.authenticate(state, token[:-1]).result is auth.AuthResult.INVALID
    assert auth.authenticate(state, token.replace("og_dev_", "og_xxx_")).result is auth.AuthResult.INVALID
    assert auth.authenticate(state, token + "x" * 200).result is auth.AuthResult.INVALID


def test_revoked_token_never_works():
    state, token, dev = _state_with_device()
    state.revoke_device(dev.id)
    assert auth.authenticate(state, token).result is auth.AuthResult.INVALID
    # Even if the index were somehow stale, status still blocks it.
    state._device_by_token_hash[dev.token_hash] = dev.id
    assert auth.authenticate(state, token).result is auth.AuthResult.INVALID


def test_expired_and_suspended():
    state, token, dev = _state_with_device(token_expires_at=time.time() - 1)
    assert auth.authenticate(state, token).result is auth.AuthResult.EXPIRED
    dev.token_expires_at = None
    dev.status = DeviceStatus.SUSPENDED
    assert auth.authenticate(state, token).result is auth.AuthResult.SUSPENDED
