"""TOTP (RFC 6238: SHA-1, 30 s, 6 digits) guarding admin actions that grant access.

The secret lives in ``<config dir>/totp.key`` (owner-only); ``ollamagate totp
setup`` creates it. Without that file, admin actions need no code.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from pathlib import Path
from urllib.parse import quote

STEP = 30
DIGITS = 6
MAX_FAILURES = 5
LOCK_SECONDS = 300


def key_path(config_dir: Path) -> Path:
    return config_dir / "totp.key"


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()  # 160 bits, as RFC 4226 recommends


def code_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def provisioning_uri(secret: str, account: str) -> str:
    label = quote(f"OllamaGate:{account}")
    return f"otpauth://totp/{label}?secret={secret}&issuer=OllamaGate&digits={DIGITS}&period={STEP}"


class Verifier:
    """Checks codes with one step of clock drift either way. A code is accepted
    once (no replay), and MAX_FAILURES wrong codes in a row lock it for LOCK_SECONDS."""

    def __init__(self, secret: str) -> None:
        code_at(secret, 0)  # fail now on a malformed secret
        self.secret = secret
        self.last_counter = -1
        self.failures = 0
        self.locked_until = 0.0

    def locked(self, now: float | None = None) -> bool:
        return (time.time() if now is None else now) < self.locked_until

    def verify(self, code: object, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        if self.locked(now):
            return False
        code = code.replace(" ", "") if isinstance(code, str) else ""
        counter = int(now // STEP)
        for c in (counter - 1, counter, counter + 1):
            if c > self.last_counter and hmac.compare_digest(code.encode(), code_at(self.secret, c).encode()):
                self.last_counter = c
                self.failures = 0
                return True
        self.failures += 1
        if self.failures >= MAX_FAILURES:
            self.failures = 0
            self.locked_until = now + LOCK_SECONDS
        return False


def load(config_dir: Path) -> Verifier | None:
    """The configured verifier, or None if TOTP isn't set up. Raises on a damaged file."""
    path = key_path(config_dir)
    if not path.exists():
        return None
    secret = json.loads(path.read_text()).get("secret")
    if not isinstance(secret, str):
        raise ValueError(f"{path} has no secret")
    return Verifier(secret)


def save(config_dir: Path, secret: str) -> Path:
    from .admin.ipc import _write_private_json

    config_dir.mkdir(parents=True, exist_ok=True)
    path = key_path(config_dir)
    _write_private_json(path, {"secret": secret})
    return path

