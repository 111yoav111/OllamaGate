"""Device token generation and verification.

Tokens look like ``og_dev_<43 base64url chars>`` (256 random bits). Only the
SHA-256 hash and a short, non-secret display prefix are ever stored.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Mapping

from ..state import Device, DeviceStatus, State

TOKEN_PREFIX = "og_dev_"
TOKEN_BYTES = 32
# Upper bound on what we even bother hashing; real tokens are 50 chars.
MAX_TOKEN_LEN = 128


def new_device_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def display_prefix(token: str) -> str:
    """Non-secret prefix for display, e.g. ``og_dev_ab12…`` (24 bits of the secret)."""
    return token[: len(TOKEN_PREFIX) + 4] + "…"


def extract_bearer(headers: Mapping[str, str]) -> str | None:
    value = headers.get("authorization")
    if not value:
        return None
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "bearer":
        return None
    token = token.strip()
    return token or None


# Browser sessions (the /app chat) carry the device token in this cookie. The
# __Host- prefix makes browsers insist on Secure, Path=/ and no Domain, so a
# sibling subdomain or port can't plant or overwrite it. (Browsers treat
# http://localhost as secure, so this also works in loopback-only HTTP mode.)
SESSION_COOKIE = "__Host-og_session"
CSRF_HEADER = "x-ollamagate-csrf"


def csrf_token(key: bytes, token: str) -> str:
    """Per-device CSRF token, bound to the session token and a per-process key."""
    return hmac.new(key, b"csrf:" + hash_token(token).encode(), hashlib.sha256).hexdigest()[:32]


def extract_credential(headers: Mapping[str, str], cookies: Mapping[str, str], csrf_key: bytes) -> tuple[str | None, bool]:
    """Return (token, via_cookie).

    A bearer token always wins. A session cookie only counts when the request
    also carries the matching CSRF header, which a cross-site page can't set
    (and SameSite=Strict keeps the cookie off cross-site requests anyway).
    """
    bearer = extract_bearer(headers)
    if bearer:
        return bearer, False
    cookie = cookies.get(SESSION_COOKIE)
    if not cookie or len(cookie) > MAX_TOKEN_LEN:
        return None, False
    given = headers.get(CSRF_HEADER, "")
    if not hmac.compare_digest(given.encode(), csrf_token(csrf_key, cookie).encode()):
        return None, True
    return cookie, True


class AuthResult(enum.Enum):
    OK = "ok"
    MISSING = "missing"
    INVALID = "invalid"
    EXPIRED = "expired"
    SUSPENDED = "suspended"
    NO_CERT = "no_cert"  # right token, but not over the device's own client certificate


@dataclass
class AuthOutcome:
    result: AuthResult
    device: Device | None = None


def authenticate(
    state: State, token: str | None, now: float | None = None, client_cert: str | None = None
) -> AuthOutcome:
    """Check a device token. ``client_cert`` is the SHA-256 of the TLS client
    certificate the request came over (see protocol.CLIENT_CERT_SCOPE)."""
    if not token:
        return AuthOutcome(AuthResult.MISSING)
    if len(token) > MAX_TOKEN_LEN or not token.startswith(TOKEN_PREFIX):
        return AuthOutcome(AuthResult.INVALID)
    token_hash = hash_token(token)
    device = state.device_by_token_hash(token_hash)
    if device is None or device.status == DeviceStatus.REVOKED:
        return AuthOutcome(AuthResult.INVALID)
    now = time.time() if now is None else now
    # The lookup is keyed by a hash of a 256-bit secret, so its timing leaks nothing
    # useful; the explicit constant-time compares keep the check obviously correct.
    current = hmac.compare_digest(device.token_hash, token_hash)
    previous = (
        device.previous_token_hash is not None
        and hmac.compare_digest(device.previous_token_hash, token_hash)
        and now < (device.previous_token_valid_until or 0)
    )
    if not (current or previous):
        return AuthOutcome(AuthResult.INVALID)
    # mTLS: a device that was issued a certificate must always present it, so a
    # leaked token alone is useless. Checked before expiry/suspension on purpose.
    if device.client_cert_fp is not None and not hmac.compare_digest(
        device.client_cert_fp, client_cert or ""
    ):
        return AuthOutcome(AuthResult.NO_CERT, device)
    if device.token_expires_at is not None and now >= device.token_expires_at:
        return AuthOutcome(AuthResult.EXPIRED, device)
    if device.status == DeviceStatus.SUSPENDED:
        return AuthOutcome(AuthResult.SUSPENDED, device)
    return AuthOutcome(AuthResult.OK, device)
