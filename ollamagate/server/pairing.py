"""Pairing windows: how a new device earns its token.

A window is opened by the owner (TUI or CLI), lives for a short TTL, can be
used by exactly one device, and self-destructs after too many wrong guesses.
Each window carries three independent secrets - one per method - and only
their SHA-256 hashes are kept in state. The plaintext secrets are returned
once to whoever opened the window so they can be displayed.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import secrets
import time
import unicodedata
import uuid
from dataclasses import dataclass
from urllib.parse import quote

from ..state import Device, PairingWindow, State, WindowState
from . import auth

# Crockford base32: no I, L, O, U, so 0/O and 1/I/L can't be confused.
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CODE_LEN = 8  # 40 bits; safe given the attempt cap and short TTL
LINK_SECRET_BYTES = 16  # 128 bits
METHODS = ("code", "qr", "link")
MAX_NAME_LEN = 64


def new_code() -> str:
    return "".join(secrets.choice(CROCKFORD) for _ in range(CODE_LEN))


def format_code(code: str) -> str:
    return f"{code[:4]}-{code[4:]}"


def normalize_code(raw: str) -> str:
    """Accept lowercase, dashes/spaces and the usual look-alikes (O->0, I/L->1)."""
    cleaned = raw.upper().replace("-", "").replace(" ", "")
    return cleaned.translate(str.maketrans({"O": "0", "I": "1", "L": "1"}))


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def clean_device_name(raw: object) -> str | None:
    """Return a safe display name, or None if unusable."""
    if not isinstance(raw, str):
        return None
    # Drop control/format characters (incl. bidi overrides) so names can't spoof the TUI.
    name = "".join(ch for ch in raw if unicodedata.category(ch)[0] not in ("C",))
    name = " ".join(name.split())
    if not name or len(name) > MAX_NAME_LEN:
        return None
    return name


@dataclass
class PairingSecrets:
    """Plaintext secrets for display. Never stored in state."""

    window_id: str
    expires_at: float
    code: str | None
    qr_url: str | None
    link_url: str | None

    @property
    def code_display(self) -> str | None:
        return format_code(self.code) if self.code else None


def pairing_url(base_url: str, secret: str, fingerprint: str | None) -> str:
    fragment = f"t={quote(secret)}"
    if fingerprint:
        fragment += f"&fp={fingerprint}"
    # The secret lives in the fragment so it never reaches server/proxy logs or Referer.
    return f"{base_url}/pair#{fragment}"


def open_window(
    state: State,
    *,
    base_url: str,
    fingerprint: str | None,
    ttl_seconds: int,
    max_attempts: int,
    methods: tuple[str, ...] = METHODS,
    now: float | None = None,
) -> PairingSecrets:
    """Open a new window, replacing (cancelling) any open one."""
    now = time.time() if now is None else now
    if not methods or any(m not in METHODS for m in methods):
        raise ValueError(f"methods must be a subset of {METHODS}")
    close_window(state, WindowState.CANCELLED, reason="replaced")
    code = new_code() if "code" in methods else None
    qr_secret = secrets.token_urlsafe(LINK_SECRET_BYTES) if "qr" in methods else None
    link_secret = secrets.token_urlsafe(LINK_SECRET_BYTES) if "link" in methods else None
    window = PairingWindow(
        id=uuid.uuid4().hex,
        created_at=now,
        expires_at=now + ttl_seconds,
        max_attempts=max_attempts,
        secret_hashes={
            method: _hash(secret)
            for method, secret in (("code", code), ("qr", qr_secret), ("link", link_secret))
            if secret is not None
        },
    )
    state.pairing_window = window
    state.audit("pairing_opened", window_id=window.id, methods=list(methods), ttl=ttl_seconds)
    return PairingSecrets(
        window_id=window.id,
        expires_at=window.expires_at,
        code=code,
        qr_url=pairing_url(base_url, qr_secret, fingerprint) if qr_secret else None,
        link_url=pairing_url(base_url, link_secret, fingerprint) if link_secret else None,
    )


def close_window(state: State, new_state: WindowState, reason: str = "") -> None:
    window = state.pairing_window
    if window is None or window.state is not WindowState.OPEN:
        return
    window.state = new_state
    state.pairing_window = None
    state.pairing_history.append(window)
    if new_state is not WindowState.USED:
        state.audit(f"pairing_{new_state.value}", window_id=window.id, reason=reason, attempts=window.attempts)


def current_window(state: State, now: float | None = None) -> PairingWindow | None:
    """The open window, expiring it first if its TTL has passed."""
    window = state.pairing_window
    if window is None:
        return None
    now = time.time() if now is None else now
    if now >= window.expires_at:
        close_window(state, WindowState.EXPIRED)
        return None
    return window


class ClaimError(enum.Enum):
    CLOSED = "closed"
    INVALID = "invalid"
    BAD_NAME = "bad_name"


@dataclass
class ClaimResult:
    error: ClaimError | None = None
    device: Device | None = None
    token: str | None = None
    attempts_left: int = 0


def claim(
    state: State,
    *,
    secret: str,
    kind: str,
    device_name: object,
    ip: str | None,
    user_agent: str,
    now: float | None = None,
    allow_model_management: bool = False,
) -> ClaimResult:
    """Try to pair a device. ``kind`` is "code" (typed code) or "link" (URL secret).

    Must stay free of ``await`` so the check-and-consume is atomic on the event loop.
    """
    window = current_window(state, now)
    if window is None:
        return ClaimResult(ClaimError.CLOSED)
    name = clean_device_name(device_name)
    if name is None:
        return ClaimResult(ClaimError.BAD_NAME, attempts_left=window.max_attempts - window.attempts)

    if kind == "code":
        candidates = {"code": _hash(normalize_code(secret))} if len(secret) <= 32 else {}
    else:
        candidates = {m: _hash(secret) for m in ("qr", "link")} if len(secret) <= 64 else {}
    matched = None
    # Compare against every configured secret without short-circuiting.
    for method, stored in window.secret_hashes.items():
        candidate = candidates.get(method)
        if candidate is not None and hmac.compare_digest(stored, candidate):
            matched = method

    ua = user_agent[:200]
    if matched is None:
        window.attempts += 1
        left = window.max_attempts - window.attempts
        state.audit("pairing_failed", ip=ip, window_id=window.id, kind=kind, user_agent=ua, attempts_left=left)
        if left <= 0:
            close_window(state, WindowState.DESTROYED, reason="too many wrong attempts")
        return ClaimResult(ClaimError.INVALID, attempts_left=max(left, 0))

    token = auth.new_device_token()
    device = state.add_device(
        name=name,
        token_hash=auth.hash_token(token),
        token_prefix=auth.display_prefix(token),
        paired_via=matched,
        allow_model_management=allow_model_management,
    )
    state.touch_device(device, ip, None, ua)
    window.device_id = device.id
    close_window(state, WindowState.USED)
    state.audit(
        "pairing_succeeded", ip=ip, device_id=device.id, window_id=window.id, method=matched, user_agent=ua
    )
    return ClaimResult(device=device, token=token)
