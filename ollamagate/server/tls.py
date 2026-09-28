"""TLS: self-signed certificate generation, fingerprints and the server SSL context."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import socket
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CERT_NAME = "cert.pem"
KEY_NAME = "key.pem"
VALIDITY_DAYS = 825
RENEW_BEFORE_DAYS = 30


def _write_private(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` readable by the owner only (0600 on POSIX)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.unlink()  # a stale temp file could carry looser permissions
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _san_entries(names: list[str]) -> list[x509.GeneralName]:
    entries: list[x509.GeneralName] = []
    seen: set[str] = set()
    for name in names:
        name = name.strip().strip("[]")
        if not name or name in seen or name in ("0.0.0.0", "::"):
            continue
        seen.add(name)
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            entries.append(x509.DNSName(name))
    return entries


def generate_self_signed(cert_path: Path, key_path: Path, sans: list[str]) -> None:
    """Create an ECDSA P-256 self-signed certificate valid for ``sans``."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OllamaGate")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(_san_entries(sans)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # Remove the old pair first: a crash midway then leaves "no cert", which
    # triggers regeneration, never a mismatched key/cert pair.
    for p in (cert_path, key_path):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    _write_private(key_path, key_pem)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def default_sans(host: str, extra: list[str]) -> list[str]:
    names = ["localhost", "127.0.0.1", "::1", socket.gethostname(), host, *extra]
    return [n for n in names if n]


def _needs_renewal(cert_path: Path, sans: list[str]) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (OSError, ValueError):
        return True
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:  # cryptography < 42 returns a naive UTC datetime
        not_after = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    remaining = not_after - dt.datetime.now(dt.timezone.utc)
    if remaining < dt.timedelta(days=RENEW_BEFORE_DAYS):
        return True
    try:
        present = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return True
    wanted = set(_san_entries(sans))
    return not wanted.issubset(set(present))


def ensure_self_signed(tls_dir: Path, sans: list[str]) -> tuple[Path, Path]:
    """Return (cert, key) paths, generating or renewing the certificate if needed."""
    cert_path, key_path = tls_dir / CERT_NAME, tls_dir / KEY_NAME
    tls_dir.mkdir(parents=True, exist_ok=True)
    if not key_path.exists() or _needs_renewal(cert_path, sans):
        generate_self_signed(cert_path, key_path, sans)
    return cert_path, key_path


def cert_fingerprint(cert_path: Path) -> str:
    """SHA-256 fingerprint of the certificate's DER encoding, lowercase hex."""
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def format_fingerprint(fp_hex: str) -> str:
    return ":".join(fp_hex[i : i + 2] for i in range(0, len(fp_hex), 2)).upper()


def build_server_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    # TLS 1.2 is limited to forward-secret AEAD suites; TLS 1.3 suites are always strong.
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


class CertReloader:
    """Reload a renewed certificate into a live SSL context.

    Let's Encrypt and Tailscale certificates are renewed every few weeks. Loading
    the new files into the *same* SSLContext makes new connections use them
    without restarting (a restart would disconnect every device, since all
    state is in memory).
    """

    def __init__(self, ctx: ssl.SSLContext, cert_path: Path, key_path: Path) -> None:
        self.ctx = ctx
        self.cert_path = cert_path
        self.key_path = key_path
        self._stamp = self._current_stamp()

    def _current_stamp(self) -> tuple[float, float] | None:
        try:
            return (self.cert_path.stat().st_mtime, self.key_path.stat().st_mtime)
        except OSError:
            return None

    def check(self) -> bool:
        """Reload if the files changed. Returns True when a new certificate was loaded."""
        stamp = self._current_stamp()
        if stamp is None or stamp == self._stamp:
            return False
        try:
            # Validate the pair on a throwaway context first: a failed load_cert_chain
            # can leave the live context half-updated and break every new handshake.
            build_server_context(self.cert_path, self.key_path)
            self.ctx.load_cert_chain(str(self.cert_path), str(self.key_path))
        except (OSError, ssl.SSLError):
            return False  # half-written or mismatched pair: keep the old one, retry later
        self._stamp = stamp
        return True
