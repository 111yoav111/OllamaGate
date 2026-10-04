"""TLS: self-signed certificate generation, fingerprints and the server SSL context."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import secrets
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

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
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
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
    return list(dict.fromkeys(n for n in names if n and n not in ("0.0.0.0", "::")))


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


def build_server_context(cert_path: Path, key_path: Path, client_ca_pem: str | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    # Client-initiated TLS 1.2 renegotiation is a cheap CPU DoS (OpenSSL 1.1.1 allows it).
    ctx.options |= getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    # TLS 1.2 is limited to forward-secret AEAD suites; TLS 1.3 suites are always strong.
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.load_cert_chain(str(cert_path), str(key_path))
    if client_ca_pem:
        # Connections without one of our client certificates are refused at the
        # handshake; ClientCA.set_pairing_open relaxes that while a pairing window
        # is open, so a new device can reach /pair. Which device a certificate
        # belongs to is checked per request in auth.authenticate.
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=client_ca_pem)
        # TLS 1.3 encrypts the client certificate (1.2 sends it in the clear, which
        # would let anyone on the path track a device). No session tickets: a
        # session resumed from a pairing window would skip the certificate check.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.num_tickets = 0
    return ctx


def peer_cert_fingerprint(ssl_object: ssl.SSLObject | None) -> str | None:
    """SHA-256 of the verified client certificate on a TLS connection, if any."""
    der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
    return hashlib.sha256(der).hexdigest() if der else None


@dataclass
class ClientCert:
    cert_pem: str
    key_pem: str
    p12: bytes  # cert + key for phones/browsers, encrypted with p12_password
    p12_password: str
    fingerprint: str  # sha256 hex of the DER certificate


CLIENT_CERT_DAYS = 397
_P12_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32: easy to type


class ClientCA:
    """In-memory CA that signs one client certificate per paired device (mTLS).

    Its key never touches disk and dies with the process. That matches the
    in-memory device list: after a restart every device must pair again anyway,
    and every certificate issued before the restart stops working.
    """

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.context: ssl.SSLContext | None = None  # the live server context (set by the runner)
        # A new name per start: browsers pick which certificate to send by issuer
        # name, so they must not offer one from before a restart. It would fail
        # verification and abort the handshake, locking the device out of /pair.
        cn = f"OllamaGate device CA {secrets.token_hex(4)}"
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = dt.datetime.now(dt.timezone.utc)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=CLIENT_CERT_DAYS + 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            # Key identifiers: strict X.509 verification (OpenSSL's X509_STRICT, which
            # newer Pythons enable by default) rejects a chain without them.
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._key, hashes.SHA256())
        )
        self.pem = self.cert.public_bytes(serialization.Encoding.PEM).decode()

    def set_pairing_open(self, is_open: bool) -> None:
        """Accept handshakes without a client certificate only while pairing is open."""
        if self.context is not None:
            self.context.verify_mode = ssl.CERT_OPTIONAL if is_open else ssl.CERT_REQUIRED

    def issue(self, label: str) -> ClientCert:
        """A certificate for one device. ``label`` only names the .p12 on the device."""
        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.timezone.utc)
        # A random subject: nothing in the certificate identifies the device.
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, secrets.token_hex(8))])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=CLIENT_CERT_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()), critical=False
            )
            .sign(self._key, hashes.SHA256())
        )
        password = "-".join("".join(secrets.choice(_P12_ALPHABET) for _ in range(4)) for _ in range(4))
        # Legacy PKCS#12 encryption on purpose: iOS/macOS and older Android refuse the
        # AES/PBKDF2 variant. The password is random (80 bits), so this is only a wrapper.
        encryption = (
            serialization.PrivateFormat.PKCS12.encryption_builder()
            .kdf_rounds(50000)
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
            .hmac_hash(hashes.SHA1())
            .build(password.encode())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        return ClientCert(
            cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
            key_pem=key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ).decode(),
            p12=pkcs12.serialize_key_and_certificates(
                f"OllamaGate {label} {now:%Y-%m-%d}".encode(), key, cert, None, encryption
            ),
            p12_password=password,
            fingerprint=hashlib.sha256(der).hexdigest(),
        )


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
