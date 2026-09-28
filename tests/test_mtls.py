"""mTLS: a client certificate issued at pairing, required with the token."""

from __future__ import annotations

import base64
import datetime as dt
import ssl

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from ollamagate.config import Config, ConfigError
from ollamagate.server import pairing, tls
from ollamagate.server.app import create_app
from ollamagate.server.runner import TLSInfo, build_server
from ollamagate.state import State

from .conftest import ThreadedServer


@pytest.fixture
def mtls_gate(fake_ollama, tmp_path):
    upstream, _ = fake_ollama
    cfg = Config()
    cfg.config_dir = tmp_path
    cfg.ollama.url = upstream.url
    cfg.tls.client_certs = True
    cfg.validate()
    cert, key = tls.ensure_self_signed(tmp_path / "tls", ["127.0.0.1"])
    state, ca = State(), tls.ClientCA()
    app = create_app(cfg, state, client_ca=ca)
    server = ThreadedServer(server=build_server(cfg, app, state, TLSInfo(cert, key, ""), client_ca=ca)).start()
    yield server, state, app, cert, tmp_path
    server.stop()


def _ctx(server_cert, cert_pem=None, key_pem=None, tmp=None):
    ctx = ssl.create_default_context(cafile=str(server_cert))
    if cert_pem:
        (tmp / "c.pem").write_text(cert_pem)
        (tmp / "k.pem").write_text(key_pem)
        ctx.load_cert_chain(tmp / "c.pem", tmp / "k.pem")
    return ctx


def _pair(server, state, app, server_cert, name="phone"):
    import asyncio

    async def open_window():
        return pairing.open_window(state, base_url="https://x", fingerprint=None, ttl_seconds=60, max_attempts=5)

    secrets = asyncio.run_coroutine_threadsafe(open_window(), app.state.loop).result(5)
    r = httpx.post(
        f"https://127.0.0.1:{server.port}/pair/claim",
        json={"code": secrets.code, "device_name": name},
        verify=_ctx(server_cert),
    )
    assert r.status_code == 200, r.text
    return r.json()


def _foreign_cert(tmp):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
    )


def test_mtls_end_to_end(mtls_gate):
    server, state, app, server_cert, tmp = mtls_gate
    base = f"https://127.0.0.1:{server.port}"
    # Pairing and health work without a client certificate.
    assert httpx.get(f"{base}/healthz", verify=_ctx(server_cert)).status_code == 200
    data = _pair(server, state, app, server_cert)
    cc = data["client_cert"]
    token = data["token"]
    auth_hdr = {"Authorization": f"Bearer {token}"}

    # The .p12 bundle opens with its password and holds the same certificate.
    key, cert, _ = pkcs12.load_key_and_certificates(base64.b64decode(cc["p12"]), cc["p12_password"].encode())
    assert cert.public_bytes(serialization.Encoding.PEM).decode() == cc["cert_pem"]

    ok = _ctx(server_cert, cc["cert_pem"], cc["key_pem"], tmp)
    assert httpx.get(f"{base}/api/tags", headers=auth_hdr, verify=ok).status_code == 200
    assert httpx.get(f"{base}/me", headers=auth_hdr, verify=ok).status_code == 200

    # Token without the certificate: generic 401.
    r = httpx.get(f"{base}/api/tags", headers=auth_hdr, verify=_ctx(server_cert))
    assert r.status_code == 401
    assert httpx.get(f"{base}/me", headers=auth_hdr, verify=_ctx(server_cert)).status_code == 401
    # Browser session cookie without the certificate: 401 too.
    r = httpx.get(f"{base}/app/session", cookies={"__Host-og_session": token}, verify=_ctx(server_cert))
    assert r.status_code == 401

    # Another paired device's certificate doesn't unlock this device's token.
    other = _pair(server, state, app, server_cert, name="laptop")["client_cert"]
    wrong = _ctx(server_cert, other["cert_pem"], other["key_pem"], tmp)
    assert httpx.get(f"{base}/api/tags", headers=auth_hdr, verify=wrong).status_code == 401
    # The certificate alone (no token) is not enough either.
    assert httpx.get(f"{base}/api/tags", verify=ok).status_code == 401

    # A certificate not issued by our CA fails the TLS handshake.
    with pytest.raises((httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)):
        httpx.get(f"{base}/api/tags", headers=auth_hdr, verify=_ctx(server_cert, *_foreign_cert(tmp), tmp)).raise_for_status()


def test_banned_ip_needs_the_certificate_to_get_through(mtls_gate):
    server, state, app, server_cert, tmp = mtls_gate
    base = f"https://127.0.0.1:{server.port}"
    data = _pair(server, state, app, server_cert)
    cc, hdr = data["client_cert"], {"Authorization": f"Bearer {data['token']}"}
    import asyncio

    async def ban():
        state.bans.ban("127.0.0.1", "test", None)

    asyncio.run_coroutine_threadsafe(ban(), app.state.loop).result(5)
    assert httpx.get(f"{base}/api/tags", headers=hdr, verify=_ctx(server_cert)).status_code == 403
    ok = _ctx(server_cert, cc["cert_pem"], cc["key_pem"], tmp)
    assert httpx.get(f"{base}/api/tags", headers=hdr, verify=ok).status_code == 200


@pytest.mark.parametrize("section,key,value", [("tls", "mode", "off"), ("network", "mode", "cloudflare")])
def test_client_certs_need_our_own_tls(section, key, value):
    cfg = Config()
    cfg.tls.client_certs = True
    cfg.network.trusted_proxies = ["127.0.0.1/32"]
    setattr(getattr(cfg, section), key, value)
    with pytest.raises(ConfigError, match="client_certs"):
        cfg.validate()
