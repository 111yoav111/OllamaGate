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


def _on_loop(app, fn):
    import asyncio

    async def run():
        return fn()

    return asyncio.run_coroutine_threadsafe(run(), app.state.loop).result(5)


def _open_window(state, app):
    return _on_loop(
        app, lambda: pairing.open_window(state, base_url="https://x", fingerprint=None, ttl_seconds=60, max_attempts=5)
    )


def _pair(server, state, app, server_cert, name="phone"):
    secrets = _open_window(state, app)
    r = httpx.post(
        f"https://127.0.0.1:{server.port}/pair/claim",
        json={"code": secrets.code, "device_name": name},
        verify=_ctx(server_cert),
    )
    assert r.status_code == 200, r.text
    assert r.headers["connection"] == "close"
    return r.json()


def _refused(url, **kwargs):
    with pytest.raises((httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)):
        httpx.get(url, **kwargs)


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
    # Outside a pairing window, no certificate = no handshake at all.
    _refused(f"{base}/healthz", verify=_ctx(server_cert))
    data = _pair(server, state, app, server_cert)
    cc = data["client_cert"]
    token = data["token"]
    auth_hdr = {"Authorization": f"Bearer {token}"}

    # The .p12 bundle opens with its password and holds the same certificate,
    # whose subject says nothing about the device.
    key, cert, _ = pkcs12.load_key_and_certificates(base64.b64decode(cc["p12"]), cc["p12_password"].encode())
    assert cert.public_bytes(serialization.Encoding.PEM).decode() == cc["cert_pem"]
    assert data["device_id"] not in cert.subject.rfc4514_string()

    ok = _ctx(server_cert, cc["cert_pem"], cc["key_pem"], tmp)
    assert httpx.get(f"{base}/api/tags", headers=auth_hdr, verify=ok).status_code == 200
    assert httpx.get(f"{base}/me", headers=auth_hdr, verify=ok).status_code == 200
    # The certificate alone (no token) is not enough.
    assert httpx.get(f"{base}/api/tags", verify=ok).status_code == 401
    # TLS 1.2 (which would send the certificate in the clear) is refused.
    old = _ctx(server_cert, cc["cert_pem"], cc["key_pem"], tmp)
    old.maximum_version = ssl.TLSVersion.TLSv1_2
    _refused(f"{base}/api/tags", headers=auth_hdr, verify=old)

    # While a pairing window is open, cert-less connections get in, but the token
    # alone still isn't accepted anywhere - and doesn't count toward a ban.
    _open_window(state, app)
    for _ in range(3):
        assert httpx.get(f"{base}/api/tags", headers=auth_hdr, verify=_ctx(server_cert)).status_code == 401
    assert httpx.get(f"{base}/me", headers=auth_hdr, verify=_ctx(server_cert)).status_code == 401
    r = httpx.get(f"{base}/app/session", cookies={"__Host-og_session": token}, verify=_ctx(server_cert))
    assert r.status_code == 401
    assert state.bans.banned("127.0.0.1") is None
    assert any(e.detail.get("reason") == "no_cert" for e in state.audit_log)

    # Another paired device's certificate doesn't unlock this device's token.
    other = _pair(server, state, app, server_cert, name="laptop")["client_cert"]
    wrong = _ctx(server_cert, other["cert_pem"], other["key_pem"], tmp)
    assert httpx.get(f"{base}/api/tags", headers=auth_hdr, verify=wrong).status_code == 401

    # A certificate not issued by this process's CA fails the handshake.
    _refused(f"{base}/api/tags", headers=auth_hdr, verify=_ctx(server_cert, *_foreign_cert(tmp), tmp))


def test_restart_gives_the_ca_a_new_name():
    # Browsers choose a client certificate by issuer name: after a restart they
    # must not offer the old (now unverifiable) one, which would abort the
    # handshake and lock the device out of /pair.
    old, new = tls.ClientCA(), tls.ClientCA()
    assert old.cert.subject != new.cert.subject
    issued = x509.load_pem_x509_certificate(old.issue("phone").cert_pem.encode())
    assert issued.issuer == old.cert.subject != new.cert.subject


def test_failed_issue_leaves_no_device(monkeypatch):
    state, ca = State(), tls.ClientCA()
    secrets = pairing.open_window(state, base_url="https://x", fingerprint=None, ttl_seconds=60, max_attempts=5)
    monkeypatch.setattr(ca, "issue", lambda label: 1 / 0)
    with pytest.raises(ZeroDivisionError):
        pairing.claim(state, secret=secrets.code, kind="code", device_name="p", ip=None, user_agent="", client_ca=ca)
    assert state.list_devices() == []


def test_banned_ip_needs_the_certificate_to_get_through(mtls_gate):
    server, state, app, server_cert, tmp = mtls_gate
    base = f"https://127.0.0.1:{server.port}"
    data = _pair(server, state, app, server_cert)
    cc, hdr = data["client_cert"], {"Authorization": f"Bearer {data['token']}"}
    _on_loop(app, lambda: state.bans.ban("127.0.0.1", "test", None))
    _open_window(state, app)  # so a cert-less connection reaches the app at all
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
