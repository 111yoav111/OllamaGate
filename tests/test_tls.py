from __future__ import annotations

import socket
import ssl

import httpx

from ollamagate.server import tls

from .conftest import ThreadedServer
from .fake_ollama import make_fake_ollama


def test_self_signed_generation_and_permissions(tmp_path):
    cert, key = tls.ensure_self_signed(tmp_path, ["localhost", "127.0.0.1"])
    assert cert.exists() and key.exists()
    if hasattr(key, "stat"):
        assert key.stat().st_mode & 0o077 == 0
    fp = tls.cert_fingerprint(cert)
    assert len(fp) == 64
    # Stable across calls when nothing changed.
    tls.ensure_self_signed(tmp_path, ["localhost", "127.0.0.1"])
    assert tls.cert_fingerprint(cert) == fp
    # A new SAN triggers regeneration.
    tls.ensure_self_signed(tmp_path, ["localhost", "127.0.0.1", "gate.example"])
    assert tls.cert_fingerprint(cert) != fp


def test_server_context_enforces_tls12_minimum(tmp_path):
    cert, key = tls.ensure_self_signed(tmp_path, ["127.0.0.1"])
    app, _ = make_fake_ollama()
    server = ThreadedServer(app, ssl_context=tls.build_server_context(cert, key)).start()
    try:
        # Pinning by fingerprint works: verify the presented cert matches.
        ctx = ssl.create_default_context(cafile=str(cert))
        with socket.create_connection(("127.0.0.1", server.port)) as raw:
            with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
                import hashlib

                assert hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest() == tls.cert_fingerprint(cert)
                assert s.version() in ("TLSv1.2", "TLSv1.3")
        # TLS 1.1 is refused.
        old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        old.check_hostname = False
        old.verify_mode = ssl.CERT_NONE
        try:
            old.minimum_version = ssl.TLSVersion.TLSv1
            old.maximum_version = ssl.TLSVersion.TLSv1_1
        except ValueError:
            return
        with socket.create_connection(("127.0.0.1", server.port)) as raw:
            try:
                old.wrap_socket(raw, server_hostname="127.0.0.1")
            except ssl.SSLError:
                pass
            else:
                raise AssertionError("TLS 1.1 handshake unexpectedly succeeded")
        r = httpx.get(f"https://127.0.0.1:{server.port}/api/tags", verify=ssl.create_default_context(cafile=str(cert)))
        assert r.status_code == 200
    finally:
        server.stop()
