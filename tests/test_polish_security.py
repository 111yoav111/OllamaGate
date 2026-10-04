"""Regression tests for the security polish pass."""

from __future__ import annotations

import os
import ssl
import stat
import sys
import time

import pytest
from cryptography import x509

from ollamagate.admin import ipc
from ollamagate.admin.ipc import AdminError
from ollamagate.admin.service import Admin
from ollamagate.config import Config
from ollamagate.server import tls
from ollamagate.server.policy import EndpointKind, apply_body_policy, classify_endpoint
from ollamagate.state import DeviceLimits, State


def test_model_path_check_has_no_catastrophic_backtracking():
    # The old single regex took seconds at 20 characters and grew exponentially.
    for path in ("/v1/models/" + "a" * 240 + "!", "/v1/models/" + "a/" * 7 + "a" * 200 + "!"):
        started = time.monotonic()
        assert classify_endpoint("GET", path) is None
        assert time.monotonic() - started < 0.5


@pytest.mark.parametrize(
    "path, ok",
    [
        ("/v1/models/llama3:8b", True),
        ("/v1/models/library/llama3:8b", True),
        ("/v1/models/a/b/c/d/e/f/g/h", True),
        ("/v1/models/a/b/c/d/e/f/g/h/i", False),  # more than 8 segments
        ("/v1/models/", False),
        ("/v1/models/llama3/", False),
        ("/v1/models//llama3", False),
        ("/v1/models/./llama3", False),
        ("/v1/models/../api/pull", False),
        ("/v1/models/a..b", False),
        ("/v1/models/llama3\n", False),  # "$" would have accepted a decoded %0A
        ("/v1/models/llama 3", False),
        ("/v1/models/" + "a" * 246, False),  # over 256 characters
    ],
)
def test_model_path_classification(path, ok):
    assert (classify_endpoint("GET", path) is EndpointKind.INFERENCE) is ok


def test_blob_path_rejects_trailing_newline():
    blob = "/api/blobs/sha256:" + "0" * 64
    assert classify_endpoint("HEAD", blob) is EndpointKind.MANAGEMENT
    assert classify_endpoint("HEAD", blob + "\n") is None


def test_json_key_with_trailing_newline_is_not_plain():
    result = apply_body_policy(DeviceLimits(), "/api/chat", b'{"model": "llama3", "stream\\n": false}')
    assert result.error == "request keys must be lowercase field names"


def test_client_cert_chain_has_key_identifiers():
    ca = tls.ClientCA()
    cert = x509.load_pem_x509_certificate(ca.issue("phone").cert_pem.encode())
    ca_ski = ca.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert aki.key_identifier == ca_ski.digest
    cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)


def test_server_context_refuses_renegotiation(tmp_path):
    if not hasattr(ssl, "OP_NO_RENEGOTIATION"):
        pytest.skip("ssl module has no OP_NO_RENEGOTIATION")
    cert, key = tls.ensure_self_signed(tmp_path, ["localhost"])
    assert tls.build_server_context(cert, key).options & ssl.OP_NO_RENEGOTIATION


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "::ffff:127.0.0.1", "::2"])
def test_ban_refuses_anything_that_covers_loopback(ip):
    # Bans apply to client_key(ip): the IPv4 behind a mapped address, an IPv6 /64.
    admin = Admin(State(), Config(), None)
    with pytest.raises(AdminError, match="loopback"):
        admin.add_ban(ip)
    assert admin.list_bans() == []


def test_ban_still_accepts_ordinary_addresses():
    admin = Admin(State(), Config(), None)
    assert admin.add_ban("2001:db8::5")["key"] == "2001:db8::/64"
    assert admin.add_ban("::ffff:198.51.100.7")["key"] == "198.51.100.7"


@pytest.mark.parametrize("key, value", [("pairing.ttl_seconds", "--5"), ("pairing.ttl_seconds", "1-2"), (["x"], 1)])
def test_bad_setting_input_is_an_admin_error(key, value):
    # These used to escape as ValueError/TypeError ("internal error" on the CLI).
    with pytest.raises(AdminError):
        Admin(State(), Config(), None).set_setting(key, value)


def test_setting_accepts_padded_integer():
    assert Admin(State(), Config(), None).set_setting("pairing.ttl_seconds", " 90 ")["pairing.ttl_seconds"] == 90


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_run_dir_is_created_private(tmp_path):
    old = os.umask(0o022)
    try:
        rdir = ipc.run_dir(tmp_path)
        ipc._private_dir(rdir)
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(rdir).st_mode) == 0o700
