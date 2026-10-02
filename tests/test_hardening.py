"""Hardening regressions: proxy, streams, timeouts and connection limits."""

from __future__ import annotations

import json
import socket
import threading
import time

import httpx
import pytest

from ollamagate.server.policy import EndpointKind, classify_endpoint

from .test_proxy_stream import bearer, wait_for


def _host_port(url: str) -> tuple[str, int]:
    host, port = url.removeprefix("http://").split(":")
    return host, int(port)


def _raw_headers(gate, path: str, body_len: int) -> bytes:
    return (
        f"POST {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {gate.token}\r\n"
        f"Content-Type: application/json\r\nContent-Length: {body_len}\r\n\r\n"
    ).encode()


def test_revoke_during_slow_upload_blocks_request(gate):
    """A token revoked while its request body is still uploading must not reach Ollama."""
    body = json.dumps({"model": "m", "stream": False}).encode()
    with socket.create_connection(_host_port(gate.url), timeout=5) as s:
        s.sendall(_raw_headers(gate, "/api/chat", len(body)) + body[:5])
        assert wait_for(lambda: len(gate.state.streams) == 1)
        gate.call(lambda: gate.state.revoke_device(gate.device.id))
        try:
            s.sendall(body[5:])
        except OSError:
            pass
        reply = s.recv(4096)
    assert reply.split(b" ")[1] in (b"503", b"401")
    assert gate.recorder.requests == []
    assert wait_for(lambda: gate.state.streams == {})


def test_body_timeout(gate_factory):
    gate = gate_factory(**{"server__body_timeout": 0.5})
    with socket.create_connection(_host_port(gate.url), timeout=5) as s:
        s.sendall(_raw_headers(gate, "/api/chat", 100) + b"{")
        reply = s.recv(4096)
    assert reply.split(b" ")[1] == b"408"
    assert gate.recorder.requests == []


def test_slowloris_headers_are_cut_off(gate_factory):
    gate = gate_factory(**{"server__header_timeout": 0.5})
    with socket.create_connection(_host_port(gate.url), timeout=5) as s:
        s.sendall(b"GET /api/tags HTTP/1.1\r\nHost: x\r\n")  # never finishes the headers
        start = time.monotonic()
        assert s.recv(4096) == b""  # server closed the connection
        assert time.monotonic() - start < 3


def test_per_ip_connection_cap(gate_factory):
    gate = gate_factory(**{"server__max_connections_per_ip": 3})
    socks = [socket.create_connection(_host_port(gate.url), timeout=5) for _ in range(3)]
    try:
        extra = socket.create_connection(_host_port(gate.url), timeout=5)
        try:
            extra.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            assert extra.recv(4096) == b""  # refused
        except ConnectionError:
            pass  # also refused (reset on Linux, aborted on Windows)
        finally:
            extra.close()
    finally:
        for s in socks:
            s.close()
    # Slots are released once connections close.
    assert wait_for(lambda: httpx.get(gate.url + "/healthz").status_code == 200)


def test_concurrency_limit(gate_factory, client):
    gate = gate_factory(**{"limits__max_concurrent": 1})
    with client.stream(
        "POST", gate.url + "/api/chat", headers=bearer(gate.token),
        json={"model": "m", "fake_chunks": 100, "fake_delay": 0.05},
    ) as r:
        lines = r.iter_lines()  # keep a reference: a dropped generator closes the connection
        next(lines)
        second = httpx.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "m"})
        assert second.status_code == 429
        assert second.headers["retry-after"] == "1"


def test_kill_with_stalled_reader(gate):
    """A client that stops reading must not keep a killed stream (or Ollama) alive."""
    with socket.create_connection(_host_port(gate.url), timeout=5) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        body = b'{"model": "m"}'
        s.sendall(_raw_headers(gate, "/api/embed", len(body)) + body)
        assert wait_for(lambda: gate.recorder.streams_started == 1)
        time.sleep(0.5)  # let buffers fill up; we never read
        gate.call(lambda: gate.state.revoke_device(gate.device.id))
        assert wait_for(lambda: gate.state.streams == {}, timeout=3)
        assert wait_for(lambda: gate.recorder.streams_aborted == 1, timeout=3)
    assert gate.state.request_log[-1].outcome == "killed"


def test_shutdown_with_active_stream_is_prompt(gate_factory, client):
    gate = gate_factory()
    result = {}

    def consume():
        try:
            with client.stream(
                "POST", gate.url + "/api/chat", headers=bearer(gate.token),
                json={"model": "m", "fake_chunks": 1000, "fake_delay": 0.05},
            ) as r:
                result["lines"] = [line for line in r.iter_lines() if line]
        except httpx.HTTPError as exc:
            result["error"] = exc

    t = threading.Thread(target=consume)
    t.start()
    assert wait_for(lambda: len(gate.state.streams) == 1)
    start = time.monotonic()
    gate.server.should_exit = True  # as Ctrl+C would
    t.join(10)
    assert time.monotonic() - start < 3
    assert json.loads(result["lines"][-1]) == {"error": "stream terminated: server shutting down"}


def test_upstream_error_midway_in_json_is_not_a_clean_response(gate):
    r = httpx.post(gate.url + "/api/show", headers=bearer(gate.token), json={"model": "broken"})
    assert r.status_code == 502 and r.json() == {"error": "upstream unavailable"}
    assert wait_for(lambda: gate.state.streams == {})


def test_host_paths_never_reach_devices(gate, client):
    """Modelfile FROM lines, parent_model and raw Go errors name files on the host."""
    show = client.post(gate.url + "/api/show", headers=bearer(gate.token), json={"model": "m"})
    tags = client.get(gate.url + "/api/tags", headers=bearer(gate.token))
    err = client.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "missing-blob"})
    for r in (show, tags, err):
        assert "/mnt/" not in r.text and "/usr/share" not in r.text and "/srv/" not in r.text and "Users" not in r.text
    assert "FROM m\n" in show.json()["modelfile"] and show.json()["details"]["parent_model"] == ""
    assert show.json()["license"] == "see https://example.com/a/b/LICENSE"
    assert [m["name"] for m in tags.json()["models"]] == ["llama3:8b", "qwen2:7b"]
    assert err.status_code == 500 and err.json() == {"error": "upstream error"}


def test_expired_token_over_http(gate, client):
    gate.call(lambda: gate.state.update_device(gate.device.id, token_expires_at=time.time() - 1))
    assert client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 401


def test_sweep_kills_stream_of_expired_device(gate, client):
    with client.stream(
        "POST", gate.url + "/api/chat", headers=bearer(gate.token),
        json={"model": "m", "fake_chunks": 400, "fake_delay": 0.05},
    ) as r:
        lines = r.iter_lines()
        next(lines)
        gate.call(lambda: gate.state.update_device(gate.device.id, token_expires_at=time.time()))
        start = time.monotonic()
        rest = [line for line in lines if line]
    assert time.monotonic() - start < 2.5  # sweep runs every second
    assert json.loads(rest[-1]) == {"error": "stream terminated: expired"}


@pytest.mark.parametrize("path", ["/api", "/api/", "/healthz/", "/v1"])
def test_no_slash_redirects(gate, client, path):
    r = client.get(gate.url + path, headers={"Host": "evil.example"})
    assert r.status_code in (401, 404)
    assert "location" not in r.headers


def test_audit_fields_truncated(gate, client):
    client.get(gate.url + "/api/" + "a" * 5000)
    entry = gate.state.audit_log[-1]
    assert len(entry.detail["path"]) <= 201


@pytest.mark.parametrize(
    "method,path,expected",
    [
        ("POST", "/api/chat", EndpointKind.INFERENCE),
        ("GET", "/api/chat", None),
        ("HEAD", "/api/tags", None),
        ("POST", "/api/pull", EndpointKind.MANAGEMENT),
        ("POST", "/api/blobs/sha256:" + "a" * 64, EndpointKind.MANAGEMENT),
        ("POST", "/api/blobs/sha256:" + "a" * 63, None),
        ("GET", "/v1/models/llama3:8b", EndpointKind.INFERENCE),
        ("GET", "/v1/models/library/llama3", EndpointKind.INFERENCE),
        ("GET", "/v1/models/.", None),
        ("GET", "/v1/models/..", None),
        ("GET", "/v1/models/x/./y", None),
        ("GET", "/v1/models/x/../../api/pull", None),
        ("GET", "/v1/models/x%2F..%2F..%2Fapi%2Fpull", None),
        ("GET", "/v1/models/x/", None),
        ("GET", "/api/tags/", None),
        ("GET", "/API/tags", None),
    ],
)
def test_classify_endpoint(method, path, expected):
    assert classify_endpoint(method, path) is expected


def test_rotation_grace_period(gate, client):
    from ollamagate.server import auth

    new = auth.new_device_token()
    gate.call(lambda: gate.state.rotate_token(gate.device.id, auth.hash_token(new), "p", grace_seconds=60))
    assert client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 200
    assert client.get(gate.url + "/api/tags", headers=bearer(new)).status_code == 200
    gate.call(lambda: gate.state.sweep(now=time.time() + 61))
    assert client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 401
    assert client.get(gate.url + "/api/tags", headers=bearer(new)).status_code == 200


def test_rotation_without_grace_is_immediate(gate, client):
    from ollamagate.server import auth

    new = auth.new_device_token()
    gate.call(lambda: gate.state.rotate_token(gate.device.id, auth.hash_token(new), "p"))
    assert client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 401
    assert client.get(gate.url + "/api/tags", headers=bearer(new)).status_code == 200


def test_silent_tls_client_is_dropped(fake_ollama, tmp_path, monkeypatch):
    """No ClientHello means no connection_made, so only the handshake timeout bounds it."""
    from ollamagate.config import Config
    from ollamagate.server import runner, tls
    from ollamagate.server.app import create_app
    from ollamagate.state import State

    from .conftest import ThreadedServer

    monkeypatch.setattr(runner, "TLS_HANDSHAKE_TIMEOUT", 0.5)
    cfg = Config()
    cfg.config_dir = tmp_path
    cfg.ollama.url = fake_ollama[0].url
    cert, key = tls.ensure_self_signed(tmp_path / "tls", ["127.0.0.1"])
    state = State()
    server = ThreadedServer(
        server=runner.build_server(cfg, create_app(cfg, state), state, runner.TLSInfo(cert, key, ""))
    ).start()
    try:
        with socket.create_connection(_host_port(server.url.replace("https", "http")), timeout=5) as s:
            start = time.monotonic()
            assert s.recv(1) == b""  # closed by the server
            assert time.monotonic() - start < 3
    finally:
        server.stop()

