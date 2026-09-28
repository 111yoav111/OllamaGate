from __future__ import annotations

import json
import time

import httpx
import pytest


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def wait_for(predicate, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


# ----- zero access without a token ------------------------------------------------


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/tags"),
        ("POST", "/api/chat"),
        ("POST", "/v1/chat/completions"),
        ("GET", "/api/does-not-exist"),
        ("POST", "/api/pull"),
    ],
)
def test_no_token_gets_generic_401(gate, client, method, path):
    r = client.request(method, gate.url + path)
    assert r.status_code == 401
    assert r.json() == {"error": "unauthorized"}
    assert "server" not in r.headers
    assert gate.recorder.requests == []  # nothing reached Ollama


def test_other_paths_404_and_healthz(gate, client):
    for path in ("/", "/docs", "/openapi.json", "/admin", "/pair"):
        r = client.get(gate.url + path)
        assert r.status_code == 404, path
        assert r.json() == {"error": "not found"}
    r = client.get(gate.url + "/healthz")
    assert r.status_code == 200 and r.text == "ok"


def test_wrong_token_is_audited_without_secret(gate, client):
    bad = "og_dev_" + "x" * 43
    r = client.get(gate.url + "/api/tags", headers=bearer(bad))
    assert r.status_code == 401
    entry = gate.state.audit_log[-1]
    assert entry.event == "auth_failed"
    assert bad not in repr(entry)


def test_security_headers(gate, client):
    r = client.get(gate.url + "/healthz")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'none'" in r.headers["content-security-policy"]


# ----- forwarding --------------------------------------------------------------------


def test_forwards_and_strips_headers(gate, client):
    r = client.get(
        gate.url + "/api/version",
        headers={
            **bearer(gate.token),
            "Cookie": "session=abc",
            "X-Forwarded-For": "1.2.3.4",
            "X-Custom": "nope",
            "Accept": "application/json",
        },
    )
    assert r.status_code == 200
    assert r.json() == {"version": "0.0.0-fake"}
    sent = gate.recorder.last["headers"]
    assert "authorization" not in sent
    assert "cookie" not in sent
    assert "x-forwarded-for" not in sent
    assert "x-custom" not in sent
    assert sent["accept"] == "application/json"
    # Upstream response headers other than content-type are not passed back.
    assert "x-upstream-secret" not in r.headers


def test_query_string_not_forwarded(gate, client):
    client.get(gate.url + "/api/tags?x=1", headers=bearer(gate.token))
    assert gate.recorder.last["query"] == ""


def test_unknown_endpoint_404_for_authenticated(gate, client):
    r = client.get(gate.url + "/api/internal", headers=bearer(gate.token))
    assert r.status_code == 404
    r = client.get(gate.url + "/api/../api/tags", headers=bearer(gate.token))
    assert r.status_code in (200, 404)
    assert all(req["path"] != "/api/internal" for req in gate.recorder.requests)


def test_management_blocked_by_default(gate, client):
    r = client.post(gate.url + "/api/pull", headers=bearer(gate.token), json={"model": "x"})
    assert r.status_code == 403
    r = client.request("DELETE", gate.url + "/api/delete", headers=bearer(gate.token), json={"model": "x"})
    assert r.status_code == 403
    assert gate.recorder.requests == []


def test_management_allowed_when_granted(gate, client):
    token, _ = gate.new_device("admin-laptop", allow_model_management=True)
    r = client.post(gate.url + "/api/pull", headers=bearer(token), json={"model": "x"})
    assert r.status_code == 200


def test_body_size_limit(gate_factory, client):
    gate = gate_factory(**{"server__max_body_bytes": 1024})
    r = client.post(gate.url + "/api/chat", headers=bearer(gate.token), content=b"x" * 2048)
    assert r.status_code == 413

    def chunks():
        for _ in range(4):
            yield b"y" * 512

    r = client.post(gate.url + "/api/chat", headers=bearer(gate.token), content=chunks())
    assert r.status_code == 413
    assert gate.recorder.requests == []


def test_streaming_ndjson_passthrough(gate, client):
    with client.stream(
        "POST", gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "m", "fake_chunks": 5, "fake_delay": 0.05}
    ) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/x-ndjson")
        first_at = None
        start = time.monotonic()
        lines = []
        for line in r.iter_lines():
            if line and first_at is None:
                first_at = time.monotonic() - start
            if line:
                lines.append(json.loads(line))
    assert len(lines) == 6 and lines[-1]["done"] is True
    # The first chunk arrives long before the whole (~0.3s) response is done: no buffering.
    assert first_at is not None and first_at < 0.2
    assert wait_for(lambda: len(gate.state.request_log) == 1)
    assert gate.state.request_log[-1].outcome == "complete"
    assert gate.state.streams == {}


def test_non_streaming_json(gate, client):
    r = client.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "m", "stream": False})
    assert r.status_code == 200 and r.json()["done"] is True


def test_openai_sse_passthrough(gate, client):
    with client.stream(
        "POST", gate.url + "/v1/chat/completions", headers=bearer(gate.token), json={"model": "m", "stream": True}
    ) as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        body = r.read().decode()
    assert body.endswith("data: [DONE]\n\n")


def test_client_disconnect_cancels_upstream(gate, client):
    rec = gate.recorder
    with client.stream(
        "POST",
        gate.url + "/api/chat",
        headers=bearer(gate.token),
        json={"model": "m", "fake_chunks": 200, "fake_delay": 0.05},
    ) as r:
        next(r.iter_lines())
    # Closing the client connection must abort the upstream generation.
    assert wait_for(lambda: rec.streams_aborted == 1, timeout=3)
    assert rec.streams_completed == 0
    assert wait_for(lambda: gate.state.streams == {})
    assert gate.state.request_log[-1].outcome == "client_disconnect"


def test_revoke_kills_active_stream_within_a_second(gate, client):
    with client.stream(
        "POST",
        gate.url + "/api/chat",
        headers=bearer(gate.token),
        json={"model": "m", "fake_chunks": 400, "fake_delay": 0.05},
    ) as r:
        lines = r.iter_lines()
        next(lines)
        killed_at = time.monotonic()
        gate.call(lambda: gate.state.revoke_device(gate.device.id))
        rest = [line for line in lines if line]
        elapsed = time.monotonic() - killed_at
    assert elapsed < 1.0
    assert json.loads(rest[-1]) == {"error": "stream terminated: revoked"}
    assert wait_for(lambda: gate.recorder.streams_aborted == 1)
    assert client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 401


def test_kill_before_first_byte(gate, client):
    """A request still waiting on Ollama (e.g. a model loading) is also cut off."""
    import threading

    result: dict = {}

    def do_request():
        result["r"] = client.post(
            gate.url + "/api/chat",
            headers=bearer(gate.token),
            json={"model": "m", "stream": False, "fake_first_delay": 5},
        )
        result["done_at"] = time.monotonic()

    t = threading.Thread(target=do_request)
    t.start()
    assert wait_for(lambda: len(gate.state.streams) == 1)
    killed_at = time.monotonic()
    gate.call(lambda: gate.state.kill_device_streams(gate.device.id, "kicked"))
    t.join(5)
    assert result["done_at"] - killed_at < 1.0
    assert result["r"].status_code == 503
    assert result["r"].json() == {"error": "request terminated: kicked"}
    assert wait_for(lambda: gate.state.streams == {})


def test_upstream_down_returns_502(make_config, client):
    import socket

    from ollamagate.server import auth
    from ollamagate.server.app import create_app
    from ollamagate.state import State

    from .conftest import ThreadedServer

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()
    cfg = make_config(f"http://127.0.0.1:{dead_port}")
    state = State()
    token = auth.new_device_token()
    state.add_device(name="d", token_hash=auth.hash_token(token), token_prefix="p", paired_via="t")
    server = ThreadedServer(create_app(cfg, state)).start()
    try:
        r = client.get(server.url + "/api/tags", headers=bearer(token))
        assert r.status_code == 502
        assert r.json() == {"error": "upstream unavailable"}
    finally:
        server.stop()


def test_suspended_device_403(gate, client):
    from ollamagate.state import DeviceStatus

    gate.device.status = DeviceStatus.SUSPENDED
    r = client.get(gate.url + "/api/tags", headers=bearer(gate.token))
    assert r.status_code == 403


def test_device_touch_records_ip_and_ua(gate, client):
    client.get(gate.url + "/api/tags", headers={**bearer(gate.token), "User-Agent": "Enchanted/1.0"})
    assert gate.device.last_ip == "127.0.0.1"
    assert gate.device.user_agent == "Enchanted/1.0"
    assert gate.device.last_seen is not None


def test_bogus_content_length(gate):
    import socket

    host, port = gate.url.removeprefix("http://").split(":")
    raw = (
        f"POST /api/chat HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {gate.token}\r\n"
        "Content-Length: abc\r\n\r\n"
    ).encode()
    with socket.create_connection((host, int(port)), timeout=5) as s:
        s.sendall(raw)
        reply = s.recv(4096)
    # Either uvicorn rejects it at the HTTP layer or we do; it never reaches Ollama.
    assert reply.split(b" ")[1] in (b"400", b"413")
    assert gate.recorder.requests == []
