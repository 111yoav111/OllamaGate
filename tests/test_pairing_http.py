from __future__ import annotations

import httpx
import pytest

from ollamagate.server import pairing

from .test_proxy_stream import bearer, wait_for


def open_window(gate, **kw):
    kw.setdefault("ttl_seconds", 300)
    kw.setdefault("max_attempts", 5)
    return gate.call(
        lambda: pairing.open_window(gate.state, base_url=gate.url, fingerprint="ab" * 32, **kw)
    )


@pytest.mark.parametrize("path", ["/pair", "/pair/pair.js", "/pair/pair.css"])
def test_pair_routes_404_when_closed(gate, client, path):
    r = client.get(gate.url + path)
    assert r.status_code == 404 and r.json() == {"error": "not found"}


def test_claim_404_when_closed(gate, client):
    r = client.post(gate.url + "/pair/claim", json={"code": "ABCD-EFGH", "device_name": "x"})
    assert r.status_code == 404 and r.json() == {"error": "not found"}


def test_pairing_page_served_with_strict_csp(gate, client):
    open_window(gate)
    r = client.get(gate.url + "/pair")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "default-src 'none'" in csp and "unsafe" not in csp
    assert "http://" not in r.text and "https://" not in r.text  # no external resources
    assert client.get(gate.url + "/pair/pair.js").status_code == 200


def test_full_code_pairing_flow_then_api_access(gate, client):
    s = open_window(gate)
    r = client.post(
        gate.url + "/pair/claim",
        json={"code": s.code_display, "device_name": "Anna's phone"},
        headers={"User-Agent": "Mozilla/5.0 (iPhone)"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["token"].startswith("og_dev_")
    assert data["fingerprint"] == "ab" * 32
    token = data["token"]
    assert client.get(gate.url + "/api/tags", headers=bearer(token)).status_code == 200
    me = client.get(gate.url + "/me", headers=bearer(token)).json()
    assert me["name"] == "Anna's phone" and me["paired_via"] == "code"
    assert "token_hash" not in me
    # Window is gone.
    assert client.get(gate.url + "/pair").status_code == 404


def test_link_pairing(gate, client):
    s = open_window(gate)
    secret = s.link_url.split("#t=")[1].split("&")[0]
    r = client.post(gate.url + "/pair/claim", json={"secret": secret, "device_name": "laptop"})
    assert r.status_code == 200
    assert gate.state.get_device(r.json()["device_id"]).paired_via == "link"


def test_wrong_code_then_lockout(gate, client):
    s = open_window(gate, max_attempts=3, methods=("code",))
    for left in (2, 1, 0):
        r = client.post(gate.url + "/pair/claim", json={"code": "ZZZZ-ZZZZ", "device_name": "x"})
        assert r.status_code == 403 and r.json()["attempts_left"] == left
    r = client.post(gate.url + "/pair/claim", json={"code": s.code, "device_name": "x"})
    assert r.status_code == 404


def test_per_ip_rate_limit(gate_factory, client):
    gate = gate_factory(**{"pairing__requests_per_minute_per_ip": 3, "pairing__max_attempts": 10})
    open_window(gate, max_attempts=10)
    codes = [client.post(gate.url + "/pair/claim", json={"code": "ZZZZ-ZZZZ", "device_name": "x"}).status_code for _ in range(4)]
    assert codes == [403, 403, 403, 429]


@pytest.mark.parametrize(
    "kwargs,status",
    [
        ({"content": b'{"code":"x","device_name":"y"}', "headers": {"Content-Type": "text/plain"}}, 415),
        ({"json": {"code": "x", "device_name": "y"}, "headers": {"Sec-Fetch-Site": "cross-site"}}, 403),
        ({"content": b"not json", "headers": {"Content-Type": "application/json"}}, 400),
        ({"json": ["x"]}, 400),
        ({"json": {"code": "x", "secret": "y", "device_name": "z"}}, 400),
        ({"json": {"device_name": "z"}}, 400),
        ({"json": {"code": "x" * 5000, "device_name": "z"}}, 413),
    ],
)
def test_malformed_claims(gate, client, kwargs, status):
    open_window(gate)
    r = client.post(gate.url + "/pair/claim", **kwargs)
    assert r.status_code == status
    assert gate.state.pairing_window is not None and gate.state.pairing_window.attempts == 0


def test_bad_device_name(gate, client):
    s = open_window(gate)
    r = client.post(gate.url + "/pair/claim", json={"code": s.code, "device_name": "‮"})
    assert r.status_code == 400


def test_me_requires_token(gate, client):
    assert client.get(gate.url + "/me").status_code == 401
    assert client.get(gate.url + "/me", headers=bearer(gate.token)).json()["name"] == "phone"


def test_new_ip_alert(gate):
    # First contact isn't "new"; a second, different IP is (simulated via state).
    gate.call(lambda: gate.state.touch_device(gate.device, "198.51.100.1", 1, ""))
    assert gate.call(lambda: gate.state.touch_device(gate.device, "198.51.100.2", 1, "")) is True
    assert gate.call(lambda: gate.state.touch_device(gate.device, "198.51.100.2", 1, "")) is False


def test_sweep_expires_window(gate):
    open_window(gate, ttl_seconds=30)
    gate.call(lambda: setattr(gate.state.pairing_window, "expires_at", 0))
    assert wait_for(lambda: gate.state.pairing_window is None, timeout=3)
    assert any(e.event == "pairing_expired" for e in gate.state.audit_log)
    assert httpx.get(gate.url + "/pair").status_code == 404
