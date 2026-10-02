"""The /app browser chat: cookie sessions and CSRF."""

from __future__ import annotations

import httpx
import pytest

from ollamagate.server import auth, pairing

COOKIE = auth.SESSION_COOKIE  # "__Host-og_session"


def browser_with_cookie(gate, token: str) -> httpx.Client:
    """A client that sends the session cookie like a browser would.

    The cookie is Secure (and __Host-), so httpx's cookie jar won't send it over
    the tests' plain http; browsers do send it to localhost / over HTTPS.
    """
    return httpx.Client(base_url=gate.url, timeout=10, headers={"Cookie": f"{COOKIE}={token}"})


def pair_browser(gate) -> tuple[httpx.Client, str, httpx.Response]:
    s = gate.call(lambda: pairing.open_window(gate.state, base_url=gate.url, fingerprint=None, ttl_seconds=60, max_attempts=5))
    r = httpx.post(gate.url + "/pair/claim", json={"code": s.code, "device_name": "browser"})
    assert r.status_code == 200
    token = r.json()["token"]
    return browser_with_cookie(gate, token), token, r


def test_claim_sets_strict_secure_host_cookie(gate):
    _, token, r = pair_browser(gate)
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"__Host-og_session={token}")
    for flag in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/"):
        assert flag in cookie
    assert "Domain" not in cookie  # required by the __Host- prefix
    assert r.json()["app_url"] == "/app"


@pytest.mark.parametrize("path", ["/app", "/app/app.js", "/app/app.css", "/app/session"])
def test_app_requires_session(gate, client, path):
    r = client.get(gate.url + path)
    if path == "/app":  # people land here after a restart or sign-out: tell them what to do
        assert r.status_code == 401 and "text/html" in r.headers["content-type"] and "open pairing" in r.text
        assert "<script" not in r.text
    else:
        assert r.status_code == 401 and r.json() == {"error": "unauthorized"}
    # A bearer token doesn't open the browser app either (it's cookie-only).
    assert client.get(gate.url + path, headers={"Authorization": f"Bearer {gate.token}"}).status_code == 401


def test_old_cookie_name_is_ignored(gate):
    _, token, _ = pair_browser(gate)
    legacy = httpx.Client(base_url=gate.url, headers={"Cookie": f"og_session={token}"})
    assert legacy.get("/app").status_code == 401


def test_app_served_with_strict_csp(gate):
    browser, _, _ = pair_browser(gate)
    r = browser.get("/app")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe" not in csp
    assert "https://" not in r.text and "http://" not in r.text


def test_cookie_needs_matching_csrf_header(gate):
    browser, token, _ = pair_browser(gate)
    assert browser.get("/api/tags").status_code == 401  # cookie alone is not enough
    assert browser.get("/api/tags", headers={"X-OllamaGate-CSRF": "0" * 32}).status_code == 401
    csrf = browser.get("/app/session").json()["csrf"]
    assert csrf == auth.csrf_token(gate.state.csrf_key, token)
    assert browser.get("/api/tags", headers={"X-OllamaGate-CSRF": csrf}).status_code == 200
    r = browser.post("/api/chat", headers={"X-OllamaGate-CSRF": csrf}, json={"model": "m", "stream": False})
    assert r.status_code == 200
    assert browser.get("/me", headers={"X-OllamaGate-CSRF": csrf}).json()["name"] == "browser"


def test_csrf_token_is_bound_to_the_session(gate):
    a, _, _ = pair_browser(gate)
    b, _, _ = pair_browser(gate)
    csrf_a = a.get("/app/session").json()["csrf"]
    assert b.get("/api/tags", headers={"X-OllamaGate-CSRF": csrf_a}).status_code == 401


def test_revoke_ends_browser_session(gate):
    browser, _, r = pair_browser(gate)
    device_id = r.json()["device_id"]
    gate.call(lambda: gate.state.revoke_device(device_id))
    assert browser.get("/app").status_code == 401
    assert browser.get("/app/session").status_code == 401


def test_logout_clears_cookie_and_needs_csrf(gate):
    browser, _, _ = pair_browser(gate)
    assert browser.post("/app/logout").status_code == 401  # no CSRF header
    csrf = browser.get("/app/session").json()["csrf"]
    r = browser.post("/app/logout", headers={"X-OllamaGate-CSRF": csrf})
    assert r.status_code == 200
    assert r.headers["set-cookie"].startswith("__Host-og_session=;") and "Max-Age=0" in r.headers["set-cookie"]


def test_stale_cookie_failures_do_not_ban(gate_factory):
    gate = gate_factory(**{"network__trusted_proxies": ["127.0.0.1/32"], "bans__failures": 3})
    stale = browser_with_cookie(gate, "og_dev_" + "x" * 43)
    for _ in range(10):
        assert stale.get("/api/tags", headers={"X-Forwarded-For": "198.51.100.90"}).status_code == 401
    assert gate.state.bans.banned("198.51.100.90") is None


def test_lockdown_closes_app(gate):
    from ollamagate.admin.service import Admin

    browser, _, _ = pair_browser(gate)
    gate.call(lambda: Admin(gate.state, gate.app.state.config, None).set_lockdown(True))
    assert browser.get("/app").status_code in (401, 503)
