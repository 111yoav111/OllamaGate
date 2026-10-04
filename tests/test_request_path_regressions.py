"""Regressions for the request path: queue, IP resolution, body limits, headers, fd limit."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from starlette.requests import Request

from ollamagate.server import runner
from ollamagate.server.body import BodyTooLarge, read_body_limited
from ollamagate.server.netutil import is_trusted, parse_networks, resolve_client_ip
from ollamagate.server.proxy import ProxyStreamResponse
from ollamagate.server.queue import PriorityGate, Ticket
from ollamagate.state import ActiveStream


def test_release_skips_waiter_cancelled_but_not_yet_resumed():
    """A release in the instant after a waiter is cancelled must not raise or strand the queue."""

    async def run() -> None:
        gate = PriorityGate(1)
        held = Ticket()
        await gate.acquire("normal", held)
        gone_ticket, next_ticket = Ticket(), Ticket()
        gone = asyncio.create_task(gate.acquire("high", gone_ticket))
        nxt = asyncio.create_task(gate.acquire("low", next_ticket))
        await asyncio.sleep(0)
        assert gate.queued == 2
        gone.cancel()  # its future is cancelled now; its cleanup runs later
        gate.release(held)  # same tick: must skip it and admit the next waiter
        await asyncio.wait_for(nxt, 1)
        with pytest.raises(asyncio.CancelledError):
            await gone
        assert next_ticket.held and not gone_ticket.held
        assert gate.active == 1 and gate.queued == 0
        gate.release(next_ticket)
        assert gate.active == 0

    asyncio.run(run())


def test_ipv4_mapped_peer_matches_ipv4_trusted_proxy():
    trusted = parse_networks(["127.0.0.1/32", "10.0.0.0/8"])
    assert is_trusted("::ffff:127.0.0.1", trusted)
    headers = httpx.Headers({"x-forwarded-for": "203.0.113.9, ::ffff:10.1.2.3"})
    assert resolve_client_ip("::ffff:127.0.0.1", headers, trusted, "direct") == "203.0.113.9"
    assert not is_trusted("::ffff:192.0.2.1", trusted)
    assert resolve_client_ip("::ffff:192.0.2.1", headers, trusted, "direct") == "::ffff:192.0.2.1"


def _request(content_length: str, body: bytes = b"") -> Request:
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(b"content-length", content_length.encode("latin-1"))],
    }
    return Request(scope, receive)


@pytest.mark.parametrize("value", ["\xb2", "1" * 5000, "-1", "1e3", ""])
def test_malformed_content_length_is_rejected_cleanly(value):
    with pytest.raises(BodyTooLarge):
        asyncio.run(read_body_limited(_request(value), 1024))


def test_valid_content_length_reads_body():
    assert asyncio.run(read_body_limited(_request("2", b"ok"), 1024)) == b"ok"


def test_response_headers_forwarded_as_raw_bytes():
    upstream = httpx.Response(
        200,
        headers=[
            (b"Content-Type", "text/plain; name=été".encode()),
            (b"content-type", b"application/json"),
            (b"x-secret", b"1"),
        ],
    )
    stream = ActiveStream(id="s", device_id="d", method="GET", path="/", started_at=0.0)
    resp = ProxyStreamResponse(upstream, stream, lambda *a: None)
    assert resp._headers() == [(b"content-type", "text/plain; name=été".encode())]


def test_fd_limit_falls_back_when_hard_limit_is_unusable(monkeypatch):
    resource = pytest.importorskip("resource")
    calls = []

    def fake_set(which, limits):
        calls.append(limits)
        if limits[0] > 10240:
            raise ValueError("current limit exceeds maximum limit")

    monkeypatch.setattr(resource, "getrlimit", lambda which: (256, resource.RLIM_INFINITY))
    monkeypatch.setattr(resource, "setrlimit", fake_set)
    runner.raise_fd_limit()
    assert calls == [(65536, resource.RLIM_INFINITY), (10240, resource.RLIM_INFINITY)]


def test_websocket_upgrades_are_disabled(make_config):
    # An upgrade would detach the connection from GuardedH11Protocol and leak
    # its per-IP connection count.
    from ollamagate.server.app import create_app
    from ollamagate.server.runner import build_uvicorn_config
    from ollamagate.state import State

    cfg = make_config("http://127.0.0.1:9")
    assert build_uvicorn_config(cfg, create_app(cfg, State()), None).ws == "none"


def test_new_ip_alerts_group_ipv6_by_64():
    from ollamagate.state import DeviceLimits, State

    state = State()
    device = state.add_device(
        name="p", token_hash="h", token_prefix="p", paired_via="test", limits=DeviceLimits()
    )
    assert state.touch_device(device, "2001:db8::1", 1, "") is False  # pairing IP
    assert state.touch_device(device, "2001:db8::abcd", 1, "") is False  # same /64
    assert state.touch_device(device, "2001:db8:0:1::1", 1, "") is True  # new /64
    assert len(device.ip_history) == 2
