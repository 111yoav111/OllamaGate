"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import json
from dataclasses import asdict
import logging
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.datastructures import Headers
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import ClientDisconnect
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..config import Config
from ..state import RequestLogEntry, State
from ..textsafe import safe_text
from . import auth, pairing
from .body import BodyTooLarge, read_body_limited
from .netutil import parse_networks, resolve_client_ip
from .protocol import CLIENT_CERT_SCOPE
from .tls import ClientCA
from .app_routes import register_app_routes
from .pairing_routes import register_pairing_routes
from .policy import (
    ACCOUNTED_ENDPOINTS,
    EndpointKind,
    apply_body_policy,
    classify_endpoint,
    filter_model_list,
    model_allowed,
)
from .queue import PriorityGate, Ticket
from .usage import UsageCounter
from .proxy import (
    ClientGone,
    ProxyStreamResponse,
    StreamKilled,
    build_upstream_headers,
    monotonic_ms,
    open_upstream,
    race_kill,
)

log = logging.getLogger("ollamagate.app")

PROXY_METHODS = ["GET", "POST", "DELETE", "HEAD"]
SWEEP_INTERVAL = 1.0


def error(status: int, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, headers=headers)


MAX_LISTING_BYTES = 2 * 1024 * 1024


def seconds_until_midnight() -> int:
    now = datetime.datetime.now()
    tomorrow = (now + datetime.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int((tomorrow - now).total_seconds())


def seconds_until_next_month() -> int:
    now = datetime.datetime.now()
    first = (now.replace(day=28) + datetime.timedelta(days=4)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return int((first - now).total_seconds())


async def read_capped(response: httpx.Response, limit: int) -> bytes:
    data = bytearray()
    async for chunk in response.aiter_raw():
        data += chunk
        if len(data) > limit:
            raise httpx.ReadError("upstream listing too large")
    return bytes(data)


def forbidden() -> JSONResponse:
    return error(403, "forbidden")


def lockdown_response() -> JSONResponse:
    return error(503, "server unavailable", {"Retry-After": "300"})


def requested_model(body: bytes) -> str:
    """Best-effort model name from a JSON request body, for display only."""
    if not body.startswith(b"{"):
        return ""
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return ""
    model = data.get("model") if isinstance(data, dict) else None
    return safe_text(model, 100) if isinstance(model, str) else ""


def unauthorized() -> JSONResponse:
    # Deliberately generic: no hint about why, no server/version info.
    return error(401, "unauthorized", {"WWW-Authenticate": "Bearer"})


class BanMiddleware:
    """Refuse requests from banned clients before any routing happens.

    A request carrying a valid device credential still gets through: bans exist
    to stop guessing, and punishing a paired device for sharing an IP (NAT) with
    an attacker would turn bans into a denial-of-service tool.
    """

    def __init__(self, app: ASGIApp, state: State, trusted: Any, network_mode: str) -> None:
        self.app = app
        self.state = state
        self.trusted = trusted
        self.network_mode = network_mode

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            peer = scope.get("client")
            ip = resolve_client_ip(peer[0] if peer else None, Headers(scope=scope), self.trusted, self.network_mode)
            if self.state.bans.banned(ip) is not None and not self._has_valid_credential(scope):
                await forbidden()(scope, receive, send)
                return
        await self.app(scope, receive, send)

    def _has_valid_credential(self, scope: Scope) -> bool:
        request = Request(scope)
        token = auth.extract_bearer(request.headers) or request.cookies.get(auth.SESSION_COOKIE)
        return auth.authenticate(self.state, token, client_cert=scope.get(CLIENT_CERT_SCOPE)).result is auth.AuthResult.OK


class SecurityHeadersMiddleware:
    """Add security headers to every response and never emit a Server header."""

    def __init__(self, app: ASGIApp, hsts: bool) -> None:
        self.app = app
        self.defaults: list[tuple[bytes, bytes]] = [
            (b"x-content-type-options", b"nosniff"),
            (b"referrer-policy", b"no-referrer"),
            (b"x-frame-options", b"DENY"),
            (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
            (b"cache-control", b"no-store"),
            (b"cross-origin-resource-policy", b"same-origin"),
        ]
        if hsts:
            self.defaults.append((b"strict-transport-security", b"max-age=31536000"))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"server"]
                present = {k.lower() for k, _ in headers}
                headers.extend((k, v) for k, v in self.defaults if k not in present)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


def create_app(
    config: Config,
    state: State,
    *,
    fingerprint: str | None = None,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
    client_ca: ClientCA | None = None,
) -> FastAPI:
    trusted = parse_networks(config.network.trusted_proxies)
    if client_ca is not None:
        state.on_pairing_change = client_ca.set_pairing_open
    b = config.bans
    state.bans.configure(b.failures, b.window_seconds, b.ban_seconds, b.max_ban_seconds)

    async def housekeeping() -> None:
        while True:
            await asyncio.sleep(SWEEP_INTERVAL)
            try:
                state.sweep()
                pairing.current_window(state)  # expires (and audits) a lapsed window
            except Exception:  # noqa: BLE001 - keep sweeping no matter what
                log.exception("state sweep failed")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        timeout = httpx.Timeout(
            connect=config.ollama.connect_timeout,
            read=config.ollama.read_timeout,
            write=60.0,
            pool=30.0,
        )
        client = httpx.AsyncClient(
            base_url=config.ollama.url,
            timeout=timeout,
            transport=upstream_transport,
            limits=httpx.Limits(max_connections=64, max_keepalive_connections=16),
            trust_env=False,  # never route to Ollama through an env-configured proxy
            follow_redirects=False,
        )
        app.state.http = client
        app.state.loop = asyncio.get_running_loop()
        sweeper = asyncio.create_task(housekeeping())
        try:
            yield
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper
            state.kill_all_streams("server shutting down")
            await client.aclose()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    # No "/api" -> "/api/" redirects: they reveal routes and echo the Host header.
    app.router.redirect_slashes = False
    app.state.config = config
    app.state.gate = state

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        # 404/405 for unknown routes look identical, revealing nothing about routing.
        if exc.status_code in (404, 405):
            return error(404, "not found")
        return error(exc.status_code, "error")

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> Response:
        return error(400, "bad request")

    def client_ip(request: Request) -> str | None:
        peer = request.client.host if request.client else None
        return resolve_client_ip(peer, request.headers, trusted, config.network.mode)

    def record_failure(ip: str | None, reason: str, attempt: str = "") -> None:
        """Count a failed login/pairing attempt; ban the client if it keeps failing.

        ``attempt`` is what was tried; only its hash is kept, to count distinct attempts.
        """
        fingerprint = auth.hash_token(attempt)[:16] if attempt else ""
        ban = state.bans.record_failure(ip, reason, fingerprint)
        if ban is not None:
            state.audit("ban_auto", ip=ip, reason=reason, strikes=ban.strikes, until=ban.until)
            log.warning("banned %s (%s, strike %d)", ban.key, reason, ban.strikes)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> Response:
        if state.lockdown:  # don't even confirm the host is alive
            return lockdown_response()
        return PlainTextResponse("ok")

    @app.get("/me", include_in_schema=False)
    async def me(request: Request) -> Response:
        """Lets a device see what the server knows about it."""
        if state.lockdown:
            return lockdown_response()
        token = auth.extract_credential(request.headers, request.cookies, state.csrf_key)[0]
        outcome = auth.authenticate(state, token, client_cert=request.scope.get(CLIENT_CERT_SCOPE))
        if outcome.result is not auth.AuthResult.OK or outcome.device is None:
            state.audit_noisy("auth_failed", ip=client_ip(request), reason=outcome.result.value, path="/me")
            return unauthorized()
        d = outcome.device
        return JSONResponse(
            {
                "id": d.id,
                "name": d.name,
                "paired_via": d.paired_via,
                "paired_at": d.paired_at,
                "token_prefix": d.token_prefix,
                "token_expires_at": d.token_expires_at,
                "allow_model_management": d.allow_model_management,
                "limits": {**asdict(d.limits), "max_body_bytes": config.server.max_body_bytes},
            }
        )

    register_pairing_routes(app, config, state, fingerprint, client_ip, record_failure, client_ca)
    register_app_routes(app, state, unauthorized)

    gate = PriorityGate(config.server.max_upstream_concurrency)
    app.state.priority_gate = gate

    def remaining_tokens(device_id: str, limits: Any) -> int | None:
        """Tokens left before the tightest quota, or None if there is no quota."""
        left = []
        if limits.tokens_per_day:
            used = state.usage_today(device_id)
            left.append(limits.tokens_per_day - used.prompt_tokens - used.completion_tokens)
        if limits.tokens_per_month:
            used = state.usage_month(device_id)
            left.append(limits.tokens_per_month - used.prompt_tokens - used.completion_tokens)
        return max(0, min(left)) if left else None

    def reject_limit(device_id: str, ip: str | None, what: str, message: str, retry_after: int) -> Response:
        state.audit_noisy("limit_" + what, ip=ip, device_id=device_id)
        return error(429, message, {"Retry-After": str(max(1, retry_after))})

    async def proxy(request: Request) -> Response:
        ip = client_ip(request)
        method, path = request.method, request.url.path
        token, via_cookie = auth.extract_credential(request.headers, request.cookies, state.csrf_key)

        # 1. Lockdown rejects everything before auth (banned IPs never get here).
        if state.lockdown:
            return lockdown_response()

        # 2. Authenticate.
        client_cert = request.scope.get(CLIENT_CERT_SCOPE)
        outcome = auth.authenticate(state, token, client_cert=client_cert)
        if outcome.result is not auth.AuthResult.OK:
            state.audit_noisy(
                "auth_failed",
                ip=ip,
                device_id=outcome.device.id if outcome.device else None,
                reason=outcome.result.value,
                path=path,
                user_agent=request.headers.get("user-agent", ""),
            )
            # NO_CERT doesn't count either: that caller had the right token (the audit
            # entry with reason=no_cert shows the owner a token may have leaked).
            if outcome.result is auth.AuthResult.INVALID and not via_cookie:
                # Only a wrong bearer token counts. Anonymous requests don't: any web
                # page can make a visitor's browser send those (no-cors fetch, <img>),
                # which would let sites get their visitors banned. A stale browser
                # cookie (e.g. after a restart) isn't an attack either.
                record_failure(ip, "failed logins", token or "")
            if outcome.result is auth.AuthResult.SUSPENDED:
                return error(403, "device suspended")
            return unauthorized()
        device = outcome.device
        assert device is not None
        limits = device.limits

        # 3. Is this an endpoint we forward at all, and may this device use it?
        kind = classify_endpoint(method, path)
        if kind is None:
            return error(404, "not found")
        if kind is EndpointKind.MANAGEMENT and not device.allow_model_management:
            state.audit("endpoint_denied", ip=ip, device_id=device.id, path=path, method=method)
            return error(403, "endpoint not allowed for this device")
        if path.startswith("/v1/models/") and not model_allowed(limits, path.removeprefix("/v1/models/")):
            return error(404, "not found")

        # 4. Rate, quota and concurrency limits - checked and claimed with no await in between.
        if limits.requests_per_minute > 0 and not state.device_rpm.hit(device.id, limit=limits.requests_per_minute):
            return reject_limit(
                device.id,
                ip,
                "rate",
                "rate limit exceeded",
                state.device_rpm.retry_after(device.id, limit=limits.requests_per_minute),
            )
        today, month = state.usage_today(device.id), state.usage_month(device.id)
        if limits.tokens_per_day and today.prompt_tokens + today.completion_tokens >= limits.tokens_per_day:
            return reject_limit(device.id, ip, "tokens_day", "daily token quota used up", seconds_until_midnight())
        if limits.tokens_per_month and month.prompt_tokens + month.completion_tokens >= limits.tokens_per_month:
            return reject_limit(
                device.id, ip, "tokens_month", "monthly token quota used up", seconds_until_next_month()
            )
        if len(state.device_streams(device.id)) >= limits.max_concurrent:
            return reject_limit(device.id, ip, "concurrency", "too many concurrent requests", 1)
        started = time.monotonic()
        stream = state.register_stream(device.id, method, path, auth.hash_token(token or ""))
        ticket = Ticket()  # the priority-gate slot, released in finish()
        counter: UsageCounter | None = None
        body = b""

        def finish(outcome_name: str, status: int, bytes_out: int) -> None:
            gate.release(ticket)  # no-op if no slot was granted
            state.unregister_stream(stream)
            if counter is not None and status < 400 and path in ACCOUNTED_ENDPOINTS:
                used = counter.result()
                state.add_usage(device.id, prompt_tokens=used.prompt_tokens, completion_tokens=used.completion_tokens)
                if not used.exact:
                    state.audit("usage_estimated", ip=ip, device_id=device.id, tokens=used.total, outcome=outcome_name)
            state.log_request(
                RequestLogEntry(
                    ts=time.time(),
                    device_id=device.id,
                    ip=ip,
                    method=method,
                    path=path,
                    status=status,
                    duration_ms=monotonic_ms(started),
                    bytes_out=bytes_out,
                    outcome=outcome_name,
                    model=stream.model,
                )
            )

        handed_off = False
        try:
            # 5. Read the body. The stream is already registered, so a revoke during
            #    a slow upload aborts it too; the whole body must arrive in time.
            try:
                body = await asyncio.wait_for(
                    race_kill(read_body_limited(request, config.server.max_body_bytes), stream),
                    config.server.body_timeout,
                )
            except BodyTooLarge:
                finish("rejected", 413, 0)
                return error(413, "request body too large")
            except asyncio.TimeoutError:
                finish("rejected", 408, 0)
                return error(408, "request body timeout")
            except ClientDisconnect:
                finish("client_disconnect", 499, 0)
                return Response(status_code=499)

            # 6. Re-check the credential: it may have been revoked, rotated,
            #    suspended or expired while the body was arriving.
            recheck = auth.authenticate(state, token, client_cert=client_cert)
            if recheck.result is not auth.AuthResult.OK or recheck.device is not device:
                finish("rejected", 401, 0)
                return unauthorized()

            # 7. Body policy: model allowlist, num_ctx/num_predict/max_tokens clamps,
            #    keep_alive cap, and a usage chunk requested for /v1 streams.
            policy = apply_body_policy(limits, path, body, remaining_tokens(device.id, limits))
            stream.model = safe_text(policy.model, 100) if policy.model else requested_model(body)
            if policy.error is not None:
                if policy.status == 403:
                    state.audit_noisy("model_denied", ip=ip, device_id=device.id, model=policy.model)
                finish("rejected", policy.status, 0)
                return error(policy.status, policy.error)
            body = policy.body

            is_new_ip = state.touch_device(
                device,
                ip,
                request.client.port if request.client else None,
                request.headers.get("user-agent", ""),
            )
            if is_new_ip:
                state.audit("device_new_ip", ip=ip, device_id=device.id)

            # 8. Wait for a slot at Ollama (higher priority first), but not forever:
            #    under constant high-priority load a low-priority request gives up.
            try:
                await asyncio.wait_for(
                    race_kill(gate.acquire(limits.priority, ticket), stream, request.receive),
                    config.server.queue_timeout,
                )
            except asyncio.TimeoutError:
                state.audit_noisy("limit_queue", ip=ip, device_id=device.id)
                finish("rejected", 503, 0)
                return error(503, "server busy, try again shortly", {"Retry-After": "10"})

            # 9. Forward.
            http: httpx.AsyncClient = request.app.state.http
            upstream_request = http.build_request(
                method, path, content=body or None, headers=build_upstream_headers(request.headers)
            )
            try:
                upstream = await open_upstream(http, upstream_request, stream, request.receive)
            except httpx.HTTPError as exc:
                log.warning("upstream unavailable: %s", type(exc).__name__)
                finish("upstream_error", 502, 0)
                return error(502, "upstream unavailable")

            if limits.allowed_models and method == "GET" and path in ("/api/tags", "/api/ps", "/v1/models"):
                # Small JSON listings: buffer them to hide models this device may not use.
                try:
                    raw = await race_kill(read_capped(upstream, MAX_LISTING_BYTES), stream, request.receive)
                except httpx.HTTPError as exc:
                    log.warning("upstream listing failed: %s", type(exc).__name__)
                    finish("upstream_error", 502, 0)
                    return error(502, "upstream unavailable")
                finally:
                    await upstream.aclose()
                content = filter_model_list(limits, path, raw)
                finish("complete", upstream.status_code, len(content))
                return Response(content, status_code=upstream.status_code, media_type="application/json")

            counter = UsageCounter(upstream.headers.get("content-type", ""), len(body))
            stream.usage = counter
            handed_off = True
            return ProxyStreamResponse(upstream, stream, finish, on_chunk=counter.feed)
        except StreamKilled as exc:
            finish("killed", 503, 0)
            return error(503, f"request terminated: {exc.reason}")
        except ClientGone:
            finish("client_disconnect", 499, 0)
            return Response(status_code=499)
        finally:
            # Any other exit (e.g. cancellation) must not leave the stream registered.
            if not handed_off and stream.id in state.streams:
                finish("error", 500, 0)

    app.add_api_route("/api/{rest:path}", proxy, methods=PROXY_METHODS, include_in_schema=False)
    app.add_api_route("/v1/{rest:path}", proxy, methods=PROXY_METHODS, include_in_schema=False)

    app.add_middleware(BanMiddleware, state=state, trusted=trusted, network_mode=config.network.mode)
    app.add_middleware(SecurityHeadersMiddleware, hsts=config.tls.mode != "off")
    return app
