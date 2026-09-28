"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
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
from .pairing_routes import register_pairing_routes
from .policy import EndpointKind, classify_endpoint
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
) -> FastAPI:
    trusted = parse_networks(config.network.trusted_proxies)

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
        outcome = auth.authenticate(state, auth.extract_bearer(request.headers))
        if outcome.result is not auth.AuthResult.OK or outcome.device is None:
            state.audit_noisy("auth_failed", ip=client_ip(request), reason=outcome.result.value, path="/me")
            return unauthorized()
        d = outcome.device
        lim = config.limits
        return JSONResponse(
            {
                "id": d.id,
                "name": d.name,
                "paired_via": d.paired_via,
                "paired_at": d.paired_at,
                "token_prefix": d.token_prefix,
                "token_expires_at": d.token_expires_at,
                "allow_model_management": d.allow_model_management,
                "limits": {
                    "max_concurrent": lim.max_concurrent,
                    "max_body_bytes": config.server.max_body_bytes,
                },
            }
        )

    register_pairing_routes(app, config, state, fingerprint, client_ip)

    async def proxy(request: Request) -> Response:
        ip = client_ip(request)
        method, path = request.method, request.url.path
        token = auth.extract_bearer(request.headers)

        # 1. Lockdown rejects everything before auth. (Phase 4: IP bans go here too.)
        if state.lockdown:
            return lockdown_response()

        # 2. Authenticate.
        outcome = auth.authenticate(state, token)
        if outcome.result is not auth.AuthResult.OK:
            state.audit_noisy(
                "auth_failed",
                ip=ip,
                device_id=outcome.device.id if outcome.device else None,
                reason=outcome.result.value,
                path=path,
                user_agent=request.headers.get("user-agent", ""),
            )
            if outcome.result is auth.AuthResult.SUSPENDED:
                return error(403, "device suspended")
            return unauthorized()
        device = outcome.device
        assert device is not None

        # 3. Is this an endpoint we forward at all, and may this device use it?
        kind = classify_endpoint(method, path)
        if kind is None:
            return error(404, "not found")
        if kind is EndpointKind.MANAGEMENT and not device.allow_model_management:
            state.audit("endpoint_denied", ip=ip, device_id=device.id, path=path, method=method)
            return error(403, "endpoint not allowed for this device")

        # 4. Concurrency cap, checked and claimed atomically (no await in between).
        if len(state.device_streams(device.id)) >= config.limits.max_concurrent:
            state.audit("limit_concurrency", ip=ip, device_id=device.id)
            return error(429, "too many concurrent requests", {"Retry-After": "1"})
        started = time.monotonic()
        stream = state.register_stream(device.id, method, path, auth.hash_token(token or ""))

        def finish(outcome_name: str, status: int, bytes_out: int) -> None:
            state.unregister_stream(stream)
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
            recheck = auth.authenticate(state, token)
            if recheck.result is not auth.AuthResult.OK or recheck.device is not device:
                finish("rejected", 401, 0)
                return unauthorized()

            stream.model = requested_model(body)
            # (Phase 4) body policy: model allowlist, num_ctx/num_predict clamps, usage injection.

            is_new_ip = state.touch_device(
                device,
                ip,
                request.client.port if request.client else None,
                request.headers.get("user-agent", ""),
            )
            if is_new_ip:
                state.audit("device_new_ip", ip=ip, device_id=device.id)

            # 7. Forward.
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
            handed_off = True
            return ProxyStreamResponse(upstream, stream, finish)
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

    app.add_middleware(SecurityHeadersMiddleware, hsts=config.tls.mode != "off")
    return app
