"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..config import Config
from ..state import RequestLogEntry, State
from . import auth
from .netutil import parse_networks, resolve_client_ip
from .policy import EndpointKind, classify_endpoint
from .proxy import (
    ClientGone,
    ProxyStreamResponse,
    StreamKilled,
    build_upstream_headers,
    monotonic_ms,
    open_upstream,
)

log = logging.getLogger("ollamagate.app")

PROXY_METHODS = ["GET", "POST", "DELETE", "HEAD"]


class BodyTooLarge(Exception):
    pass


def error(status: int, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, headers=headers)


def unauthorized() -> JSONResponse:
    # Deliberately generic: no hint about why, no server/version info.
    return error(401, "unauthorized", {"WWW-Authenticate": "Bearer"})


async def read_body_limited(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        if not declared.isdigit():
            raise BodyTooLarge()  # malformed; treat as refused
        if int(declared) > limit:
            raise BodyTooLarge()
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise BodyTooLarge()
    return bytes(body)


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
    upstream_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    trusted = parse_networks(config.network.trusted_proxies)

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
            trust_env=False,  # never route to Ollama through an env-configured proxy
            follow_redirects=False,
        )
        app.state.http = client
        app.state.loop = asyncio.get_running_loop()
        try:
            yield
        finally:
            state.kill_all_streams("server shutting down")
            await client.aclose()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
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
        return PlainTextResponse("ok")

    async def proxy(request: Request) -> Response:
        ip = client_ip(request)
        method, path = request.method, request.url.path
        outcome = auth.authenticate(state, auth.extract_bearer(request.headers))
        if outcome.result is not auth.AuthResult.OK:
            state.audit(
                "auth_failed",
                ip=ip,
                device_id=outcome.device.id if outcome.device else None,
                reason=outcome.result.value,
                path=path,
                user_agent=request.headers.get("user-agent", "")[:200],
            )
            if outcome.result is auth.AuthResult.SUSPENDED:
                return error(403, "device suspended")
            return unauthorized()
        device = outcome.device
        assert device is not None

        kind = classify_endpoint(method, path)
        if kind is None:
            return error(404, "not found")
        if kind is EndpointKind.MANAGEMENT and not device.allow_model_management:
            state.audit("endpoint_denied", ip=ip, device_id=device.id, path=path, method=method)
            return error(403, "endpoint not allowed for this device")

        try:
            body = await read_body_limited(request, config.server.max_body_bytes)
        except BodyTooLarge:
            return error(413, "request body too large")

        state.touch_device(
            device,
            ip,
            request.client.port if request.client else None,
            request.headers.get("user-agent", ""),
        )
        started = time.monotonic()
        stream = state.register_stream(device.id, method, path)
        http: httpx.AsyncClient = request.app.state.http
        upstream_request = http.build_request(
            method, path, content=body or None, headers=build_upstream_headers(request.headers)
        )

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
                )
            )

        try:
            upstream = await open_upstream(http, upstream_request, stream, request.receive)
        except StreamKilled as exc:
            finish("killed", 503, 0)
            return error(503, f"request terminated: {exc.reason}")
        except ClientGone:
            finish("client_disconnect", 499, 0)
            return Response(status_code=499)
        except httpx.HTTPError as exc:
            log.warning("upstream unavailable: %s", type(exc).__name__)
            finish("upstream_error", 502, 0)
            return error(502, "upstream unavailable")
        except BaseException:
            finish("upstream_error", 500, 0)
            raise
        return ProxyStreamResponse(upstream, stream, finish)

    app.add_api_route("/api/{rest:path}", proxy, methods=PROXY_METHODS, include_in_schema=False)
    app.add_api_route("/v1/{rest:path}", proxy, methods=PROXY_METHODS, include_in_schema=False)

    app.add_middleware(SecurityHeadersMiddleware, hsts=config.tls.mode != "off")
    return app
