"""HTTP routes for pairing: the pairing page and the claim endpoint.

While no pairing window is open every ``/pair*`` route returns the same
``404`` as any unknown path, so the feature's existence isn't revealed.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Callable

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse, Response

from ..config import Config
from ..state import State
from . import pairing
from .ratelimit import RateLimiter

MAX_CLAIM_BODY = 4096

PAGE_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

_ASSETS = {
    "/pair": ("pair.html", "text/html; charset=utf-8"),
    "/pair/pair.js": ("pair.js", "text/javascript; charset=utf-8"),
    "/pair/pair.css": ("pair.css", "text/css; charset=utf-8"),
}


def _load_asset(name: str) -> bytes:
    return resources.files("ollamagate.web").joinpath(name).read_bytes()


def _json(status: int, payload: dict) -> JSONResponse:
    return JSONResponse(payload, status_code=status)


def not_found() -> JSONResponse:
    return _json(404, {"error": "not found"})


def register_pairing_routes(
    app: FastAPI,
    config: Config,
    state: State,
    fingerprint: str | None,
    client_ip: Callable[[Request], str | None],
) -> None:
    assets = {path: (_load_asset(name), ctype) for path, (name, ctype) in _ASSETS.items()}
    # Claims are what an attacker would brute-force; page loads get more slack.
    claim_limiter = RateLimiter(config.pairing.requests_per_minute_per_ip, 60.0)
    page_limiter = RateLimiter(60, 60.0)

    def gate(request: Request, limiter: RateLimiter) -> Response | None:
        """Common checks: window open (else 404), then per-IP rate limit."""
        if pairing.current_window(state) is None:
            return not_found()
        ip = client_ip(request) or "unknown"
        if not limiter.hit(ip):
            state.audit("pairing_rate_limited", ip=ip)
            return JSONResponse(
                {"error": "too many requests"},
                status_code=429,
                headers={"Retry-After": str(limiter.retry_after(ip))},
            )
        return None

    async def page(request: Request) -> Response:
        blocked = gate(request, page_limiter)
        if blocked is not None:
            return blocked
        body, ctype = assets[request.url.path]
        return Response(body, media_type=ctype, headers={"Content-Security-Policy": PAGE_CSP})

    for path in _ASSETS:
        app.add_api_route(path, page, methods=["GET"], include_in_schema=False)

    @app.post("/pair/claim", include_in_schema=False)
    async def claim(request: Request) -> Response:
        blocked = gate(request, claim_limiter)
        if blocked is not None:
            return blocked
        ip = client_ip(request)
        # Browsers always send Sec-Fetch-Site; refuse cross-site form posts.
        if request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
            return _json(403, {"error": "cross-site request refused"})
        # JSON only: a cross-origin JSON POST needs a CORS preflight, which we never grant.
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            return _json(415, {"error": "expected application/json"})
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_CLAIM_BODY:
                return _json(413, {"error": "request too large"})
        try:
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            return _json(400, {"error": "invalid JSON"})

        code, secret = data.get("code"), data.get("secret")
        if isinstance(code, str) and code and secret is None:
            kind, value = "code", code
        elif isinstance(secret, str) and secret and code is None:
            kind, value = "link", secret
        else:
            return _json(400, {"error": "send either a code or a secret"})

        result = pairing.claim(
            state,
            secret=value,
            kind=kind,
            device_name=data.get("device_name"),
            ip=ip,
            user_agent=request.headers.get("user-agent", ""),
            allow_model_management=config.limits.allow_model_management,
        )
        if result.error is pairing.ClaimError.CLOSED:
            return not_found()
        if result.error is pairing.ClaimError.BAD_NAME:
            return _json(400, {"error": "device name must be 1-64 printable characters"})
        if result.error is pairing.ClaimError.INVALID:
            return _json(403, {"error": "invalid pairing code", "attempts_left": result.attempts_left})
        assert result.device is not None and result.token is not None
        return _json(
            200,
            {
                "token": result.token,
                "device_id": result.device.id,
                "name": result.device.name,
                "base_url": config.base_url,
                "fingerprint": fingerprint,
            },
        )
