"""The built-in browser chat at /app.

Everything under /app requires a valid session cookie (set when a browser
pairs); anyone else gets the same generic 401 as the API. The page itself is
static (no external resources, strict CSP) and talks to the normal /api
endpoints with the cookie plus a CSRF header, so the device's limits,
quotas and audit trail all apply unchanged.
"""

from __future__ import annotations

from importlib import resources
from typing import Callable

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse, Response

from ..state import State
from . import auth

APP_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

_ASSETS = {
    "/app": ("app.html", "text/html; charset=utf-8"),
    "/app/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app/app.css": ("app.css", "text/css; charset=utf-8"),
}


def session_cookie_header(token: str, secure: bool, max_age: int) -> str:
    parts = [f"{auth.SESSION_COOKIE}={token}", "Path=/", "HttpOnly", "SameSite=Strict", f"Max-Age={max_age}"]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def register_app_routes(
    app: FastAPI,
    state: State,
    unauthorized: Callable[[], Response],
    secure_cookies: bool,
) -> None:
    assets = {
        path: (resources.files("ollamagate.web").joinpath(name).read_bytes(), ctype)
        for path, (name, ctype) in _ASSETS.items()
    }

    def session_device(request: Request):  # type: ignore[no-untyped-def]
        cookie = request.cookies.get(auth.SESSION_COOKIE)
        outcome = auth.authenticate(state, cookie)
        return outcome.device if outcome.result is auth.AuthResult.OK else None

    async def page(request: Request) -> Response:
        if state.lockdown or session_device(request) is None:
            return unauthorized()
        body, ctype = assets[request.url.path]
        return Response(body, media_type=ctype, headers={"Content-Security-Policy": APP_CSP})

    for path in _ASSETS:
        app.add_api_route(path, page, methods=["GET"], include_in_schema=False)

    @app.get("/app/session", include_in_schema=False)
    async def session(request: Request) -> Response:
        """Hands the page its CSRF token. Readable only same-origin (no CORS)."""
        device = session_device(request)
        if state.lockdown or device is None:
            return unauthorized()
        token = request.cookies[auth.SESSION_COOKIE]
        return JSONResponse({"name": device.name, "csrf": auth.csrf_token(state.csrf_key, token)})

    @app.post("/app/logout", include_in_schema=False)
    async def logout(request: Request) -> Response:
        """Forget the session in this browser (the device stays paired)."""
        token, via_cookie = auth.extract_credential(request.headers, request.cookies, state.csrf_key)
        if not (token and via_cookie):
            return unauthorized()
        response = JSONResponse({"ok": True})
        response.headers["Set-Cookie"] = session_cookie_header("", secure_cookies, 0)
        return response
