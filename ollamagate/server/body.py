"""Reading request bodies with a hard size cap."""

from __future__ import annotations

from starlette.requests import Request


class BodyTooLarge(Exception):
    pass


async def read_body_limited(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        raise BodyTooLarge()
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise BodyTooLarge()
    return bytes(body)
