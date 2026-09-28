"""Streaming forwarder to Ollama.

Responses are passed through chunk by chunk (never buffered). Each forwarded
request is tracked as an ``ActiveStream`` so the owner can kill it; a stream
ends as soon as any of these happens:

* Ollama finishes the response,
* the client disconnects (the upstream request is closed, so Ollama stops), or
* the stream is killed (revoke / kick / lockdown) - within one event-loop tick.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Awaitable, Callable

import httpx
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from ..state import ActiveStream

log = logging.getLogger("ollamagate.proxy")

# Only these request headers are forwarded. Everything else - notably
# Authorization, Cookie, X-Forwarded-*, hop-by-hop headers - is dropped.
FORWARD_REQUEST_HEADERS = ("content-type", "accept")
# Only these response headers are passed back to the client.
FORWARD_RESPONSE_HEADERS = ("content-type",)


class StreamKilled(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ClientGone(Exception):
    pass


def build_upstream_headers(incoming: Any) -> dict[str, str]:
    headers = {name: incoming[name] for name in FORWARD_REQUEST_HEADERS if name in incoming}
    # Ask for an uncompressed body so bytes can be streamed through verbatim.
    headers["accept-encoding"] = "identity"
    return headers


async def wait_for_disconnect(receive: Receive) -> None:
    """Return once the client has disconnected. The request body must already be consumed."""
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return


async def open_upstream(
    client: httpx.AsyncClient,
    request: httpx.Request,
    stream: ActiveStream,
    receive: Receive,
) -> httpx.Response:
    """Send ``request`` upstream, aborting early if the stream is killed or the client leaves.

    Model loading can take a long time before the first byte arrives, so we
    must not wait blindly here.
    """
    send_task = asyncio.ensure_future(client.send(request, stream=True))
    kill_task = asyncio.ensure_future(stream.killed.wait())
    gone_task = asyncio.ensure_future(wait_for_disconnect(receive))
    try:
        await asyncio.wait({send_task, kill_task, gone_task}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in (kill_task, gone_task):
            task.cancel()
    if send_task.done():
        return send_task.result()
    send_task.cancel()
    try:
        response = await send_task
    except (asyncio.CancelledError, httpx.HTTPError):
        pass
    else:  # the response raced in just as we cancelled
        await response.aclose()
    if stream.killed.is_set():
        raise StreamKilled(stream.kill_reason)
    raise ClientGone()


def _error_trailer(content_type: str, message: str) -> bytes:
    """An in-band error for a stream whose status line has already been sent."""
    if "text/event-stream" in content_type:
        return b"data: " + json.dumps({"error": {"message": message, "type": "ollamagate"}}).encode() + b"\n\n"
    if "ndjson" in content_type:
        return json.dumps({"error": message}).encode() + b"\n"
    return b""


class ProxyStreamResponse(Response):
    """ASGI response that pipes an ``httpx`` streaming response to the client.

    Subclasses ``Response`` only so FastAPI passes it through untouched; the
    base initialiser is intentionally not used.
    """

    def __init__(
        self,
        upstream: httpx.Response,
        stream: ActiveStream,
        on_done: Callable[[str, int, int], Awaitable[None] | None],
        on_chunk: Callable[[bytes], None] | None = None,
    ) -> None:
        self.upstream = upstream
        self.stream = stream
        self.on_done = on_done
        self.on_chunk = on_chunk
        self.background = None
        self.status_code = upstream.status_code
        self.content_type = upstream.headers.get("content-type", "")
        self.bytes_out = 0

    def _headers(self) -> list[tuple[bytes, bytes]]:
        headers = []
        for name in FORWARD_RESPONSE_HEADERS:
            value = self.upstream.headers.get(name)
            if value is not None:
                headers.append((name.encode("latin-1"), value.encode("latin-1")))
        return headers

    async def _pump(self, send: Send) -> str:
        outcome = "complete"
        try:
            async for chunk in self.upstream.aiter_raw():
                if not chunk:
                    continue
                if self.on_chunk is not None:
                    self.on_chunk(chunk)
                self.bytes_out += len(chunk)
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
        except httpx.HTTPError as exc:
            log.warning("upstream stream error: %s", type(exc).__name__)
            outcome = "upstream_error"
            trailer = _error_trailer(self.content_type, "upstream error")
            if trailer:
                await send({"type": "http.response.body", "body": trailer, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        return outcome

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        outcome = "client_disconnect"
        try:
            await send(
                {"type": "http.response.start", "status": self.status_code, "headers": self._headers()}
            )
            pump = asyncio.ensure_future(self._pump(send))
            gone = asyncio.ensure_future(wait_for_disconnect(receive))
            kill = asyncio.ensure_future(self.stream.killed.wait())
            try:
                await asyncio.wait({pump, gone, kill}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in (pump, gone, kill):
                    task.cancel()
                await asyncio.gather(pump, gone, kill, return_exceptions=True)
            if pump.done() and not pump.cancelled() and pump.exception() is None:
                outcome = pump.result()
            elif kill.done() and not kill.cancelled():
                outcome = "killed"
                trailer = _error_trailer(self.content_type, f"stream terminated: {self.stream.kill_reason}")
                try:
                    if trailer:
                        await send({"type": "http.response.body", "body": trailer, "more_body": True})
                    await send({"type": "http.response.body", "body": b"", "more_body": False})
                except OSError:
                    pass
            elif pump.done() and not pump.cancelled() and isinstance(pump.exception(), OSError):
                outcome = "client_disconnect"
        finally:
            await self.upstream.aclose()
            result = self.on_done(outcome, self.status_code, self.bytes_out)
            if asyncio.iscoroutine(result):
                await result


def monotonic_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
