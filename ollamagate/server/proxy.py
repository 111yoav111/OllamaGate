"""Streaming forwarder to Ollama.

Responses are passed through chunk by chunk (never buffered). Each forwarded
request is tracked as an ``ActiveStream`` so the owner can kill it; a stream
ends as soon as any of these happens:

* Ollama finishes the response,
* the client disconnects (the upstream request is closed, so Ollama stops), or
* the stream is killed (revoke / kick / lockdown) - within one event-loop tick,
  even if the client has stopped reading.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Awaitable, Callable, TypeVar

import httpx
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from ..state import ActiveStream

log = logging.getLogger("ollamagate.proxy")

T = TypeVar("T")

# Only these request headers are forwarded. Everything else - notably
# Authorization, Cookie, X-Forwarded-*, hop-by-hop headers - is dropped.
FORWARD_REQUEST_HEADERS = ("content-type", "accept")
# Only these response headers are passed back to the client.
FORWARD_RESPONSE_HEADERS = ("content-type",)
# How long we try to deliver an in-band error before giving up on a client.
TRAILER_TIMEOUT = 1.0


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


async def _reap(task: asyncio.Future[Any]) -> None:
    """Await a task we just cancelled, closing any response it still produced."""
    try:
        result = await task
    except asyncio.CancelledError:
        current = asyncio.current_task()
        if current is not None and current.cancelling():
            raise  # we are being cancelled ourselves; don't swallow it
    except Exception:  # noqa: BLE001 - the task's own failure is irrelevant now
        pass
    else:
        if isinstance(result, httpx.Response):
            await result.aclose()


async def race_kill(
    work: Awaitable[T], stream: ActiveStream, receive: Receive | None = None
) -> T:
    """Run ``work`` but abort it if the stream is killed or (optionally) the client leaves."""
    work_task = asyncio.ensure_future(work)
    watchers = [asyncio.ensure_future(stream.killed.wait())]
    if receive is not None:
        watchers.append(asyncio.ensure_future(wait_for_disconnect(receive)))
    try:
        await asyncio.wait({work_task, *watchers}, return_when=asyncio.FIRST_COMPLETED)
    except BaseException:
        work_task.cancel()
        await _reap(work_task)
        raise
    finally:
        for w in watchers:
            w.cancel()
    if work_task.done():
        return work_task.result()
    work_task.cancel()
    await _reap(work_task)
    if stream.killed.is_set():
        raise StreamKilled(stream.kill_reason)
    raise ClientGone()


async def open_upstream(
    client: httpx.AsyncClient, request: httpx.Request, stream: ActiveStream, receive: Receive
) -> httpx.Response:
    """Send ``request`` upstream, aborting if the stream is killed or the client leaves.

    Model loading can take a long time before the first byte arrives, so we
    must not wait blindly here.
    """
    return await race_kill(client.send(request, stream=True), stream, receive)


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
        on_done: Callable[[str, int, int], None],
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
        """Copy the body. Returns "complete" or "upstream_error"."""
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
            await self._end_with_error("upstream error", send)
            return "upstream_error"
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        return "complete"

    async def _end_with_error(self, message: str, send: Send) -> None:
        """Tell a streaming client why the stream ended, then end it.

        Bodies that are not line-delimited streams get no terminator at all, so
        the connection is aborted and the client sees a truncated response
        rather than a clean-looking but incomplete one. A client that has stopped
        reading gets TRAILER_TIMEOUT seconds before we give up on it.
        """
        trailer = _error_trailer(self.content_type, message)
        if not trailer:
            return

        async def deliver() -> None:
            await send({"type": "http.response.body", "body": trailer, "more_body": True})
            await send({"type": "http.response.body", "body": b"", "more_body": False})

        try:
            await asyncio.wait_for(deliver(), TRAILER_TIMEOUT)
        except (asyncio.TimeoutError, OSError):
            pass

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

            if pump.done() and not pump.cancelled():
                exc = pump.exception()
                if exc is None:
                    outcome = pump.result()
                else:
                    log.error("stream pump failed: %r", exc)
                    outcome = "error"
            elif kill.done() and not kill.cancelled():
                outcome = "killed"
                # Stop Ollama first, then (best effort) tell the client why.
                await self.upstream.aclose()
                await self._end_with_error(f"stream terminated: {self.stream.kill_reason}", send)
        finally:
            try:
                await self.upstream.aclose()
            finally:
                self.on_done(outcome, self.status_code, self.bytes_out)


def monotonic_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
