"""A tiny fake Ollama server for tests.

It records what it receives (so tests can assert headers were stripped) and
whether streams were closed early (so tests can assert client disconnects and
kills propagate upstream).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route


@dataclass
class Recorder:
    requests: list[dict[str, Any]] = field(default_factory=list)
    streams_started: int = 0
    streams_completed: int = 0
    streams_aborted: int = 0
    aborted_event: asyncio.Event | None = None

    @property
    def last(self) -> dict[str, Any]:
        return self.requests[-1]


def make_fake_ollama() -> tuple[Starlette, Recorder]:
    rec = Recorder()

    async def record(request: Request) -> dict[str, Any]:
        body = await request.body()
        entry = {
            "method": request.method,
            "path": request.url.path,
            "query": request.url.query,
            "headers": {k.lower(): v for k, v in request.headers.items()},
            "body": json.loads(body) if body else None,
        }
        rec.requests.append(entry)
        return entry

    async def stream_lines(lines, delay: float):
        rec.streams_started += 1
        finished = False
        try:
            for line in lines:
                yield line
                await asyncio.sleep(delay)
            finished = True
        finally:
            if finished:
                rec.streams_completed += 1
            else:
                rec.streams_aborted += 1

    async def chat(request: Request):
        entry = await record(request)
        body = entry["body"] or {}
        chunks = int(body.get("fake_chunks", 3))
        delay = float(body.get("fake_delay", 0.0))
        model = body.get("model", "test")
        if model == "missing-blob":  # a raw Go error, as Ollama sends for a damaged model
            return JSONResponse({"error": "open /srv/secret/.ollama/models/blobs/sha256-ab: no such file"}, status_code=500)
        await asyncio.sleep(float(body.get("fake_first_delay", 0.0)))  # e.g. model loading
        if body.get("stream") is False:
            return JSONResponse(
                {
                    "model": model,
                    "message": {"role": "assistant", "content": "hello " * chunks},
                    "done": True,
                    "prompt_eval_count": 7,
                    "eval_count": chunks,
                }
            )
        lines = [
            json.dumps({"model": model, "message": {"role": "assistant", "content": f"tok{i} "}, "done": False}) + "\n"
            for i in range(chunks)
        ]
        lines.append(json.dumps({"model": model, "done": True, "prompt_eval_count": 7, "eval_count": chunks}) + "\n")
        return StreamingResponse(stream_lines(lines, delay), media_type="application/x-ndjson")

    async def openai_chat(request: Request):
        entry = await record(request)
        body = entry["body"] or {}
        chunks = int(body.get("fake_chunks", 3))
        delay = float(body.get("fake_delay", 0.0))
        lines = [
            "data: " + json.dumps({"choices": [{"delta": {"content": f"tok{i}"}}]}) + "\n\n" for i in range(chunks)
        ]
        lines.append("data: " + json.dumps({"choices": [], "usage": {"prompt_tokens": 7, "completion_tokens": chunks}}) + "\n\n")
        lines.append("data: [DONE]\n\n")
        return StreamingResponse(stream_lines(lines, delay), media_type="text/event-stream")

    async def tags(request: Request):
        await record(request)
        return JSONResponse(
            {
                "models": [
                    {"name": "llama3:8b", "details": {"parent_model": "C:\\Users\\me\\.ollama\\blob"}},
                    {"name": "qwen2:7b"},
                ]
            }
        )

    async def openai_models(request: Request):
        await record(request)
        return JSONResponse({"object": "list", "data": [{"id": "llama3:8b"}, {"id": "qwen2:7b"}]})

    async def version(request: Request):
        await record(request)
        return JSONResponse({"version": "0.0.0-fake"}, headers={"x-upstream-secret": "leak"})

    async def show(request: Request):
        """Like Ollama's: the Modelfile names the blob by its absolute path."""
        entry = await record(request)
        if (entry["body"] or {}).get("model") == "broken":
            return broken_json()
        return JSONResponse(
            {
                "modelfile": "# Modelfile\nFROM /mnt/Games/ollama/blobs/sha256-d3\nPARAMETER stop </s>\n",
                "template": "{{ .Prompt }}",
                "license": "see https://example.com/a/b/LICENSE",
                "details": {"parent_model": "/usr/share/ollama/.ollama/models/blobs/sha256-d3", "format": "gguf"},
            }
        )

    def broken_json():
        """Starts a JSON body, then dies mid-response (upstream crash)."""

        async def body():
            yield b'{"modelfile": "partial'
            await asyncio.sleep(0.05)
            raise RuntimeError("upstream crashed")

        return StreamingResponse(body(), media_type="application/json")

    async def infinite(request: Request):
        """An endless fast stream, to fill socket buffers."""
        await record(request)

        async def body():
            rec.streams_started += 1
            try:
                while True:
                    yield b'{"message":{"content":"' + b"x" * 65000 + b'"},"done":false}\n'
                    await asyncio.sleep(0)
            finally:
                rec.streams_aborted += 1

        return StreamingResponse(body(), media_type="application/x-ndjson")

    async def generic(request: Request):
        await record(request)
        return JSONResponse({"status": "success"})

    routes = [
        Route("/api/chat", chat, methods=["POST"]),
        Route("/api/generate", chat, methods=["POST"]),
        Route("/v1/chat/completions", openai_chat, methods=["POST"]),
        Route("/api/tags", tags, methods=["GET"]),
        Route("/v1/models", openai_models, methods=["GET"]),
        Route("/api/version", version, methods=["GET"]),
        Route("/api/pull", generic, methods=["POST"]),
        Route("/api/show", show, methods=["POST"]),
        Route("/api/embed", infinite, methods=["POST"]),
        Route("/api/delete", generic, methods=["DELETE"]),
        Route("/api/internal", generic, methods=["GET", "POST"]),
    ]
    return Starlette(routes=routes), rec
