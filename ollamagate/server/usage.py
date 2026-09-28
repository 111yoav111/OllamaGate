"""Token accounting from Ollama responses.

Ollama reports token counts only at the end of a response:

* native API (``/api/*``): the final JSON object has ``prompt_eval_count`` and
  ``eval_count`` (the last NDJSON line when streaming);
* OpenAI API (``/v1/*``): a ``usage`` object with ``prompt_tokens`` and
  ``completion_tokens`` (a final ``data:`` chunk when streaming - the proxy
  asks for it with ``stream_options.include_usage``).

A client that disconnects before the end would otherwise never be billed, so
for an incomplete response the counter falls back to an estimate: one token
per streamed chunk (Ollama streams about a token per chunk) plus the prompt
size estimated from the request body.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

# Only a bounded tail of the response is kept for parsing.
MAX_BUFFER = 256 * 1024
BYTES_PER_TOKEN = 4


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    exact: bool = False

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10**9 else 0


class UsageCounter:
    """Feed it the raw response bytes; ask for ``result()`` when the response ends."""

    def __init__(self, content_type: str, request_body_len: int) -> None:
        self.sse = "text/event-stream" in content_type
        self.ndjson = "ndjson" in content_type
        self.request_body_len = request_body_len
        self._buf = bytearray()
        self._chunks = 0
        self._usage: Usage | None = None

    @property
    def chunks(self) -> int:
        """Chunks seen so far (roughly tokens, for a live tokens/second figure)."""
        return self._chunks

    def feed(self, chunk: bytes) -> None:
        self._buf += chunk
        if self.sse or self.ndjson:
            # Parse complete lines as they arrive; keep only the unfinished tail.
            *lines, rest = self._buf.split(b"\n")
            for line in lines:
                self._line(line)
            self._buf = bytearray(rest[-MAX_BUFFER:])
        elif len(self._buf) > MAX_BUFFER:
            self._buf = self._buf[-MAX_BUFFER:]  # a non-streamed body this large isn't chat output

    def _line(self, line: bytes) -> None:
        line = line.strip()
        if not line:
            return
        if self.sse:
            if not line.startswith(b"data:"):
                return
            line = line[5:].strip()
            if line == b"[DONE]":
                return
        self._chunks += 1
        self._parse(line)

    def _parse(self, raw: bytes | bytearray) -> None:
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError):
            return
        if not isinstance(data, dict):
            return
        if "eval_count" in data or "prompt_eval_count" in data:
            self._usage = Usage(_count(data.get("prompt_eval_count")), _count(data.get("eval_count")), True)
        usage = data.get("usage")
        if isinstance(usage, dict) and ("prompt_tokens" in usage or "completion_tokens" in usage):
            self._usage = Usage(_count(usage.get("prompt_tokens")), _count(usage.get("completion_tokens")), True)

    def result(self) -> Usage:
        if self._buf:
            if self.sse or self.ndjson:
                self._line(bytes(self._buf))
            else:
                self._parse(self._buf)  # a complete non-streamed JSON body
            self._buf = bytearray()
        if self._usage is not None:
            return self._usage
        # Incomplete or unreported: estimate so interrupted streams still count.
        return Usage(
            prompt_tokens=self.request_body_len // BYTES_PER_TOKEN,
            completion_tokens=self._chunks,
            exact=False,
        )
