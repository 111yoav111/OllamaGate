"""Request policy: which Ollama endpoints exist and who may call them."""

from __future__ import annotations

import enum
import re


class EndpointKind(enum.Enum):
    INFERENCE = "inference"  # chat, generate, embeddings, model listing
    MANAGEMENT = "management"  # pull/push/delete/create/copy/blobs - blocked by default


_EXACT: dict[tuple[str, str], EndpointKind] = {
    # Ollama native API
    ("POST", "/api/generate"): EndpointKind.INFERENCE,
    ("POST", "/api/chat"): EndpointKind.INFERENCE,
    ("POST", "/api/embed"): EndpointKind.INFERENCE,
    ("POST", "/api/embeddings"): EndpointKind.INFERENCE,
    ("GET", "/api/tags"): EndpointKind.INFERENCE,
    ("POST", "/api/show"): EndpointKind.INFERENCE,
    ("GET", "/api/ps"): EndpointKind.INFERENCE,
    ("GET", "/api/version"): EndpointKind.INFERENCE,
    ("POST", "/api/pull"): EndpointKind.MANAGEMENT,
    ("POST", "/api/push"): EndpointKind.MANAGEMENT,
    ("DELETE", "/api/delete"): EndpointKind.MANAGEMENT,
    ("POST", "/api/create"): EndpointKind.MANAGEMENT,
    ("POST", "/api/copy"): EndpointKind.MANAGEMENT,
    # OpenAI-compatible API
    ("POST", "/v1/chat/completions"): EndpointKind.INFERENCE,
    ("POST", "/v1/completions"): EndpointKind.INFERENCE,
    ("POST", "/v1/embeddings"): EndpointKind.INFERENCE,
    ("GET", "/v1/models"): EndpointKind.INFERENCE,
}

_BLOB_RE = re.compile(r"^/api/blobs/sha256[:\-][0-9a-f]{64}$")
_MODEL_RE = re.compile(r"^/v1/models/[A-Za-z0-9._:\-/]{1,200}$")


def classify_endpoint(method: str, path: str) -> EndpointKind | None:
    """Return the endpoint kind, or ``None`` if the path is not an allowed endpoint."""
    kind = _EXACT.get((method, path))
    if kind is not None:
        return kind
    if method in ("HEAD", "POST") and _BLOB_RE.match(path):
        return EndpointKind.MANAGEMENT
    if method == "GET" and _MODEL_RE.match(path) and ".." not in path:
        return EndpointKind.INFERENCE
    return None
