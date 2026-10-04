"""Request policy: which Ollama endpoints exist, who may call them, and how
request bodies are checked and clamped against a device's limits."""

from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass

from ..state import DeviceLimits


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

# fullmatch, not "$": "$" also matches before a trailing newline (a decoded "%0A").
_BLOB_RE = re.compile(r"/api/blobs/sha256[:\-][0-9a-f]{64}")
_MODEL_PREFIX = "/v1/models/"
_MODEL_SEGMENT_RE = re.compile(r"[A-Za-z0-9_:\-.]+")


def _is_model_path(path: str) -> bool:
    """``/v1/models/<name>`` with names like "library/llama3:8b".

    Checked segment by segment (a single nested-quantifier regex backtracks
    exponentially on a near-miss). Every segment must contain a non-dot
    character so "." / ".." segments (which httpx normalises away) can't be used.
    """
    if len(path) > 256 or not path.startswith(_MODEL_PREFIX) or ".." in path:
        return False
    segments = path[len(_MODEL_PREFIX) :].split("/")
    return len(segments) <= 8 and all(_MODEL_SEGMENT_RE.fullmatch(s) and s.strip(".") for s in segments)


def classify_endpoint(method: str, path: str) -> EndpointKind | None:
    """Return the endpoint kind, or ``None`` if the path is not an allowed endpoint."""
    kind = _EXACT.get((method, path))
    if kind is not None:
        return kind
    if method in ("HEAD", "POST") and _BLOB_RE.fullmatch(path):
        return EndpointKind.MANAGEMENT
    if method == "GET" and _is_model_path(path):
        return EndpointKind.INFERENCE
    return None


# ----- body policy ----------------------------------------------------------------------

# Endpoints whose JSON body names a model that must be on the device's allowlist.
_MODEL_ENDPOINTS = {
    "/api/generate", "/api/chat", "/api/embed", "/api/embeddings", "/api/show",
    "/v1/chat/completions", "/v1/completions", "/v1/embeddings",
}
# Endpoints that generate text (and therefore get output-length clamps).
_GENERATE_API = {"/api/generate", "/api/chat"}
_GENERATE_V1 = {"/v1/chat/completions", "/v1/completions"}
# Endpoints whose token usage counts against quotas.
ACCOUNTED_ENDPOINTS = _MODEL_ENDPOINTS - {"/api/show"}
MAX_KEEP_ALIVE_SECONDS = 30 * 60


@dataclass
class PolicyResult:
    body: bytes
    model: str = ""
    error: str | None = None  # set => reject with ``status``
    status: int = 400
    streaming: bool = False


def normalize_model(name: str) -> str:
    """"llama3" and "llama3:latest" are the same model to Ollama."""
    name = name.strip().lower()
    return name if ":" in name.rsplit("/", 1)[-1] else name + ":latest"


def model_allowed(limits: DeviceLimits, model: str) -> bool:
    if not limits.allowed_models:
        return True
    wanted = normalize_model(model)
    return any(normalize_model(m) == wanted for m in limits.allowed_models)


def _keep_alive_seconds(value: object) -> float | None:
    """Ollama accepts numbers (seconds) or durations like "5m"; None if unparseable."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        units = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}
        for suffix in ("ms", "s", "m", "h"):
            if value.endswith(suffix):
                try:
                    return float(value[: -len(suffix)]) * units[suffix]
                except ValueError:
                    return None
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _clamp_int(value: object, maximum: int) -> int:
    """Clamp a client-supplied limit; anything missing, negative ("infinite") or bogus -> maximum."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return maximum
    return int(min(value, maximum))


# Ollama decodes bodies with Go's encoding/json, which matches struct field
# names case-insensitively (with Unicode folding: "ſtream" == "stream") and lets
# the last match win. A body with both "model" and "MODEL" would therefore pass
# our checks on one key while Ollama used the other. So where Go does struct
# matching (top level, options, stream_options) only plain lowercase ASCII keys
# are accepted - every real field name is written that way anyway.
_PLAIN_KEY = re.compile(r"[a-z0-9_]{1,64}")
_NATIVE_OPTION_ENDPOINTS = {"/api/generate", "/api/chat", "/api/embed", "/api/embeddings"}


def _keys_are_plain(obj: dict) -> bool:
    return all(_PLAIN_KEY.fullmatch(k) for k in obj)


def _reject_constant(name: str) -> None:
    raise ValueError(f"{name} is not valid JSON")  # NaN / Infinity: Python accepts them, Go doesn't


def _loads(body: bytes) -> object:
    return json.loads(body, parse_constant=_reject_constant) if body else None


# Pull/push take {"insecure": true}, which lets Ollama fetch over plain HTTP
# from any host - a way for a device to make it talk to the owner's LAN.
_REGISTRY_ENDPOINTS = {"/api/pull", "/api/push"}


def _registry_policy(body: bytes) -> PolicyResult:
    try:
        data = _loads(body)
    except (ValueError, RecursionError):
        return PolicyResult(body, error="request body must be JSON")
    if not isinstance(data, dict) or not _keys_are_plain(data):
        return PolicyResult(body, error="request keys must be lowercase field names")
    if data.get("insecure"):
        return PolicyResult(body, error="insecure registries are not allowed", status=403)
    return PolicyResult(json.dumps(data).encode())


def apply_body_policy(
    limits: DeviceLimits, path: str, body: bytes, remaining_tokens: int | None = None
) -> PolicyResult:
    """Validate and rewrite a request body according to the device's limits.

    Only JSON bodies of model endpoints are touched. The body is always
    re-serialised from what was checked, so duplicate keys (Python keeps the
    last, Go merges objects) can't hide a value from us. ``remaining_tokens`` (when a
    quota applies) further caps the output length so one request can't
    overshoot the quota by much.
    """
    if path in _REGISTRY_ENDPOINTS:
        return _registry_policy(body)
    if path not in _MODEL_ENDPOINTS:
        return PolicyResult(body)
    try:
        data = _loads(body)
    except (ValueError, RecursionError):
        return PolicyResult(body, error="request body must be JSON")
    if not isinstance(data, dict):
        return PolicyResult(body, error="request body must be a JSON object")
    for obj in (data, data.get("options"), data.get("stream_options")):
        if isinstance(obj, dict) and not _keys_are_plain(obj):
            return PolicyResult(body, error="request keys must be lowercase field names")
    model = data.get("model")
    if path == "/api/show" and not model:
        model = data.get("name")  # older clients; Ollama falls back to it the same way
    if not isinstance(model, str) or not model or len(model) > 200:
        return PolicyResult(body, error="a model name is required")
    if not model_allowed(limits, model):
        return PolicyResult(body, model=model, error="model not allowed for this device", status=403)

    max_predict = limits.max_num_predict
    if remaining_tokens is not None:
        max_predict = max(1, min(max_predict, remaining_tokens) if max_predict else remaining_tokens)

    streaming = False
    if path in _NATIVE_OPTION_ENDPOINTS:
        options = data.get("options")
        if options is None:
            options = {}
        if not isinstance(options, dict):
            return PolicyResult(body, model=model, error="options must be an object")
        caps = []
        # num_ctx is only clamped when asked for: adding it would override Ollama's
        # own default (and force model reloads when clients mix settings).
        # Embeddings load a context too, so they are covered.
        if "num_ctx" in options:
            caps.append(("num_ctx", limits.max_num_ctx))
        # num_predict is always set for generation, so every answer is bounded.
        if path in _GENERATE_API:
            caps.append(("num_predict", max_predict))
        for key, maximum in caps:
            if maximum > 0:
                options[key] = _clamp_int(options.get(key), maximum)
        if options or "options" in data:
            data["options"] = options
        if path in _GENERATE_API:
            streaming = data.get("stream", True) is not False  # Ollama streams by default
    elif path in _GENERATE_V1:
        if max_predict > 0:
            for key in ("max_tokens", "max_completion_tokens"):
                if key in data or key == "max_tokens":
                    data[key] = _clamp_int(data.get(key), max_predict)
        streaming = data.get("stream") is True
        if streaming:
            # Ask for a final usage chunk so the stream can be accounted for.
            opts = data.get("stream_options")
            if not isinstance(opts, dict):
                opts = {}
            opts["include_usage"] = True
            data["stream_options"] = opts

    if "keep_alive" in data:
        seconds = _keep_alive_seconds(data["keep_alive"])
        if seconds is None or not 0 <= seconds <= MAX_KEEP_ALIVE_SECONDS:  # NaN fails too
            data["keep_alive"] = f"{MAX_KEEP_ALIVE_SECONDS // 60}m"

    return PolicyResult(json.dumps(data).encode(), model=model, streaming=streaming)


def filter_model_list(limits: DeviceLimits, path: str, body: bytes) -> bytes:
    """Hide models the device may not use from /api/tags, /api/ps and /v1/models.

    Fails closed: anything that doesn't look like a model list comes back empty.
    """
    if not limits.allowed_models:
        return body
    list_key, name_key = ("data", "id") if path == "/v1/models" else ("models", "name")
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        data = None
    if not isinstance(data, dict) or not isinstance(data.get(list_key), list):
        return json.dumps({list_key: []}).encode()
    data[list_key] = [
        m for m in data[list_key]
        if isinstance(m, dict) and isinstance(m.get(name_key), str) and model_allowed(limits, m[name_key])
    ]
    return json.dumps(data).encode()


# ----- response scrubbing ---------------------------------------------------------------

# An absolute host path: "/x/" not glued to a word, URL or relative path, a
# drive letter ("C:\" / "C:/") or a UNC share ("\\host").
_ABS_PATH_RE = re.compile(r"(?<![\w/:.~-])/[^\s/'\"]+/|\b[A-Za-z]:[\\/]|\\\\[^\s\\]")
_MODELFILE_PATH_RE = re.compile(r"^(FROM|ADAPTER)[ \t]+(\S.*)$", re.MULTILINE)
SCRUBBED_PATHS = {"/api/tags", "/api/ps", "/api/show"}
GENERIC_UPSTREAM_ERROR = "upstream error"


def has_host_path(text: str) -> bool:
    return bool(_ABS_PATH_RE.search(text))


def _scrub_error(body: bytes) -> bytes:
    """Ollama passes raw Go errors through, e.g. ``open /home/x/.ollama/...``."""
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        data = None
    if isinstance(data, dict):
        err = data.get("error")
        message = err.get("message") if isinstance(err, dict) else err
        if isinstance(message, str) and not has_host_path(message):
            return body
    return json.dumps({"error": GENERIC_UPSTREAM_ERROR}).encode()


def _scrub_details(item: object) -> None:
    details = item.get("details") if isinstance(item, dict) else None
    if isinstance(details, dict) and isinstance(details.get("parent_model"), str) and has_host_path(details["parent_model"]):
        details["parent_model"] = ""


def _scrub_modelfile(text: str, model: str) -> str:
    def fix(m: re.Match[str]) -> str:
        if not has_host_path(m.group(2)):
            return m.group(0)
        return f"FROM {model}" if m.group(1) == "FROM" else "# ADAPTER (local path hidden)"

    return _MODELFILE_PATH_RE.sub(fix, text)


def scrub_response(path: str, status: int, body: bytes, model: str = "") -> bytes:
    """Hide the host's file paths from Ollama responses before they leave.

    Covers error bodies, ``details.parent_model`` in listings and the
    ``FROM``/``ADAPTER`` lines of ``/api/show``'s Modelfile. Fails closed:
    a body that isn't the JSON we expect is replaced.
    """
    if status >= 400:
        return _scrub_error(body)
    if path not in SCRUBBED_PATHS:
        return body
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        data = None
    if not isinstance(data, dict):
        return json.dumps({"models": []} if path != "/api/show" else {}).encode()
    if path == "/api/show":
        _scrub_details(data)
        if isinstance(data.get("modelfile"), str):
            data["modelfile"] = _scrub_modelfile(data["modelfile"], model or "model")
    elif isinstance(data.get("models"), list):
        for item in data["models"]:
            _scrub_details(item)
    return json.dumps(data).encode()
