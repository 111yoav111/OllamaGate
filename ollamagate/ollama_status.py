"""Ask the local Ollama for its version and loaded models (for the dashboard)."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from .textsafe import safe_text


@dataclass
class LoadedModel:
    name: str
    size: int
    size_vram: int


@dataclass
class OllamaStatus:
    reachable: bool
    version: str = ""
    models: list[LoadedModel] = field(default_factory=list)
    error: str = ""


async def probe(client: httpx.AsyncClient) -> OllamaStatus:
    try:
        version = (await client.get("/api/version", timeout=3)).json().get("version", "")
        ps = (await client.get("/api/ps", timeout=3)).json().get("models", []) or []
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        return OllamaStatus(reachable=False, error=type(exc).__name__)
    models = []
    for m in ps if isinstance(ps, list) else []:
        if isinstance(m, dict):
            models.append(
                LoadedModel(
                    name=safe_text(str(m.get("name", "?")), 80),
                    size=_int(m.get("size")),
                    size_vram=_int(m.get("size_vram")),
                )
            )
    return OllamaStatus(reachable=True, version=safe_text(str(version), 40), models=models)


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**63 else 0


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{n} B"
