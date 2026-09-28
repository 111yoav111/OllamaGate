"""Build and run the uvicorn server with our TLS settings."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from ..config import Config
from . import tls

log = logging.getLogger("ollamagate")


@dataclass
class TLSInfo:
    cert_path: Path
    key_path: Path
    fingerprint: str  # sha256 hex of the DER certificate


def prepare_tls(config: Config) -> TLSInfo | None:
    if config.tls.mode == "off":
        return None
    if config.tls.mode == "files":
        cert, key = Path(config.tls.cert_file), Path(config.tls.key_file)
    else:
        sans = tls.default_sans(config.server.host, config.tls.extra_sans)
        cert, key = tls.ensure_self_signed(config.config_dir / "tls", sans)
    return TLSInfo(cert, key, tls.cert_fingerprint(cert))


def build_server(config: Config, app: FastAPI, tls_info: TLSInfo | None) -> uvicorn.Server:
    uv_config = uvicorn.Config(
        app,
        host=config.server.host,
        port=config.server.port,
        # We resolve client IPs ourselves, only trusting configured proxies.
        proxy_headers=False,
        server_header=False,
        date_header=False,
        access_log=False,  # our own request log never records secrets or content
        log_level="warning",
        ssl_certfile=str(tls_info.cert_path) if tls_info else None,
        ssl_keyfile=str(tls_info.key_path) if tls_info else None,
        timeout_keep_alive=30,
    )
    uv_config.load()
    if tls_info:
        # Replace uvicorn's default context with our hardened one (TLS 1.2+, AEAD only).
        uv_config.ssl = tls.build_server_context(tls_info.cert_path, tls_info.key_path)
    return uvicorn.Server(uv_config)
