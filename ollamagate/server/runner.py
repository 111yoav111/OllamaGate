"""Build and run the uvicorn server with our TLS and connection settings."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from ..config import Config
from ..state import State
from . import tls
from .netutil import parse_networks
from .protocol import make_guarded_protocol

log = logging.getLogger("ollamagate")

GRACEFUL_SHUTDOWN_SECONDS = 5


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


class GateServer(uvicorn.Server):
    """uvicorn server that cuts active streams as soon as shutdown begins.

    uvicorn waits for open connections before running the app's lifespan
    shutdown, so long-running generations would otherwise block exit.
    """

    def __init__(self, config: uvicorn.Config, state: State) -> None:
        super().__init__(config)
        self.gate_state = state

    async def shutdown(self, sockets: list | None = None) -> None:  # type: ignore[override]
        self.gate_state.kill_all_streams("server shutting down")
        await super().shutdown(sockets)


def build_uvicorn_config(config: Config, app: FastAPI, tls_info: TLSInfo | None) -> uvicorn.Config:
    protocol = make_guarded_protocol(
        header_timeout=config.server.header_timeout,
        max_connections_per_ip=config.server.max_connections_per_ip,
        trusted=parse_networks(config.network.trusted_proxies),
    )
    uv_config = uvicorn.Config(
        app,
        host=config.server.host,
        port=config.server.port,
        http=protocol,
        # We resolve client IPs ourselves, only trusting configured proxies.
        proxy_headers=False,
        server_header=False,
        date_header=False,
        access_log=False,  # our own request log never records secrets or content
        log_level="warning",
        ssl_certfile=str(tls_info.cert_path) if tls_info else None,
        ssl_keyfile=str(tls_info.key_path) if tls_info else None,
        timeout_keep_alive=30,
        limit_concurrency=config.server.max_connections,
        h11_max_incomplete_event_size=16 * 1024,
        timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS,
    )
    uv_config.load()
    if tls_info:
        # Replace uvicorn's default context with our hardened one (TLS 1.2+, AEAD only).
        uv_config.ssl = tls.build_server_context(tls_info.cert_path, tls_info.key_path)
    return uv_config


def build_server(config: Config, app: FastAPI, state: State, tls_info: TLSInfo | None) -> GateServer:
    return GateServer(build_uvicorn_config(config, app, tls_info), state)
