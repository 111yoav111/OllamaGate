"""Build and run the uvicorn server with our TLS and connection settings."""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import signal
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import uvicorn
from fastapi import FastAPI

from ..config import Config
from ..state import State
from . import tls
from .netutil import parse_networks
from .protocol import make_guarded_protocol

log = logging.getLogger("ollamagate")

GRACEFUL_SHUTDOWN_SECONDS = 5
# Our per-IP cap and header deadline start only once TLS is up (asyncio calls
# connection_made after the handshake), so a client that never sends a
# ClientHello is only bounded by this. asyncio's default is 60 s.
TLS_HANDSHAKE_TIMEOUT = 10.0


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

    async def startup(self, sockets: list | None = None) -> None:  # type: ignore[override]
        raise_fd_limit()
        loop = asyncio.get_running_loop()
        if self.config.ssl is not None:
            # uvicorn doesn't expose ssl_handshake_timeout; pass it to the create_server it calls.
            loop.create_server = functools.partial(loop.create_server, ssl_handshake_timeout=TLS_HANDSHAKE_TIMEOUT)  # type: ignore[method-assign]
        try:
            await super().startup(sockets)
        finally:
            loop.__dict__.pop("create_server", None)

    async def shutdown(self, sockets: list | None = None) -> None:  # type: ignore[override]
        self.gate_state.kill_all_streams("server shutting down")
        await super().shutdown(sockets)

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        """Like uvicorn's, but don't re-raise the signal afterwards.

        uvicorn re-raises SIGINT/SIGTERM once serving stops, which kills the
        process before our own cleanup (removing the admin socket) can run.
        """
        if threading.current_thread() is not threading.main_thread():
            yield
            return
        signals = [signal.SIGINT, signal.SIGTERM]
        if hasattr(signal, "SIGBREAK"):  # Windows Ctrl+Break
            signals.append(signal.SIGBREAK)
        original = {sig: signal.signal(sig, self.handle_exit) for sig in signals}
        try:
            yield
        finally:
            for sig, handler in original.items():
                signal.signal(sig, handler)


def raise_fd_limit() -> None:
    """Use the hard file-descriptor limit (often 1024 soft) so idle sockets can't starve us."""
    try:
        import resource
    except ImportError:  # Windows
        return
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = hard if hard != resource.RLIM_INFINITY else 65536
    if soft != resource.RLIM_INFINITY and soft < target:
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(target, 65536), hard))


def build_uvicorn_config(
    config: Config,
    app: FastAPI,
    tls_info: TLSInfo | None,
    own_logging: bool = True,
    client_ca: tls.ClientCA | None = None,
) -> uvicorn.Config:
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
        # own_logging=False: leave logging alone so uvicorn's records reach our handlers
        # (the TUI's in-memory buffer) instead of being written over the TUI.
        log_config=uvicorn.config.LOGGING_CONFIG if own_logging else None,
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
        uv_config.ssl = tls.build_server_context(
            tls_info.cert_path, tls_info.key_path, client_ca.pem if client_ca else None
        )
        if client_ca is not None:
            client_ca.context = uv_config.ssl
    return uv_config


def build_server(
    config: Config,
    app: FastAPI,
    state: State,
    tls_info: TLSInfo | None,
    own_logging: bool = True,
    client_ca: tls.ClientCA | None = None,
) -> GateServer:
    return GateServer(build_uvicorn_config(config, app, tls_info, own_logging, client_ca), state)
