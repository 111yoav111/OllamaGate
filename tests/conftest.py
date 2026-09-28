from __future__ import annotations

import asyncio
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx
import pytest
import uvicorn

from ollamagate.config import Config
from ollamagate.server import auth
from ollamagate.server.app import create_app
from ollamagate.server.runner import build_server
from ollamagate.state import Device, State

from .fake_ollama import Recorder, make_fake_ollama


class ThreadedServer:
    """Run an ASGI app under a real uvicorn server in a background thread."""

    def __init__(self, app: Any = None, ssl_context: Any = None, server: uvicorn.Server | None = None, **kwargs: Any) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        if server is None:
            config = uvicorn.Config(
                app, log_level="warning", lifespan="on", proxy_headers=False, server_header=False, **kwargs
            )
            config.load()
            if ssl_context is not None:
                config.ssl = ssl_context
            server = uvicorn.Server(config)
        self.server = server
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.sock]}, daemon=True)

    def start(self) -> "ThreadedServer":
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started:
            if time.time() > deadline or not self.thread.is_alive():
                raise RuntimeError("server failed to start")
            time.sleep(0.01)
        return self

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@dataclass
class Gate:
    url: str
    state: State
    app: Any
    recorder: Recorder
    token: str
    device: Device
    server: Any = None

    def call(self, fn: Callable[[], Any]) -> Any:
        """Run ``fn`` on the gate's event loop (state mutations must happen there)."""
        loop: asyncio.AbstractEventLoop = self.app.state.loop

        async def run() -> Any:
            return fn()

        return asyncio.run_coroutine_threadsafe(run(), loop).result(timeout=5)

    def run(self, coro: Any) -> Any:
        """Run a coroutine on the gate's event loop and return its result."""
        return asyncio.run_coroutine_threadsafe(coro, self.app.state.loop).result(timeout=5)

    def new_device(self, name: str = "extra", **kwargs: Any) -> tuple[str, Device]:
        token = auth.new_device_token()
        device = self.call(
            lambda: self.state.add_device(
                name=name,
                token_hash=auth.hash_token(token),
                token_prefix=auth.display_prefix(token),
                paired_via="test",
                **kwargs,
            )
        )
        return token, device


@pytest.fixture
def fake_ollama():
    app, rec = make_fake_ollama()
    server = ThreadedServer(app).start()
    yield server, rec
    server.stop()


@pytest.fixture
def make_config(tmp_path):
    def factory(ollama_url: str, **overrides: Any) -> Config:
        cfg = Config()
        cfg.config_dir = tmp_path
        cfg.tls.mode = "off"
        cfg.ollama.url = ollama_url
        cfg.ollama.read_timeout = 10
        for dotted, value in overrides.items():
            section, key = dotted.split("__")
            setattr(getattr(cfg, section), key, value)
        cfg.validate()
        return cfg

    return factory


@pytest.fixture
def gate_factory(fake_ollama, make_config):
    servers: list[ThreadedServer] = []

    def factory(**overrides: Any) -> Gate:
        upstream, rec = fake_ollama
        cfg = make_config(upstream.url, **overrides)
        state = State()
        token = auth.new_device_token()
        device = state.add_device(
            name="phone", token_hash=auth.hash_token(token), token_prefix=auth.display_prefix(token), paired_via="test"
        )
        app = create_app(cfg, state, fingerprint="ab" * 32)
        # Use the production uvicorn config (guarded protocol, limits, shutdown hook).
        gate_server = build_server(cfg, app, state, None)
        gate_server.config.log_level = "warning"
        server = ThreadedServer(server=gate_server).start()
        servers.append(server)
        return Gate(server.url, state, app, rec, token, device, gate_server)

    yield factory
    for s in servers:
        s.stop()
        assert not s.thread.is_alive(), "gate did not shut down"


@pytest.fixture
def gate(gate_factory) -> Gate:
    return gate_factory()


@pytest.fixture
def client():
    with httpx.Client(timeout=10) as c:
        yield c
