"""Local-only admin control channel between the CLI and the running server.

All state lives in the server's memory, so CLI commands such as
``ollamagate devices revoke`` must talk to the running process. They do so
over a channel that is never reachable from the network:

* POSIX: a Unix domain socket in a ``0700`` directory, created ``0600``.
* Windows: a TCP socket bound to ``127.0.0.1`` on a random port.

On both, every request must also carry a 256-bit secret that the server writes
to an owner-only ``admin.json`` file next to the socket. The files are removed
on shutdown. Messages are single-line JSON.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import secrets
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

log = logging.getLogger("ollamagate.admin")

MAX_MESSAGE = 64 * 1024
Handler = Callable[[str, dict[str, Any]], Awaitable[Any]]


class AdminError(Exception):
    """An error meant to be shown to the admin (bad device id, etc.)."""


class NotRunning(Exception):
    pass


def run_dir(config_dir: Path) -> Path:
    return config_dir / "run"


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(path, 0o700)


def _write_private_json(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(data).encode())
    finally:
        os.close(fd)
    os.replace(tmp, path)


def use_unix_socket() -> bool:
    return sys.platform != "win32" and hasattr(socket, "AF_UNIX")


@dataclass
class ControlServer:
    server: asyncio.AbstractServer
    info_path: Path
    socket_path: Path | None

    async def close(self) -> None:
        self.server.close()
        await self.server.wait_closed()
        for p in (self.info_path, self.socket_path):
            if p is not None:
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass


async def _serve_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, secret: str, handler: Handler
) -> None:
    try:
        while True:
            try:
                line = await reader.readline()
            except (asyncio.LimitOverrunError, ValueError):
                break
            if not line:
                break
            try:
                request = json.loads(line)
                if not isinstance(request, dict):
                    raise ValueError
            except ValueError:
                reply: dict[str, Any] = {"ok": False, "error": "malformed request"}
            else:
                given = request.get("secret")
                if not isinstance(given, str) or not hmac.compare_digest(given, secret):
                    writer.write(json.dumps({"ok": False, "error": "unauthorized"}).encode() + b"\n")
                    await writer.drain()
                    break
                cmd, args = request.get("cmd"), request.get("args") or {}
                if not isinstance(cmd, str) or not isinstance(args, dict):
                    reply = {"ok": False, "error": "malformed request"}
                else:
                    try:
                        reply = {"ok": True, "result": await handler(cmd, args)}
                    except AdminError as exc:
                        reply = {"ok": False, "error": str(exc)}
                    except Exception:  # noqa: BLE001 - never kill the server over an admin command
                        log.exception("admin command %s failed", cmd)
                        reply = {"ok": False, "error": "internal error"}
            writer.write(json.dumps(reply).encode() + b"\n")
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


def _socket_in_use(path: Path) -> bool:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect(str(path))
        return True
    except OSError:
        return False


async def start_control_server(config_dir: Path, handler: Handler) -> ControlServer:
    rdir = run_dir(config_dir)
    _private_dir(rdir)
    info_path = rdir / "admin.json"
    secret = secrets.token_urlsafe(32)

    async def on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _serve_connection(reader, writer, secret, handler)

    if use_unix_socket():
        sock_path = rdir / "admin.sock"
        if sock_path.exists():
            if _socket_in_use(sock_path):
                raise RuntimeError("another OllamaGate instance is already running")
            sock_path.unlink()
        old_umask = os.umask(0o177)
        try:
            server = await asyncio.start_unix_server(on_connect, path=str(sock_path), limit=MAX_MESSAGE)
        finally:
            os.umask(old_umask)
        os.chmod(sock_path, 0o600)
        info = {"transport": "unix", "path": str(sock_path), "secret": secret, "pid": os.getpid()}
    else:
        sock_path = None
        server = await asyncio.start_server(on_connect, host="127.0.0.1", port=0, limit=MAX_MESSAGE)
        port = server.sockets[0].getsockname()[1]
        info = {"transport": "tcp", "port": port, "secret": secret, "pid": os.getpid()}
    _write_private_json(info_path, info)
    return ControlServer(server, info_path, sock_path)


class ControlClient:
    """Synchronous client used by the CLI."""

    def __init__(self, config_dir: Path, timeout: float = 10.0) -> None:
        info_path = run_dir(config_dir) / "admin.json"
        try:
            self.info = json.loads(info_path.read_text())
        except (OSError, ValueError) as exc:
            raise NotRunning("OllamaGate is not running (no admin socket found)") from exc
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = b""

    def _connect(self) -> socket.socket:
        if self._sock is not None:
            return self._sock
        try:
            if self.info.get("transport") == "unix":
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect(self.info["path"])
            else:
                sock = socket.create_connection(("127.0.0.1", int(self.info["port"])), timeout=self.timeout)
        except (OSError, KeyError, ValueError) as exc:
            raise NotRunning("OllamaGate is not running (admin socket unreachable)") from exc
        self._sock = sock
        return sock

    def call(self, cmd: str, **args: Any) -> Any:
        sock = self._connect()
        payload = {"secret": self.info.get("secret"), "cmd": cmd, "args": args}
        sock.sendall(json.dumps(payload).encode() + b"\n")
        while b"\n" not in self._buf:
            chunk = sock.recv(65536)
            if not chunk:
                raise NotRunning("admin connection closed")
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        reply = json.loads(line)
        if not reply.get("ok"):
            raise AdminError(reply.get("error", "error"))
        return reply.get("result")

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "ControlClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
