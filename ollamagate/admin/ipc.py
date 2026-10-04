"""Local-only admin control channel between the CLI and the running server.

All state lives in the server's memory, so CLI commands such as
``ollamagate devices revoke`` must talk to the running process. They do so
over a channel that is never reachable from the network:

* POSIX: a Unix domain socket in a ``0700`` directory, created ``0600``.
* Windows: a TCP socket bound to ``127.0.0.1`` on a random port.

On both, every request must carry a 256-bit secret that the server writes to
an owner-only ``admin.json`` file, and every reply carries an HMAC proof over
a fresh client nonce, so the CLI can't be fooled by another local process
that grabbed a stale port. The files are removed on shutdown. Messages are
single-line JSON.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

log = logging.getLogger("ollamagate.admin")

MAX_MESSAGE = 64 * 1024
IDLE_TIMEOUT = 30.0
# AF_UNIX paths are limited to ~104 bytes on macOS and 108 on Linux.
MAX_UNIX_PATH = 100
Handler = Callable[[str, dict[str, Any]], Awaitable[Any]]

__all__ = ["AdminError", "NotRunning", "ControlClient", "start_control_server", "run_dir"]


class AdminError(Exception):
    """An error meant to be shown to the admin (bad device id, etc.)."""


class NotRunning(Exception):
    pass


def run_dir(config_dir: Path) -> Path:
    return config_dir / "run"


def _proof(secret: str, nonce: str) -> str:
    return hmac.new(secret.encode(), b"ollamagate-server:" + nonce.encode(), hashlib.sha256).hexdigest()


def _private_dir(path: Path) -> None:
    """Create ``path`` as a directory only we can use; refuse anything suspicious."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)  # never briefly group/world-readable
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"{path} must be a real directory, not a symlink")
    if sys.platform != "win32":
        if st.st_uid != os.getuid():
            raise RuntimeError(f"{path} is not owned by the current user")
        os.chmod(path, 0o700)


def _write_private_json(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_suffix(".tmp")
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, json.dumps(data).encode())
    finally:
        os.close(fd)
    os.replace(tmp, path)


def use_unix_socket() -> bool:
    return sys.platform != "win32" and hasattr(socket, "AF_UNIX")


def _parse(line: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(line)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


@dataclass
class ControlServer:
    server: asyncio.AbstractServer
    info_path: Path
    socket_path: Path | None
    secret: str
    writers: set[asyncio.StreamWriter] = field(default_factory=set)
    temp_dir: Path | None = None

    async def close(self) -> None:
        self.server.close()
        # Python 3.12+ waits for open connections in wait_closed(); close them first.
        for writer in list(self.writers):
            writer.close()
        await self.server.wait_closed()
        # Only remove admin.json if it is still ours (another instance may own it now).
        try:
            if json.loads(self.info_path.read_text()).get("secret") == self.secret:
                self.info_path.unlink()
        except (OSError, ValueError):
            pass
        if self.socket_path is not None:
            try:
                self.socket_path.unlink()
            except FileNotFoundError:
                pass
        if self.temp_dir is not None:
            try:
                self.temp_dir.rmdir()
            except OSError:
                pass


async def _serve_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, secret: str, handler: Handler
) -> None:
    async def reply(message: dict[str, Any]) -> None:
        writer.write(json.dumps(message).encode() + b"\n")
        await writer.drain()

    try:
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), IDLE_TIMEOUT)
            except (asyncio.TimeoutError, asyncio.LimitOverrunError, ValueError):
                break
            if not line:
                break
            request = _parse(line)
            if request is None:
                await reply({"ok": False, "error": "malformed request"})
                continue
            given, nonce = request.get("secret"), request.get("nonce")
            if (
                not isinstance(given, str)
                or not isinstance(nonce, str)
                or len(nonce) > 128
                or not hmac.compare_digest(given.encode(), secret.encode())
            ):
                await reply({"ok": False, "error": "unauthorized"})
                break
            proof = _proof(secret, nonce)
            cmd, args = request.get("cmd"), request.get("args") or {}
            if not isinstance(cmd, str) or not isinstance(args, dict):
                await reply({"ok": False, "error": "malformed request", "proof": proof})
                continue
            try:
                message = {"ok": True, "result": await handler(cmd, args)}
            except AdminError as exc:
                message = {"ok": False, "error": str(exc)}
            except Exception:  # noqa: BLE001 - never kill the server over an admin command
                log.exception("admin command %s failed", cmd)
                message = {"ok": False, "error": "internal error"}
            message["proof"] = proof
            await reply(message)
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


def _alive(info_path: Path) -> bool:
    """Is an OllamaGate instance answering on the channel described by ``info_path``?"""
    try:
        client = ControlClient.from_info_file(info_path, timeout=1.0)
    except NotRunning:
        return False
    try:
        client.call("ping")
        return True
    except (NotRunning, AdminError):
        return False
    finally:
        client.close()


def _socket_path(rdir: Path) -> tuple[Path, Path | None]:
    path = rdir / "admin.sock"
    if len(str(path)) <= MAX_UNIX_PATH:
        return path, None
    temp_dir = Path(tempfile.mkdtemp(prefix="og-"))  # created 0700 by mkdtemp
    return temp_dir / "admin.sock", temp_dir


async def start_control_server(config_dir: Path, handler: Handler) -> ControlServer:
    rdir = run_dir(config_dir)
    _private_dir(rdir)
    info_path = rdir / "admin.json"
    if info_path.exists() and await asyncio.to_thread(_alive, info_path):
        raise RuntimeError("another OllamaGate instance is already running")
    secret = secrets.token_urlsafe(32)
    writers: set[asyncio.StreamWriter] = set()

    async def dispatch(cmd: str, args: dict[str, Any]) -> Any:
        if cmd == "ping":
            return "pong"
        return await handler(cmd, args)

    async def on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writers.add(writer)
        try:
            await _serve_connection(reader, writer, secret, dispatch)
        finally:
            writers.discard(writer)

    temp_dir = None
    if use_unix_socket():
        sock_path, temp_dir = _socket_path(rdir)
        if sock_path.exists() or sock_path.is_symlink():
            sock_path.unlink()  # stale: the liveness check above found no server
        old_umask = os.umask(0o177)
        try:
            server = await asyncio.start_unix_server(on_connect, path=str(sock_path), limit=MAX_MESSAGE)
        finally:
            os.umask(old_umask)
        os.chmod(sock_path, 0o600)
        info: dict[str, Any] = {"transport": "unix", "path": str(sock_path)}
    else:
        sock_path = None
        server = await asyncio.start_server(on_connect, host="127.0.0.1", port=0, limit=MAX_MESSAGE)
        info = {"transport": "tcp", "port": server.sockets[0].getsockname()[1]}
    info.update(secret=secret, pid=os.getpid())
    _write_private_json(info_path, info)
    return ControlServer(server, info_path, sock_path, secret, writers, temp_dir)


class ControlClient:
    """Synchronous client used by the CLI."""

    def __init__(self, config_dir: Path, timeout: float = 10.0) -> None:
        self._init(run_dir(config_dir) / "admin.json", timeout)

    @classmethod
    def from_info_file(cls, info_path: Path, timeout: float = 10.0) -> "ControlClient":
        client = cls.__new__(cls)
        client._init(info_path, timeout)
        return client

    def _init(self, info_path: Path, timeout: float) -> None:
        try:
            self.info = json.loads(info_path.read_text())
            if not isinstance(self.info, dict):
                raise ValueError
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
        except (OSError, KeyError, ValueError, TypeError) as exc:
            raise NotRunning("OllamaGate is not running (admin socket unreachable)") from exc
        self._sock = sock
        return sock

    def call(self, cmd: str, **args: Any) -> Any:
        secret = str(self.info.get("secret", ""))
        nonce = secrets.token_hex(16)
        payload = json.dumps({"secret": secret, "nonce": nonce, "cmd": cmd, "args": args}).encode() + b"\n"
        if len(payload) > MAX_MESSAGE:
            raise AdminError("request too large")
        try:
            sock = self._connect()
            sock.sendall(payload)
            while b"\n" not in self._buf:
                chunk = sock.recv(65536)
                if not chunk:
                    raise NotRunning("admin connection closed")
                self._buf += chunk
        except OSError as exc:  # timeouts, resets, broken pipes
            self.close()
            raise NotRunning(f"lost connection to OllamaGate ({type(exc).__name__})") from exc
        line, _, self._buf = self._buf.partition(b"\n")
        reply = _parse(line)
        if reply is None:
            raise NotRunning("invalid reply from admin channel")
        if reply.get("error") == "unauthorized" and "proof" not in reply:
            raise AdminError("unauthorized (is admin.json from another instance?)")
        proof = reply.get("proof")
        if not isinstance(proof, str) or not hmac.compare_digest(proof, _proof(secret, nonce)):
            raise NotRunning("admin channel did not prove it is OllamaGate; refusing to trust it")
        if not reply.get("ok"):
            raise AdminError(str(reply.get("error", "error")))
        return reply.get("result")

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "ControlClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
