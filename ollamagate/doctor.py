"""Setup checks: is Ollama exposed beyond loopback, is TLS sane, etc."""

from __future__ import annotations

import ipaddress
import os
import socket
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .config import Config, is_loopback_host


@dataclass
class Finding:
    level: str  # ok | warn | error
    title: str
    fix: str = ""


def local_ip_addresses() -> list[str]:
    """Best-effort list of this machine's non-loopback IP addresses."""
    addrs: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addrs.add(str(info[4][0]))
    except OSError:
        pass
    # The UDP "connect" trick reveals the primary outbound address; no packet is sent.
    for family, target in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.connect((target, 9))
                addrs.add(s.getsockname()[0])
        except OSError:
            pass
    result = []
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a.split("%")[0])
        except ValueError:
            continue
        if not ip.is_loopback and not ip.is_unspecified and not ip.is_link_local:
            result.append(str(ip))
    return sorted(result)


def ollama_exposed_on(port: int, timeout: float = 0.5) -> list[str]:
    """Return the non-loopback addresses on which something accepts connections on ``port``."""
    exposed = []
    for addr in local_ip_addresses():
        try:
            with socket.create_connection((addr, port), timeout=timeout):
                exposed.append(addr)
        except OSError:
            continue
    return exposed


OLLAMA_FIX = "Bind Ollama to loopback: set OLLAMA_HOST=127.0.0.1 and restart Ollama."


def check_ollama_binding(config: Config) -> list[Finding]:
    findings = []
    env_host = os.environ.get("OLLAMA_HOST", "")
    if env_host:
        host = urlsplit(env_host if "://" in env_host else f"http://{env_host}").hostname or ""
        if host and not is_loopback_host(host):
            findings.append(Finding("error", f"OLLAMA_HOST is set to {env_host!r} (not loopback)", OLLAMA_FIX))
    port = urlsplit(config.ollama.url).port or 11434
    exposed = ollama_exposed_on(port)
    if exposed:
        findings.append(
            Finding("error", f"Ollama port {port} is reachable on {', '.join(exposed)}", OLLAMA_FIX)
        )
    if not findings:
        findings.append(Finding("ok", "Ollama is not reachable on non-loopback interfaces"))
    return findings


def _owner_only(path: Path) -> bool:
    if sys.platform == "win32":
        return True  # POSIX modes don't apply; rely on the per-user profile directory ACLs
    mode = path.stat().st_mode
    return not (mode & (stat.S_IRWXG | stat.S_IRWXO))


def check_files(config: Config) -> list[Finding]:
    findings = []
    for name in ("config.toml", "tls/key.pem"):
        path = config.config_dir / name
        if path.exists() and not _owner_only(path):
            findings.append(
                Finding("warn", f"{path} is readable by other users", f"chmod 600 {path}")
            )
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        findings.append(Finding("error", "Running as root", "Run OllamaGate as a normal user."))
    return findings


def check_config(config: Config) -> list[Finding]:
    findings = []
    if config.tls.mode == "self-signed":
        findings.append(
            Finding(
                "warn",
                "Using a self-signed certificate; browsers will show a warning",
                "Consider network.mode = 'tailscale' or a real certificate.",
            )
        )
    if config.logging.log_content:
        findings.append(Finding("warn", "Prompt/response content logging is enabled", "Set logging.log_content = false."))
    if config.server.host in ("0.0.0.0", "::") and config.network.mode == "direct":
        findings.append(
            Finding("warn", "Listening on all interfaces", "Bind to a specific interface (e.g. your Tailscale IP) if possible.")
        )
    return findings


def run_all(config: Config) -> list[Finding]:
    return check_ollama_binding(config) + check_files(config) + check_config(config)
