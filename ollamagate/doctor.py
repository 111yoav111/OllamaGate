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
    if config.logging.log_content:
        findings.append(Finding("warn", "Prompt/response content logging is enabled", "Set logging.log_content = false."))
    if config.server.host in ("0.0.0.0", "::") and config.network.mode == "direct":
        findings.append(
            Finding("warn", "Listening on all interfaces", "Bind to a specific interface (e.g. your Tailscale IP) if possible.")
        )
    return findings


def check_ollama_running(config: Config) -> list[Finding]:
    """Is Ollama answering where OllamaGate expects it?"""
    import httpx

    try:
        r = httpx.get(config.ollama.url.rstrip("/") + "/api/version", timeout=3, trust_env=False)
        version = r.json().get("version", "?")
    except (httpx.HTTPError, ValueError, AttributeError):
        return [Finding("error", f"Ollama is not answering at {config.ollama.url}", "Start Ollama (ollama serve).")]
    return [Finding("ok", f"Ollama {version} is running at {config.ollama.url}")]


def check_tls(config: Config) -> list[Finding]:
    """Certificate present, not about to expire, and valid for the public name."""
    import datetime as dt

    from cryptography import x509

    if config.tls.mode == "off":
        return [Finding("ok", "Plain HTTP on loopback only (TLS terminates at the tunnel)")]
    if config.tls.mode == "files":
        cert_path, key_path = Path(config.tls.cert_file), Path(config.tls.key_file)
    elif config.network.mode == "tailscale":
        cert_path, key_path = config.config_dir / "tls" / "tailscale.crt", config.config_dir / "tls" / "tailscale.key"
        if not cert_path.exists():
            return [Finding("ok", "The Tailscale certificate will be fetched on first start")]
    else:
        cert_path, key_path = config.config_dir / "tls" / "cert.pem", config.config_dir / "tls" / "key.pem"
        if not cert_path.exists():
            return [Finding("ok", "A self-signed certificate will be created on first start")]
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (OSError, ValueError) as exc:
        return [Finding("error", f"Cannot read certificate {cert_path}: {exc}", "Check tls.cert_file.")]
    findings = []
    if not key_path.exists():
        findings.append(Finding("error", f"Private key {key_path} is missing", "Check tls.key_file."))
    elif not _owner_only(key_path):
        findings.append(Finding("warn", f"{key_path} is readable by other users", f"chmod 600 {key_path}"))
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    days = (not_after - dt.datetime.now(dt.timezone.utc)).days
    if days < 0:
        findings.append(Finding("error", "The TLS certificate has expired", "Renew it (certbot renew / tailscale cert)."))
    elif days < 14:
        findings.append(Finding("warn", f"The TLS certificate expires in {days} days", "Renew it soon."))
    else:
        findings.append(Finding("ok", f"TLS certificate valid for {days} more days"))
    host = urlsplit(config.base_url).hostname or ""
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [n.lower() for n in sans.get_values_for_type(x509.DNSName)]
        names += [str(ip) for ip in sans.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    matches = host.lower() in names or any(
        n.startswith("*.") and host.lower().endswith(n[1:]) and host.count(".") == n.count(".") for n in names
    )
    if host and not matches:
        findings.append(
            Finding("warn", f"The certificate is not valid for {host}", "Add it to tls.extra_sans or fix server.public_url.")
        )
    return findings


def check_network_mode(config: Config) -> list[Finding]:
    import shutil

    mode = config.network.mode
    findings = []
    if mode == "tailscale":
        from .network import tailscale_info

        try:
            info = tailscale_info()
        except Exception as exc:  # noqa: BLE001 - report whatever went wrong
            return [Finding("error", f"Tailscale: {exc}", "Install Tailscale and run `tailscale up`.")]
        findings.append(Finding("ok", f"Tailscale is running as {info.dns_name} ({info.ipv4 or info.ipv6})"))
        return findings  # host, public URL and certificate are derived from Tailscale at start-up
    if is_loopback_host(urlsplit(config.base_url).hostname or "") and mode != "cloudflare":
        findings.append(
            Finding(
                "warn",
                f"Pairing links will point at {config.base_url}, which other devices can't reach",
                "Set server.public_url (and server.host), or use network.mode = 'tailscale'.",
            )
        )
    if mode == "cloudflare":
        if shutil.which("cloudflared") is None:
            findings.append(Finding("warn", "cloudflared was not found on this machine", "Install cloudflared and run your tunnel."))
        findings.append(
            Finding(
                "ok",
                f"Tunnel target should be http{'s' if config.tls.mode != 'off' else ''}://"
                f"{config.server.host}:{config.server.port}",
            )
        )
    if mode == "direct" and config.tls.mode == "self-signed":
        findings.append(
            Finding(
                "warn",
                "Direct mode with a self-signed certificate: every phone will show a browser warning",
                "Consider network.mode = 'tailscale' (easiest, most secure) or a real certificate.",
            )
        )
    return findings


def run_all(config: Config) -> list[Finding]:
    return (
        check_ollama_running(config)
        + check_ollama_binding(config)
        + check_tls(config)
        + check_network_mode(config)
        + check_files(config)
        + check_config(config)
    )
