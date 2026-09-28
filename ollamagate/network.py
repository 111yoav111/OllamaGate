"""Network modes: how devices reach OllamaGate over the internet.

``network.mode`` in config.toml picks one (in order of recommendation):

* ``tailscale``  - listen only on this machine's Tailscale address and use a
  real Tailscale HTTPS certificate. Devices must be on your tailnet *and*
  paired (defence in depth). Needs "HTTPS certificates" enabled in the
  Tailscale admin console.
* ``cloudflare`` - a local ``cloudflared`` tunnel forwards to OllamaGate on
  loopback, so no router ports are opened; the tunnel is the only trusted
  proxy (for CF-Connecting-IP).
* ``letsencrypt`` - your own domain with a certificate from certbot and a
  router port-forward.
* ``direct``     - default; self-signed certificate unless configured otherwise.

This module only reads the environment (the tailscale CLI, certificate files)
and adjusts the in-memory config at startup; it never changes config.toml.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .config import Config, ConfigError, is_loopback_host

log = logging.getLogger("ollamagate.network")

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)


@dataclass
class TailscaleInfo:
    dns_name: str  # e.g. "my-pc.tailnet-1234.ts.net"
    ipv4: str | None
    ipv6: str | None


@dataclass
class ModeResult:
    notes: list[str] = field(default_factory=list)


def tailscale_info(run: Runner = _run) -> TailscaleInfo:
    """Read this machine's tailnet name and addresses from ``tailscale status --json``."""
    if shutil.which("tailscale") is None and run is _run:
        raise ConfigError("network.mode = 'tailscale' but the tailscale CLI was not found")
    proc = run(["tailscale", "status", "--json"])
    if proc.returncode != 0:
        raise ConfigError(f"tailscale status failed: {proc.stderr.strip()[:200] or 'is tailscale up?'}")
    try:
        status = json.loads(proc.stdout)
        me = status["Self"]
        dns_name = str(me["DNSName"]).rstrip(".")
        ips = [str(ip) for ip in me.get("TailscaleIPs") or []]
    except (ValueError, KeyError, TypeError) as exc:
        raise ConfigError("could not understand `tailscale status --json` output") from exc
    if status.get("BackendState") not in (None, "Running"):
        raise ConfigError(f"tailscale is not running (state: {status.get('BackendState')})")
    if not dns_name:
        raise ConfigError("tailscale reports no DNS name; enable MagicDNS in the admin console")
    return TailscaleInfo(
        dns_name=dns_name,
        ipv4=next((ip for ip in ips if "." in ip), None),
        ipv6=next((ip for ip in ips if ":" in ip), None),
    )


def tailscale_cert(info: TailscaleInfo, tls_dir: Path, run: Runner = _run) -> tuple[Path, Path]:
    """Fetch (or refresh) the Tailscale HTTPS certificate for this machine."""
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert, key = tls_dir / "tailscale.crt", tls_dir / "tailscale.key"
    proc = run(["tailscale", "cert", "--cert-file", str(cert), "--key-file", str(key), info.dns_name])
    if proc.returncode != 0 or not cert.exists() or not key.exists():
        raise ConfigError(
            "tailscale cert failed - enable 'HTTPS certificates' in the Tailscale admin console "
            f"({proc.stderr.strip()[:200]})"
        )
    try:
        key.chmod(0o600)
    except OSError:
        pass
    return cert, key


def apply_network_mode(config: Config, run: Runner = _run) -> ModeResult:
    """Adjust ``config`` for its network mode. Raises ConfigError if the setup can't work."""
    result = ModeResult()
    mode = config.network.mode
    if mode == "tailscale":
        info = tailscale_info(run)
        if is_loopback_host(config.server.host) and info.ipv4:
            # Default host: listen on the tailnet address only, never on the LAN.
            config.server.host = info.ipv4
            result.notes.append(f"listening on the Tailscale address {info.ipv4}")
        if not config.server.public_url:
            config.server.public_url = f"https://{info.dns_name}:{config.server.port}"
        if config.tls.mode == "self-signed":
            cert, key = tailscale_cert(info, config.config_dir / "tls", run)
            config.tls.mode, config.tls.cert_file, config.tls.key_file = "files", str(cert), str(key)
            result.notes.append(f"using the Tailscale certificate for {info.dns_name}")
    elif mode == "cloudflare":
        if not is_loopback_host(config.server.host):
            raise ConfigError("network.mode = 'cloudflare' must listen on loopback (the tunnel connects locally)")
        if not config.server.public_url:
            raise ConfigError("network.mode = 'cloudflare' needs server.public_url (your tunnel's hostname)")
        result.notes.append("expecting cloudflared to forward to this address; no router ports needed")
    elif mode == "letsencrypt":
        if config.tls.mode != "files":
            raise ConfigError("network.mode = 'letsencrypt' needs tls.mode = 'files' with certbot's certificate")
        if not config.server.public_url:
            raise ConfigError("network.mode = 'letsencrypt' needs server.public_url (https://your.domain:port)")
    config.validate()
    return result
