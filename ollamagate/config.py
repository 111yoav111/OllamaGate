"""Configuration: a TOML file plus ``OLLAMAGATE_<SECTION>__<KEY>`` env overrides.

Everything has a safe default, so running without a config file works.
"""

from __future__ import annotations

import ipaddress
import math
import os
import sys
import tomllib
import typing
from dataclasses import dataclass, field, fields
from pathlib import Path
from urllib.parse import urlsplit

ENV_PREFIX = "OLLAMAGATE_"


class ConfigError(ValueError):
    """Raised when the configuration is invalid or insecure."""


def default_config_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "ollamagate"


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8443
    # Public base URL used in pairing links/QR codes, e.g. "https://my-pc.tailnet.ts.net:8443".
    # Empty = derived from host/port.
    public_url: str = ""
    max_body_bytes: int = 20 * 1024 * 1024
    # Seconds a client gets to send request headers / the whole request body.
    header_timeout: float = 15.0
    body_timeout: float = 120.0
    # Connection caps (slowloris / resource exhaustion protection).
    max_connections: int = 512
    max_connections_per_ip: int = 32


@dataclass
class NetworkConfig:
    # direct | tailscale | cloudflare | letsencrypt
    mode: str = "direct"
    # Peers allowed to set X-Forwarded-For / CF-Connecting-IP (CIDRs). Empty = trust nobody.
    trusted_proxies: list[str] = field(default_factory=list)


@dataclass
class OllamaConfig:
    url: str = "http://127.0.0.1:11434"
    connect_timeout: float = 5.0
    # Max seconds to wait for the next chunk from Ollama (model loads can be slow).
    read_timeout: float = 600.0


@dataclass
class TLSConfig:
    # self-signed | files | off   ("off" is only allowed on loopback)
    mode: str = "self-signed"
    cert_file: str = ""
    key_file: str = ""
    # Extra DNS names / IPs for the self-signed certificate.
    extra_sans: list[str] = field(default_factory=list)


@dataclass
class PairingConfig:
    ttl_seconds: int = 300
    max_attempts: int = 5
    requests_per_minute_per_ip: int = 10


@dataclass
class LimitsConfig:
    """Default per-device limits. 0 means unlimited where it makes sense."""

    tokens_per_day: int = 0
    tokens_per_month: int = 0
    requests_per_minute: int = 60
    max_concurrent: int = 2
    max_num_ctx: int = 8192
    max_num_predict: int = 4096
    allowed_models: list[str] = field(default_factory=list)  # empty = all models
    allow_model_management: bool = False
    priority: str = "normal"  # low | normal | high


@dataclass
class LoggingConfig:
    audit_size: int = 5000
    request_log_size: int = 5000
    # Prompt/response content is never logged unless this is explicitly enabled.
    log_content: bool = False


@dataclass
class Config:
    server: ServerConfig = field(default_factory=ServerConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    pairing: PairingConfig = field(default_factory=PairingConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    config_dir: Path = field(default_factory=default_config_dir)

    def validate(self) -> None:
        s = self.server
        if not (1 <= s.port <= 65535):
            raise ConfigError(f"server.port out of range: {s.port}")
        for name in ("max_body_bytes", "max_connections", "max_connections_per_ip"):
            if getattr(s, name) <= 0:
                raise ConfigError(f"server.{name} must be positive")
        for name, value in (
            ("server.header_timeout", s.header_timeout),
            ("server.body_timeout", s.body_timeout),
            ("ollama.connect_timeout", self.ollama.connect_timeout),
            ("ollama.read_timeout", self.ollama.read_timeout),
        ):
            if not math.isfinite(value) or value <= 0:
                raise ConfigError(f"{name} must be a positive number")
        lim = self.limits
        for name in ("tokens_per_day", "tokens_per_month", "requests_per_minute", "max_num_ctx", "max_num_predict"):
            if getattr(lim, name) < 0:
                raise ConfigError(f"limits.{name} must not be negative")
        if lim.max_concurrent < 1:
            raise ConfigError("limits.max_concurrent must be at least 1")
        if self.tls.mode not in ("self-signed", "files", "off"):
            raise ConfigError(f"tls.mode must be self-signed, files or off (got {self.tls.mode!r})")
        if self.tls.mode == "files" and not (self.tls.cert_file and self.tls.key_file):
            raise ConfigError("tls.mode = 'files' requires tls.cert_file and tls.key_file")
        if self.tls.mode == "off" and not is_loopback_host(s.host):
            raise ConfigError(
                "Plain HTTP is only allowed on a loopback address. "
                f"server.host = {s.host!r} requires TLS."
            )
        if self.network.mode not in ("direct", "tailscale", "cloudflare", "letsencrypt"):
            raise ConfigError(f"unknown network.mode {self.network.mode!r}")
        for cidr in self.network.trusted_proxies:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ConfigError(f"invalid network.trusted_proxies entry {cidr!r}") from exc
        up = urlsplit(self.ollama.url)
        if up.scheme not in ("http", "https") or not up.hostname:
            raise ConfigError(f"invalid ollama.url {self.ollama.url!r}")
        if not is_loopback_host(up.hostname):
            raise ConfigError("ollama.url must point at a loopback address (Ollama must stay local)")
        if s.public_url:
            validate_public_url(s.public_url)
        if self.pairing.ttl_seconds < 30 or self.pairing.ttl_seconds > 3600:
            raise ConfigError("pairing.ttl_seconds must be between 30 and 3600")
        if not (1 <= self.pairing.max_attempts <= 10):
            raise ConfigError("pairing.max_attempts must be between 1 and 10")
        if self.limits.priority not in ("low", "normal", "high"):
            raise ConfigError("limits.priority must be low, normal or high")

    @property
    def base_url(self) -> str:
        if self.server.public_url:
            return self.server.public_url.rstrip("/")
        scheme = "http" if self.tls.mode == "off" else "https"
        host = self.server.host
        if host in ("0.0.0.0", "::"):
            host = "localhost"
        if ":" in host:
            host = f"[{host}]"
        return f"{scheme}://{host}:{self.server.port}"


def validate_public_url(url: str) -> None:
    """The URL devices use to reach us; it ends up in pairing links and QR codes."""
    if any(ch.isspace() or ord(ch) < 0x20 for ch in url) or len(url) > 200:
        raise ConfigError("server.public_url must not contain whitespace or control characters")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError for a bad port
    except ValueError as exc:
        raise ConfigError(f"server.public_url is not a valid URL: {exc}") from None
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ConfigError("server.public_url must look like https://host[:port]")
    if parts.scheme == "http" and not is_loopback_host(parts.hostname):
        raise ConfigError("server.public_url must use https (pairing secrets travel in it)")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ConfigError("server.public_url must be just scheme://host[:port] (no path, query, fragment or user)")


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _coerce(value: typing.Any, hint: typing.Any, where: str) -> typing.Any:
    """Coerce a TOML or env-string value to the dataclass field type."""
    origin = typing.get_origin(hint)
    if origin is list:
        if isinstance(value, str):
            value = [v.strip() for v in value.split(",") if v.strip()]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{where} must be a list of strings")
        return list(value)
    if hint is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.lower() in ("1", "true", "yes", "on"):
            return True
        if isinstance(value, str) and value.lower() in ("0", "false", "no", "off"):
            return False
        raise ConfigError(f"{where} must be a boolean")
    if hint is int:
        if isinstance(value, bool):
            raise ConfigError(f"{where} must be an integer")
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{where} must be an integer") from exc
    if hint is float:
        if isinstance(value, bool):
            raise ConfigError(f"{where} must be a number")
        try:
            return float(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{where} must be a number") from exc
    if hint is str:
        if not isinstance(value, str):
            raise ConfigError(f"{where} must be a string")
        return value
    raise ConfigError(f"unsupported config type for {where}")


def _apply(section_obj: typing.Any, data: dict, section: str) -> None:
    hints = typing.get_type_hints(type(section_obj))
    known = {f.name for f in fields(section_obj)}
    for key, value in data.items():
        if key not in known:
            raise ConfigError(f"unknown config key {section}.{key}")
        setattr(section_obj, key, _coerce(value, hints[key], f"{section}.{key}"))


SECTIONS = ("server", "network", "ollama", "tls", "pairing", "limits", "logging")


def load_config(path: Path | None = None, env: typing.Mapping[str, str] | None = None) -> Config:
    """Load config from ``path`` (optional) and apply env overrides, then validate."""
    env = os.environ if env is None else env
    cfg = Config()
    if env.get(ENV_PREFIX + "CONFIG_DIR"):
        cfg.config_dir = Path(env[ENV_PREFIX + "CONFIG_DIR"])
    if path is None:
        candidate = cfg.config_dir / "config.toml"
        path = candidate if candidate.exists() else None
    if path is not None:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        for section, values in data.items():
            if section not in SECTIONS or not isinstance(values, dict):
                raise ConfigError(f"unknown config section [{section}]")
            _apply(getattr(cfg, section), values, section)
    for name, value in env.items():
        if not name.startswith(ENV_PREFIX) or "__" not in name:
            continue
        section, _, key = name[len(ENV_PREFIX):].lower().partition("__")
        if section not in SECTIONS:
            raise ConfigError(f"unknown config section in env var {name}")
        _apply(getattr(cfg, section), {key: value}, section)
    cfg.validate()
    return cfg
