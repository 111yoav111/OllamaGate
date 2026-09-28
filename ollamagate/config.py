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
    # Requests forwarded to Ollama at once (all devices); the rest queue by priority.
    max_upstream_concurrency: int = 4
    # Seconds a request may wait in that queue before getting 503 "server busy".
    queue_timeout: float = 120.0


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
    # mTLS: issue each device a client certificate at pairing and require it
    # (together with the token) on every request.
    client_certs: bool = False


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
class BansConfig:
    # N failed logins/pairing attempts within window_seconds -> ban, doubling per repeat.
    failures: int = 10
    window_seconds: int = 600
    ban_seconds: int = 3600
    max_ban_seconds: int = 7 * 86400


@dataclass
class NotifyConfig:
    """Owner notifications (all off by default). See ollamagate/notify.py."""

    ntfy_url: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    desktop: bool = False
    events: list[str] = field(default_factory=lambda: ["pairing", "new_ip", "ban", "lockdown"])


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
    bans: BansConfig = field(default_factory=BansConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    config_dir: Path = field(default_factory=default_config_dir)

    def validate(self) -> None:
        s = self.server
        if not (1 <= s.port <= 65535):
            raise ConfigError(f"server.port out of range: {s.port}")
        for name in ("max_body_bytes", "max_connections", "max_connections_per_ip", "max_upstream_concurrency"):
            if getattr(s, name) <= 0:
                raise ConfigError(f"server.{name} must be positive")
        for name, value in (
            ("server.header_timeout", s.header_timeout),
            ("server.body_timeout", s.body_timeout),
            ("server.queue_timeout", s.queue_timeout),
            ("ollama.connect_timeout", self.ollama.connect_timeout),
            ("ollama.read_timeout", self.ollama.read_timeout),
        ):
            if not math.isfinite(value) or value <= 0:
                raise ConfigError(f"{name} must be a positive number")
        lim = self.limits
        for name in ("tokens_per_day", "tokens_per_month", "requests_per_minute", "max_num_ctx", "max_num_predict"):
            if getattr(lim, name) < 0:
                raise ConfigError(f"limits.{name} must not be negative")
        b = self.bans
        if b.failures < 1 or b.window_seconds < 1 or b.ban_seconds < 1 or b.max_ban_seconds < b.ban_seconds:
            raise ConfigError("bans: failures, window_seconds and ban_seconds must be positive; max >= ban_seconds")
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
        if self.tls.client_certs and (self.tls.mode == "off" or self.network.mode == "cloudflare"):
            raise ConfigError(
                "tls.client_certs needs OllamaGate to terminate TLS itself "
                "(not tls.mode = 'off', not network.mode = 'cloudflare')"
            )
        if self.network.mode not in ("direct", "tailscale", "cloudflare", "letsencrypt"):
            raise ConfigError(f"unknown network.mode {self.network.mode!r}")
        if self.network.mode == "cloudflare" and not self.network.trusted_proxies:
            raise ConfigError(
                "network.mode = 'cloudflare' needs network.trusted_proxies (usually [\"127.0.0.1/32\", \"::1/128\"] "
                "for a local cloudflared); otherwise every client looks like the tunnel and bans can't work"
            )
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
        n = self.notify
        if n.ntfy_url and not n.ntfy_url.startswith("https://"):
            raise ConfigError("notify.ntfy_url must be an https:// URL")
        if bool(n.telegram_bot_token) != bool(n.telegram_chat_id):
            raise ConfigError("notify.telegram_bot_token and notify.telegram_chat_id go together")
        unknown_events = set(n.events) - {"pairing", "new_ip", "ban", "lockdown"}
        if unknown_events:
            raise ConfigError(f"unknown notify.events {sorted(unknown_events)}")
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


SECTIONS = ("server", "network", "ollama", "tls", "pairing", "limits", "bans", "notify", "logging")


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
    if cfg.network.mode == "cloudflare" and not cfg.network.trusted_proxies:
        # A local cloudflared connects over loopback; trust it (and only it).
        cfg.network.trusted_proxies = ["127.0.0.1/32", "::1/128"]
    cfg.validate()
    return cfg
