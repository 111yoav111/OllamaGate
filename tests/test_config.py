from __future__ import annotations

import pytest

from ollamagate.config import ConfigError, load_config


def write(tmp_path, text: str):
    p = tmp_path / "config.toml"
    p.write_text(text)
    return p


def test_defaults_are_secure(tmp_path):
    cfg = load_config(env={"OLLAMAGATE_CONFIG_DIR": str(tmp_path)})
    assert cfg.server.host == "127.0.0.1"
    assert cfg.tls.mode == "self-signed"
    assert cfg.limits.allow_model_management is False
    assert cfg.logging.log_content is False
    assert cfg.network.trusted_proxies == []


def test_toml_and_env_override(tmp_path):
    p = write(tmp_path, '[server]\nport = 9000\n[network]\ntrusted_proxies = ["10.0.0.0/8"]\n')
    cfg = load_config(p, env={"OLLAMAGATE_SERVER__PORT": "9100", "OLLAMAGATE_LIMITS__ALLOWED_MODELS": "a, b"})
    assert cfg.server.port == 9100
    assert cfg.network.trusted_proxies == ["10.0.0.0/8"]
    assert cfg.limits.allowed_models == ["a", "b"]


@pytest.mark.parametrize(
    "text",
    [
        '[server]\nhost = "0.0.0.0"\n[tls]\nmode = "off"\n',  # plain HTTP off loopback
        '[ollama]\nurl = "http://192.168.1.5:11434"\n',  # Ollama must be local
        '[server]\nbogus = 1\n',  # unknown key
        '[bogus]\nx = 1\n',  # unknown section
        '[server]\nport = "abc"\n',
        '[server]\nport = 70000\n',
        '[network]\ntrusted_proxies = ["not-a-cidr"]\n',
        '[tls]\nmode = "files"\n',
        '[pairing]\nmax_attempts = 50\n',
    ],
)
def test_invalid_configs_rejected(tmp_path, text):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, text), env={})


def test_plain_http_allowed_on_loopback(tmp_path):
    cfg = load_config(write(tmp_path, '[tls]\nmode = "off"\n'), env={})
    assert cfg.base_url == "http://127.0.0.1:8443"
