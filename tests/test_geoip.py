"""Offline GeoIP: country lookups, allow/deny lists and the pre-routing block."""

from __future__ import annotations

import pytest

from ollamagate.config import ConfigError, load_config
from ollamagate.geoip import GeoIP

from .test_proxy_stream import bearer

DB = {"8.8.8.8": {"country": {"iso_code": "US"}}, "85.214.1.1": {"country": {"iso_code": "DE"}}, "9.9.9.9": {}}


class FakeReader(dict):
    pass


def geo(allow=(), deny=()) -> GeoIP:
    return GeoIP(FakeReader(DB), list(allow), list(deny))


def test_lookup_and_rules():
    g = geo(allow=["DE"])
    assert g.country("8.8.8.8") == "US" and g.country("85.214.1.1") == "DE"
    assert g.country("9.9.9.9") is None and g.country("192.168.1.2") is None
    assert g.permits("85.214.1.1") and not g.permits("8.8.8.8")
    assert not g.permits("9.9.9.9")  # unknown country fails an allowlist
    for local in ("127.0.0.1", "10.0.0.1", "100.64.1.1", "::1", "fd00::1"):
        assert g.permits(local)  # LAN, loopback, Tailscale are never filtered
    assert g.country("::ffff:8.8.8.8") == "US" and not g.permits("::ffff:8.8.8.8")  # dual-stack socket
    assert g.permits("::ffff:127.0.0.1")
    g = geo(deny=["US"])
    assert not g.permits("8.8.8.8") and g.permits("85.214.1.1") and g.permits("9.9.9.9")
    assert geo().permits("8.8.8.8")


def test_config_validation(tmp_path):
    cfg = load_config(env={"OLLAMAGATE_CONFIG_DIR": str(tmp_path), "OLLAMAGATE_GEOIP__DATABASE": "x.mmdb",
                           "OLLAMAGATE_GEOIP__ALLOW_COUNTRIES": "de, at"})
    assert cfg.geoip.allow_countries == ["DE", "AT"]
    with pytest.raises(ConfigError):
        load_config(env={"OLLAMAGATE_CONFIG_DIR": str(tmp_path), "OLLAMAGATE_GEOIP__DENY_COUNTRIES": "US"})
    with pytest.raises(ConfigError):
        load_config(env={"OLLAMAGATE_CONFIG_DIR": str(tmp_path), "OLLAMAGATE_GEOIP__DATABASE": "x",
                         "OLLAMAGATE_GEOIP__DENY_COUNTRIES": "USA"})


def test_blocked_country_is_refused_even_with_a_token(gate_factory, client):
    gate = gate_factory(**{"network__trusted_proxies": ["127.0.0.1/32"]})
    gate.state.geo = geo(allow=["DE"])
    headers = bearer(gate.token)
    assert client.get(gate.url + "/api/tags", headers={**headers, "X-Forwarded-For": "85.214.1.1"}).status_code == 200
    r = client.get(gate.url + "/api/tags", headers={**headers, "X-Forwarded-For": "8.8.8.8"})
    assert r.status_code == 403 and gate.recorder.requests[-1]["headers"].get("x-forwarded-for") is None
    assert len(gate.recorder.requests) == 1
    blocked = [e for e in gate.state.audit_log if e.event == "geo_blocked"]
    assert blocked and blocked[-1].detail["country"] == "US" and blocked[-1].ip == "8.8.8.8"
    assert client.get(gate.url + "/api/tags", headers=headers).status_code == 200  # loopback


def test_dashboard_says_whether_geoip_is_on():
    from ollamagate.admin.service import Admin
    from ollamagate.config import Config
    from ollamagate.state import State

    admin = Admin(State(), Config(), None)
    assert admin.dashboard()["geoip"].startswith("off")
    admin.state.geo = geo(allow=["DE"], deny=["US"])
    assert admin.dashboard()["geoip"] == "on · only DE; blocking US"
