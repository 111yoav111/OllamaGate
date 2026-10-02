"""End to end: limits, accounting and bans through the real server."""

from __future__ import annotations

import json
import time

from typer.testing import CliRunner

from ollamagate.__main__ import cli
from ollamagate.admin.service import Admin
from ollamagate.state import DeviceLimits

from .test_admin import admin_gate  # noqa: F401 - fixture
from .test_proxy_stream import bearer, wait_for

XFF = "X-Forwarded-For"


def set_limits(gate, **kw):
    admin = Admin(gate.state, gate.app.state.config, None)
    gate.call(lambda: admin.set_limits(gate.device.id, **kw))


def test_clamps_reach_ollama(gate, client):
    set_limits(gate, max_num_ctx=2048, max_num_predict=64)
    client.post(gate.url + "/api/chat", headers=bearer(gate.token),
                json={"model": "m", "stream": False, "options": {"num_ctx": 32768}, "keep_alive": -1})
    sent = gate.recorder.last["body"]
    assert sent["options"] == {"num_ctx": 2048, "num_predict": 64}
    assert sent["keep_alive"] == "30m"


def test_v1_stream_gets_usage_and_is_accounted(gate, client):
    with client.stream("POST", gate.url + "/v1/chat/completions", headers=bearer(gate.token),
                       json={"model": "m", "stream": True, "fake_chunks": 4}) as r:
        r.read()
    assert gate.recorder.last["body"]["stream_options"] == {"include_usage": True}
    assert wait_for(lambda: gate.state.usage_today(gate.device.id).completion_tokens == 4)
    assert gate.state.usage_today(gate.device.id).prompt_tokens == 7


def test_native_stream_and_json_are_accounted(gate, client):
    with client.stream("POST", gate.url + "/api/chat", headers=bearer(gate.token),
                       json={"model": "m", "fake_chunks": 5}) as r:
        r.read()
    client.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "m", "stream": False, "fake_chunks": 3})
    u = lambda: gate.state.usage_today(gate.device.id)  # noqa: E731
    assert wait_for(lambda: u().completion_tokens == 8)
    assert u().prompt_tokens == 14
    assert gate.state.usage_lifetime(gate.device.id).requests == 2


def test_interrupted_stream_is_charged_an_estimate(gate, client):
    with client.stream("POST", gate.url + "/api/chat", headers=bearer(gate.token),
                       json={"model": "m", "fake_chunks": 500, "fake_delay": 0.01}) as r:
        lines = r.iter_lines()
        for _ in range(10):
            next(lines)
    assert wait_for(lambda: gate.state.usage_today(gate.device.id).completion_tokens >= 10)
    assert any(e.event == "usage_estimated" for e in gate.state.audit_log)


def test_daily_token_quota(gate, client):
    set_limits(gate, tokens_per_day=10)
    r = client.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "m", "stream": False, "fake_chunks": 5})
    assert r.status_code == 200  # 7 prompt + 5 = 12 tokens: now over
    assert wait_for(lambda: gate.state.usage_today(gate.device.id).completion_tokens == 5)
    r = client.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "m", "stream": False})
    assert r.status_code == 429 and r.json() == {"error": "daily token quota used up"}
    assert 0 < int(r.headers["retry-after"]) <= 86400
    requests_before = len(gate.recorder.requests)
    assert client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 429
    assert len(gate.recorder.requests) == requests_before


def test_requests_per_minute(gate, client):
    set_limits(gate, requests_per_minute=3)
    codes = [client.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_per_device_concurrency_limit(gate, client):
    import httpx

    set_limits(gate, max_concurrent=1)
    with client.stream("POST", gate.url + "/api/chat", headers=bearer(gate.token),
                       json={"model": "m", "fake_chunks": 100, "fake_delay": 0.05}) as r:
        lines = r.iter_lines()
        next(lines)
        assert httpx.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "m"}).status_code == 429
        # Model lists have their own pool and skip the queue: pickers keep working mid-chat.
        assert httpx.get(gate.url + "/api/tags", headers=bearer(gate.token)).status_code == 200


def test_abandoned_request_is_charged_for_its_prompt(gate, client):
    """stream:false sends nothing until the end; leaving before then must still cost tokens."""
    import threading

    set_limits(gate, max_num_ctx=100)
    body = {"model": "m", "stream": False, "fake_first_delay": 5, "messages": [{"content": "x" * 2000}]}
    t = threading.Thread(target=lambda: client.post(gate.url + "/api/chat", headers=bearer(gate.token), json=body))
    t.start()
    assert wait_for(lambda: len(gate.recorder.requests) == 1)  # Ollama is working on it
    gate.call(lambda: gate.state.kill_device_streams(gate.device.id, "kicked"))
    t.join(5)
    assert wait_for(lambda: gate.state.usage_today(gate.device.id).prompt_tokens == 100)  # capped at a context
    bad = client.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "m", "options": "x"})
    assert bad.status_code == 400 and gate.state.usage_today(gate.device.id).prompt_tokens == 100  # never sent


def test_model_allowlist_end_to_end(gate, client):
    set_limits(gate, allowed_models=["llama3:8b"])
    r = client.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "qwen2:7b"})
    assert r.status_code == 403 and r.json() == {"error": "model not allowed for this device"}
    tags = client.get(gate.url + "/api/tags", headers=bearer(gate.token)).json()
    assert [m["name"] for m in tags["models"]] == ["llama3:8b"]
    models = client.get(gate.url + "/v1/models", headers=bearer(gate.token)).json()
    assert [m["id"] for m in models["data"]] == ["llama3:8b"]
    assert client.get(gate.url + "/v1/models/qwen2:7b", headers=bearer(gate.token)).status_code == 404
    assert client.post(gate.url + "/api/chat", headers=bearer(gate.token),
                       json={"model": "llama3:8b", "stream": False}).status_code == 200


def test_policy_rejects_bad_json(gate, client):
    r = client.post(gate.url + "/api/chat", headers=bearer(gate.token), content=b"nope")
    assert r.status_code == 400
    assert gate.recorder.requests == []


def test_auto_ban_through_trusted_proxy(gate_factory, client):
    gate = gate_factory(**{"network__trusted_proxies": ["127.0.0.1/32"], "bans__failures": 5})
    attacker = {XFF: "198.51.100.66"}
    for i in range(5):  # five *different* wrong tokens: guessing
        r = client.get(gate.url + "/api/tags", headers={**attacker, "Authorization": f"Bearer og_dev_guess{i}"})
        assert r.status_code == 401
    # Now that client is refused everywhere (even /healthz) unless it has a valid token:
    # a paired device sharing the attacker's IP (NAT) keeps working.
    assert client.get(gate.url + "/api/tags", headers={**attacker, "Authorization": "Bearer og_dev_x"}).status_code == 403
    assert client.get(gate.url + "/healthz", headers=attacker).status_code == 403
    assert client.get(gate.url + "/pair", headers=attacker).status_code == 403
    assert client.get(gate.url + "/api/tags", headers={**attacker, **bearer(gate.token)}).status_code == 200
    # Nobody else is affected.
    assert client.get(gate.url + "/api/tags", headers={XFF: "198.51.100.67", **bearer(gate.token)}).status_code == 200
    assert any(e.event == "ban_auto" for e in gate.state.audit_log)


def test_failed_pairing_attempts_count_towards_bans(gate_factory, client):
    from ollamagate.server import pairing

    gate = gate_factory(**{"network__trusted_proxies": ["127.0.0.1/32"], "bans__failures": 3})
    gate.call(lambda: pairing.open_window(gate.state, base_url=gate.url, fingerprint=None, ttl_seconds=60, max_attempts=10))
    for code in ("ZZZZ-ZZZ1", "ZZZZ-ZZZ2", "ZZZZ-ZZZ3"):
        client.post(gate.url + "/pair/claim", headers={XFF: "198.51.100.70"}, json={"code": code, "device_name": "x"})
    assert client.get(gate.url + "/pair", headers={XFF: "198.51.100.70"}).status_code == 403


def test_bans_cli_and_ban_cuts_streams(admin_gate, client):  # noqa: F811
    gate, _ = admin_gate
    gate.call(lambda: setattr(gate.device, "last_ip", "198.51.100.80"))
    r = CliRunner().invoke(cli, ["bans", "add", "198.51.100.80", "--reason", "abuse"])
    assert r.exit_code == 0 and "Banned 198.51.100.80" in r.output
    assert "198.51.100.80" in CliRunner().invoke(cli, ["bans", "list"]).output
    assert CliRunner().invoke(cli, ["bans", "add", "127.0.0.1"]).exit_code == 1  # never yourself
    assert CliRunner().invoke(cli, ["bans", "remove", "198.51.100.80"]).output.startswith("Ban lifted")
    assert CliRunner().invoke(cli, ["bans", "list"]).output.startswith("No active bans")


def test_devices_limits_cli(admin_gate, client):  # noqa: F811
    gate, _ = admin_gate
    r = CliRunner().invoke(cli, ["devices", "limits", gate.device.id, "--tokens-per-day", "5000",
                                 "--allowed-models", "llama3, qwen2:7b", "--priority", "high"])
    assert r.exit_code == 0, r.output
    lim = gate.device.limits
    assert lim.tokens_per_day == 5000 and lim.allowed_models == ["llama3", "qwen2:7b"] and lim.priority == "high"
    assert CliRunner().invoke(cli, ["devices", "limits", gate.device.id, "--priority", "urgent"]).exit_code == 1
    assert CliRunner().invoke(cli, ["devices", "limits", gate.device.id, "--max-concurrent", "0"]).exit_code == 1
    r = CliRunner().invoke(cli, ["devices", "limits", gate.device.id])
    assert "tokens_per_day" in r.output and "5000" in r.output
    assert any(e.event == "admin_limits" for e in gate.state.audit_log)


def test_new_devices_get_config_default_limits(gate_factory, client):
    from ollamagate.server import pairing

    gate = gate_factory(**{"limits__tokens_per_day": 1234, "limits__priority": "low"})
    s = gate.call(lambda: pairing.open_window(gate.state, base_url=gate.url, fingerprint=None, ttl_seconds=60, max_attempts=5))
    r = client.post(gate.url + "/pair/claim", json={"code": s.code, "device_name": "new"})
    d = gate.state.get_device(r.json()["device_id"])
    assert d.limits == DeviceLimits(tokens_per_day=1234, priority="low")


def test_priority_queue_end_to_end(gate_factory, client):
    """With one upstream slot, a queued high-priority request beats an earlier low one."""
    import threading

    gate = gate_factory(**{"server__max_upstream_concurrency": 1})
    low_token, low_dev = gate.new_device("low", limits=DeviceLimits(priority="low"))
    high_token, high_dev = gate.new_device("high", limits=DeviceLimits(priority="high"))
    done = []

    def req(token, name):
        client.post(gate.url + "/api/chat", headers=bearer(token), json={"model": name, "stream": False})
        done.append(name)

    with client.stream("POST", gate.url + "/api/chat", headers=bearer(gate.token),
                       json={"model": "hold", "fake_chunks": 20, "fake_delay": 0.05}) as r:
        lines = r.iter_lines()
        next(lines)
        t_low = threading.Thread(target=req, args=(low_token, "low"))
        t_low.start()
        time.sleep(0.2)
        t_high = threading.Thread(target=req, args=(high_token, "high"))
        t_high.start()
        time.sleep(0.2)
        assert gate.app.state.priority_gate.queued == 2
    t_low.join(10)
    t_high.join(10)
    served = [req["body"]["model"] for req in gate.recorder.requests if req["body"]["model"] in ("low", "high")]
    assert served == ["high", "low"]


# ----- regressions -------------------------------------------------------------------


def test_anonymous_requests_cannot_get_a_client_banned(gate_factory, client):
    """A web page can make visitors' browsers send anonymous requests; those must not ban."""
    gate = gate_factory(**{"network__trusted_proxies": ["127.0.0.1/32"], "bans__failures": 3})
    victim = {XFF: "198.51.100.77"}
    for _ in range(20):
        assert client.get(gate.url + "/api/tags", headers=victim).status_code == 401
    assert gate.state.bans.banned("198.51.100.77") is None


def test_stale_token_after_restart_does_not_ban(gate_factory, client):
    """A device polling with its pre-restart token repeats one credential: not guessing."""
    gate = gate_factory(**{"network__trusted_proxies": ["127.0.0.1/32"], "bans__failures": 3})
    stale = {XFF: "198.51.100.78", "Authorization": "Bearer og_dev_" + "s" * 43}
    for _ in range(20):
        assert client.get(gate.url + "/api/tags", headers=stale).status_code == 401
    assert gate.state.bans.banned("198.51.100.78") is None
    assert client.get(gate.url + "/pair", headers={XFF: "198.51.100.78"}).status_code == 404  # can pair again


def test_case_variant_keys_are_rejected(gate, client):
    """Ollama's Go decoder folds key case; "MODEL" must not sneak past the allowlist."""
    set_limits(gate, allowed_models=["llama3:8b"], max_num_predict=64)
    for body in (
        {"model": "llama3:8b", "MODEL": "qwen2:7b", "stream": False},
        {"model": "llama3:8b", "options": {"num_predict": 10, "Num_Predict": -1}},
        {"model": "llama3:8b", "Keep_Alive": -1},
        {"model": "llama3:8b", "ſtream": True},  # Unicode folding: long s == s
    ):
        r = client.post(gate.url + "/api/chat", headers=bearer(gate.token), json=body)
        assert r.status_code == 400, body
    r = client.post(gate.url + "/v1/chat/completions", headers=bearer(gate.token),
                    json={"model": "llama3:8b", "stream": True, "stream_options": {"Include_Usage": False}})
    assert r.status_code == 400
    assert gate.recorder.requests == []


def test_num_ctx_only_clamped_when_requested(gate, client):
    set_limits(gate, max_num_ctx=1024)
    client.post(gate.url + "/api/chat", headers=bearer(gate.token),
                json={"model": "m", "stream": False, "options": {"num_ctx": 131072}})
    assert gate.recorder.last["body"]["options"] == {"num_ctx": 1024, "num_predict": 4096}
    client.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "m", "stream": False})
    assert gate.recorder.last["body"]["options"] == {"num_predict": 4096}  # Ollama's own num_ctx applies


def test_output_capped_to_remaining_quota(gate, client):
    set_limits(gate, tokens_per_day=100, max_num_predict=4096)
    client.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "m", "stream": False, "fake_chunks": 3})
    assert wait_for(lambda: gate.state.usage_today(gate.device.id).completion_tokens == 3)
    client.post(gate.url + "/api/chat", headers=bearer(gate.token), json={"model": "m", "stream": False})
    assert gate.recorder.last["body"]["options"]["num_predict"] == 100 - 10  # 7 prompt + 3 output used


def test_me_reports_device_limits(gate, client):
    set_limits(gate, tokens_per_day=4242, priority="high")
    lim = client.get(gate.url + "/me", headers=bearer(gate.token)).json()["limits"]
    assert lim["tokens_per_day"] == 4242 and lim["priority"] == "high"


def test_queue_timeout_returns_503(gate_factory, client):
    import httpx

    gate = gate_factory(**{"server__max_upstream_concurrency": 1, "server__queue_timeout": 0.5})
    with client.stream("POST", gate.url + "/api/chat", headers=bearer(gate.token),
                       json={"model": "hold", "fake_chunks": 40, "fake_delay": 0.05}) as r:
        lines = r.iter_lines()
        next(lines)
        other, _ = gate.new_device("other")
        started = time.monotonic()
        busy = httpx.post(gate.url + "/api/chat", headers=bearer(other), json={"model": "m", "stream": False})
        assert busy.status_code == 503 and busy.headers["retry-after"] == "10"
        assert time.monotonic() - started < 3
        assert gate.app.state.priority_gate.queued == 0


def test_cloudflare_mode_requires_trusted_proxies():
    import pytest

    from ollamagate.config import Config, ConfigError

    cfg = Config()
    cfg.network.mode = "cloudflare"
    with pytest.raises(ConfigError, match="trusted_proxies"):
        cfg.validate()
    cfg.network.trusted_proxies = ["127.0.0.1/32"]
    cfg.validate()
