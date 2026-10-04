"""Body policy, token accounting, the priority gate and bans (unit tests)."""

from __future__ import annotations

import asyncio
import json

import pytest

from ollamagate.bans import BanList
from ollamagate.server.policy import apply_body_policy, filter_model_list, model_allowed, normalize_model, scrub_response
from ollamagate.server.queue import PriorityGate
from ollamagate.server.usage import UsageCounter
from ollamagate.state import DeviceLimits


def body(**kw) -> bytes:
    return json.dumps(kw).encode()


LIM = DeviceLimits(max_num_ctx=4096, max_num_predict=512, allowed_models=[])


# ----- body policy -----------------------------------------------------------------------


def test_clamps_native_options():
    r = apply_body_policy(LIM, "/api/chat", body(model="m", options={"num_ctx": 100000, "num_predict": -1}))
    data = json.loads(r.body)
    assert data["options"] == {"num_ctx": 4096, "num_predict": 512}
    assert r.error is None


def test_sets_missing_limits_and_keeps_lower_values():
    data = json.loads(apply_body_policy(LIM, "/api/generate", body(model="m", stream=False)).body)
    assert data["options"] == {"num_predict": 512}  # num_ctx is left to Ollama unless asked for
    data = json.loads(apply_body_policy(LIM, "/api/chat", body(model="m", options={"num_ctx": 2048, "num_predict": 10})).body)
    assert data["options"] == {"num_ctx": 2048, "num_predict": 10}


@pytest.mark.parametrize("bad", [True, "lots", 1e30, -2, None])
def test_bogus_limits_become_the_maximum(bad):
    data = json.loads(apply_body_policy(LIM, "/api/chat", body(model="m", options={"num_predict": bad})).body)
    assert data["options"]["num_predict"] == 512


def test_openai_max_tokens_and_usage_injection():
    r = apply_body_policy(LIM, "/v1/chat/completions", body(model="m", stream=True, max_tokens=9999))
    data = json.loads(r.body)
    assert data["max_tokens"] == 512
    assert data["stream_options"] == {"include_usage": True}
    r = apply_body_policy(LIM, "/v1/chat/completions", body(model="m", max_completion_tokens=100))
    data = json.loads(r.body)
    assert data["max_completion_tokens"] == 100 and data["max_tokens"] == 512
    assert "stream_options" not in data


def test_keep_alive_capped():
    for bad in (-1, "-1m", "24h", 999999, "forever", True):
        data = json.loads(apply_body_policy(LIM, "/api/chat", body(model="m", keep_alive=bad)).body)
        assert data["keep_alive"] == "30m", bad
    data = json.loads(apply_body_policy(LIM, "/api/chat", body(model="m", keep_alive="5m")).body)
    assert data["keep_alive"] == "5m"


def test_model_allowlist():
    lim = DeviceLimits(allowed_models=["llama3", "qwen2:7b"])
    assert model_allowed(lim, "llama3:latest") and model_allowed(lim, "LLAMA3")
    assert model_allowed(lim, "qwen2:7b") and not model_allowed(lim, "qwen2:72b")
    r = apply_body_policy(lim, "/api/chat", body(model="mistral"))
    assert r.error and r.status == 403
    assert normalize_model("library/llama3") == "library/llama3:latest"


@pytest.mark.parametrize("raw", [b"", b"[]", b"not json", b"[" * 5000, body(prompt="x"), body(model=""), body(model=5)])
def test_malformed_bodies_rejected(raw):
    r = apply_body_policy(LIM, "/api/chat", raw)
    assert r.error is not None and r.status == 400


def test_non_model_endpoints_untouched():
    raw = b'{"anything": 1}'
    assert apply_body_policy(LIM, "/api/delete", raw).body is raw


@pytest.mark.parametrize("path, raw", [
    # Go merges a repeated object into the first; Python keeps only the last.
    ("/api/embed", b'{"model":"m","options":{"num_ctx":262144},"options":{}}'),
    ("/api/chat", b'{"model":"m","options":{"num_ctx":262144},"options":{"num_predict":100}}'),
])
def test_duplicate_keys_cannot_hide_values(path, raw):
    forwarded = apply_body_policy(LIM, path, raw).body
    assert b"262144" not in forwarded and forwarded.count(b'"options"') == 1


@pytest.mark.parametrize("raw", [b'{"model":"m","options":{"num_predict":NaN}}', b'{"model":"m","max_tokens":Infinity}'])
def test_nan_and_infinity_are_rejected(raw):
    assert apply_body_policy(LIM, "/api/chat", raw).error == "request body must be JSON"
    assert json.loads(apply_body_policy(LIM, "/api/chat", body(model="m", keep_alive="nan")).body)["keep_alive"] == "30m"


def test_registry_endpoints_refuse_insecure():
    assert apply_body_policy(LIM, "/api/pull", body(model="10.0.0.1:80/a/b", insecure=True)).status == 403
    assert apply_body_policy(LIM, "/api/pull", body(model="m", INSECURE=True)).error  # case-folded smuggling
    assert apply_body_policy(LIM, "/api/push", body(model="m")).error is None


def test_show_accepts_name_like_ollama():
    lim = DeviceLimits(allowed_models=["ok"])
    assert apply_body_policy(lim, "/api/show", body(name="ok")).error is None
    assert apply_body_policy(lim, "/api/show", body(name="secret")).status == 403
    assert apply_body_policy(lim, "/api/show", body(model="secret", name="ok")).status == 403  # model wins in Ollama


def test_filter_model_list():
    lim = DeviceLimits(allowed_models=["llama3:8b"])
    tags = body(models=[{"name": "llama3:8b"}, {"name": "qwen2:7b"}, "junk"])
    assert json.loads(filter_model_list(lim, "/api/tags", tags)) == {"models": [{"name": "llama3:8b"}]}
    v1 = body(data=[{"id": "llama3:8b"}, {"id": "qwen2:7b"}])
    assert json.loads(filter_model_list(lim, "/v1/models", v1))["data"] == [{"id": "llama3:8b"}]


# ----- usage counting ----------------------------------------------------------------------


def test_ndjson_usage_from_final_line_even_split_across_chunks():
    c = UsageCounter("application/x-ndjson", 40)
    stream = b'{"done":false}\n{"done":false}\n{"done":true,"prompt_eval_count":12,"eval_count":34}\n'
    for i in range(0, len(stream), 7):
        c.feed(stream[i : i + 7])
    u = c.result()
    assert (u.prompt_tokens, u.completion_tokens, u.exact) == (12, 34, True)


def test_sse_usage_chunk():
    c = UsageCounter("text/event-stream", 0)
    c.feed(b'data: {"choices":[{}]}\n\ndata: {"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":6}}\n\ndata: [DONE]\n\n')
    u = c.result()
    assert (u.prompt_tokens, u.completion_tokens, u.exact) == (5, 6, True)


def test_plain_json_usage():
    c = UsageCounter("application/json", 0)
    c.feed(b'{"done":true,"prompt_eval_count":3,')
    c.feed(b'"eval_count":4}')
    assert c.result().total == 7


def test_interrupted_stream_is_estimated():
    c = UsageCounter("application/x-ndjson", 400)
    for _ in range(25):
        c.feed(b'{"message":{"content":"x"},"done":false}\n')
    u = c.result()
    assert not u.exact and u.completion_tokens == 25 and u.prompt_tokens == 100


def test_garbage_counts_are_ignored():
    c = UsageCounter("application/json", 0)
    c.feed(b'{"prompt_eval_count": -5, "eval_count": true}')
    u = c.result()
    assert u.exact and u.total == 0


# ----- priority gate ---------------------------------------------------------------------------


def test_priority_gate_orders_waiters():
    async def run():
        gate = PriorityGate(1)
        order = []
        await gate.acquire("normal")  # hold the only slot

        async def worker(name, prio):
            async with gate.slot(prio):
                order.append(name)

        tasks = [asyncio.create_task(worker(n, p)) for n, p in [("low", "low"), ("n1", "normal"), ("high", "high"), ("n2", "normal")]]
        await asyncio.sleep(0.01)
        assert gate.queued == 4
        gate.release()
        await asyncio.gather(*tasks)
        return order, gate.active

    order, active = asyncio.run(run())
    assert order == ["high", "n1", "n2", "low"] and active == 0


def test_cancelled_waiter_never_takes_a_slot():
    async def run():
        gate = PriorityGate(1)
        await gate.acquire("normal")
        waiter = asyncio.create_task(gate.acquire("high"))
        await asyncio.sleep(0.01)
        waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)
        gate.release()
        await gate.acquire("low")  # must not deadlock
        return gate.active

    assert asyncio.run(run()) == 1


# ----- bans -----------------------------------------------------------------------------------


def test_ban_after_threshold_and_escalation():
    bans = BanList(threshold=3, window_seconds=60, ban_seconds=100, max_ban_seconds=300)
    t = 1000.0
    assert bans.record_failure("198.51.100.1", "x", now=t) is None
    assert bans.record_failure("198.51.100.1", "x", now=t + 1) is None
    ban = bans.record_failure("198.51.100.1", "x", now=t + 2)
    assert ban is not None and ban.until == t + 102
    assert bans.banned("198.51.100.1", now=t + 50) is ban
    assert bans.banned("198.51.100.1", now=t + 103) is None
    for i in range(3):
        ban = bans.record_failure("198.51.100.1", "x", now=t + 200 + i)
    assert ban.strikes == 2 and ban.until - ban.created_at == 200
    for i in range(3):
        ban = bans.record_failure("198.51.100.1", "x", now=t + 500 + i)
    assert ban.until - ban.created_at == 300  # capped


def test_failures_outside_window_dont_count():
    bans = BanList(threshold=3, window_seconds=10)
    for i in range(10):
        assert bans.record_failure("198.51.100.2", "x", now=1000 + i * 20) is None


def test_ipv6_banned_per_64_and_loopback_exempt():
    bans = BanList(threshold=2)
    bans.record_failure("2001:db8:1:2::1", "x")
    assert bans.record_failure("2001:db8:1:2::ffff", "x") is not None
    assert bans.banned("2001:db8:1:2:dead::beef") is not None
    for _ in range(50):
        assert bans.record_failure("127.0.0.1", "x") is None


def test_manual_ban_and_unban():
    bans = BanList()
    bans.ban("203.0.113.9", "manual", None)
    assert bans.banned("203.0.113.9", now=10**12) is not None  # until lifted
    assert bans.unban("203.0.113.9") and bans.banned("203.0.113.9") is None


# ----- regressions ---------------------------------------------------------------------


def test_repeating_the_same_credential_does_not_ban():
    bans = BanList(threshold=3)
    for _ in range(20):
        assert bans.record_failure("198.51.100.3", "x", fingerprint="same-old-token") is None
    assert bans.record_failure("198.51.100.3", "x", fingerprint="a") is None  # 2 distinct
    assert bans.record_failure("198.51.100.3", "x", fingerprint="b") is not None  # 3 distinct


def test_escalation_reaches_the_maximum():
    """Strike memory counts from the end of a ban, so long bans keep escalating."""
    bans = BanList(threshold=1, ban_seconds=3600, max_ban_seconds=7 * 86400)
    now, durations = 0.0, []
    for _ in range(10):
        ban = bans.record_failure("198.51.100.4", "x", now=now)
        durations.append(ban.until - ban.created_at)
        now = ban.until + 1  # re-offend right after the ban ends
    assert durations[:6] == [3600 * 2**i for i in range(6)]
    assert durations[-1] == 7 * 86400


def test_slot_granted_then_cancelled_is_released_via_ticket():
    from ollamagate.server.queue import Ticket

    async def run():
        gate = PriorityGate(1)
        first = Ticket()
        await gate.acquire("normal", first)
        second = Ticket()
        waiter = asyncio.create_task(gate.acquire("normal", second))
        await asyncio.sleep(0)
        gate.release(first)  # grants the slot to the waiter...
        waiter.cancel()  # ...which is cancelled before it resumes
        await asyncio.gather(waiter, return_exceptions=True)
        assert second.held  # it still owns the slot
        gate.release(second)
        gate.release(second)  # releasing twice is a no-op
        return gate.active, gate.queued

    assert asyncio.run(run()) == (0, 0)


def test_remaining_quota_caps_output():
    r = apply_body_policy(LIM, "/api/chat", body(model="m"), remaining_tokens=50)
    assert json.loads(r.body)["options"]["num_predict"] == 50
    r = apply_body_policy(DeviceLimits(max_num_predict=0), "/v1/completions", body(model="m"), remaining_tokens=0)
    assert json.loads(r.body)["max_tokens"] == 1


def test_uppercase_or_folded_keys_rejected():
    for bad in (
        body(model="m", MODEL="x"),
        body(model="m", options={"NUM_CTX": 1}),
        body(model="m", stream_options={"Include_Usage": False}),
        body(model="m", **{"ſtream": True}),
    ):
        assert apply_body_policy(LIM, "/api/chat", bad).status == 400


def test_filter_model_list_fails_closed():
    lim = DeviceLimits(allowed_models=["llama3:8b"])
    assert json.loads(filter_model_list(lim, "/api/tags", b"garbage")) == {"models": []}
    assert json.loads(filter_model_list(lim, "/v1/models", b'{"data": "nope"}')) == {"data": []}
    ps = body(models=[{"name": "llama3:8b"}, {"name": "qwen2:7b"}])
    assert [m["name"] for m in json.loads(filter_model_list(lim, "/api/ps", ps))["models"]] == ["llama3:8b"]


def test_large_non_streamed_body_still_counted_exactly():
    c = UsageCounter("application/json", 10)
    c.feed(b'{"model":"m","embeddings":[[' + b"0.123," * 100_000 + b'0.1]],"prompt_eval_count":42}')
    u = c.result()
    assert u.exact and u.prompt_tokens == 42


def test_rpm_retry_after_after_limit_lowered():
    from ollamagate.ratelimit import RateLimiter

    rl = RateLimiter(60, 60.0)
    for i in range(10):
        rl.hit("d", now=float(i))  # hits at t=0..9
    # Limit lowered to 3: the oldest hit that blocks is at t=7 (10 - 3), expiring at 67.
    assert rl.retry_after("d", now=10.0, limit=3) == 58


def test_embeddings_num_ctx_clamped_only_when_given():
    lim = DeviceLimits(max_num_ctx=1024)
    r = apply_body_policy(lim, "/api/embed", body(model="m", input="x", options={"num_ctx": 131072}))
    assert json.loads(r.body)["options"] == {"num_ctx": 1024}
    raw = body(model="m", input="x")
    assert "options" not in json.loads(apply_body_policy(lim, "/api/embed", raw).body)  # Ollama's default applies


# ----- response scrubbing ----------------------------------------------------------------


@pytest.mark.parametrize("msg, leaks", [
    ("model 'nope:latest' not found", False),
    ("model 'library/llama3' not found", False),
    ("invalid model name", False),
    ("see https://ollama.com/a/b", False),
    ("open /home/u/.ollama/models/x: no such file", True),
    (r"open C:\Users\u\.ollama: denied", True),
    (r"\\nas\share\blob missing", True),
])
def test_scrub_error_messages(msg, leaks):
    out = json.loads(scrub_response("/api/chat", 500, body(error=msg)))
    assert out == ({"error": "upstream error"} if leaks else {"error": msg})
    out = json.loads(scrub_response("/v1/chat/completions", 400, body(error={"message": msg, "type": "x"})))
    assert ("message" not in json.dumps(out)) is leaks


def test_scrub_fails_closed():
    assert json.loads(scrub_response("/api/chat", 502, b"<html>/var/x/</html>")) == {"error": "upstream error"}
    assert json.loads(scrub_response("/api/show", 200, b"garbage")) == {}
    assert json.loads(scrub_response("/api/tags", 200, b"[1]")) == {"models": []}
    assert scrub_response("/api/version", 200, b"untouched") == b"untouched"


def test_scrub_modelfile_adapter_and_relative_from():
    mf = "FROM llama3:8b\nADAPTER /home/u/lora.gguf\nSYSTEM use /tmp/x/ paths\n"
    out = json.loads(scrub_response("/api/show", 200, body(modelfile=mf)))["modelfile"]
    assert out == "FROM llama3:8b\n# ADAPTER (local path hidden)\nSYSTEM use /tmp/x/ paths\n"


def test_ban_table_is_bounded(monkeypatch):
    import ollamagate.bans as bans_mod

    monkeypatch.setattr(bans_mod, "MAX_TRACKED_CLIENTS", 5)
    bans = BanList(threshold=1)
    keep = bans.ban("198.51.100.1", "manual", None)
    for i in range(20):
        bans.record_failure(f"2001:db8:0:{i:x}::1", "auth", fingerprint=str(i), now=1000.0 + i)
    assert len(bans.bans) <= 5 and len(bans._strikes) <= 5
    assert bans.bans[keep.key] is keep  # manual bans are never evicted
    assert bans.banned("2001:db8:0:13::1", now=1020.0) is not None  # the newest is kept


def test_noisy_audit_has_a_global_cap():
    from ollamagate.state import NOISY_EVENTS_PER_MINUTE_TOTAL, State

    state = State()
    for i in range(1000):  # every hit from a different /64
        state.audit_noisy("auth_failed", ip=f"2001:db8:{i:x}::1")
    assert len(state.audit_log) == NOISY_EVENTS_PER_MINUTE_TOTAL
    assert state.audit_suppressed == 1000 - NOISY_EVENTS_PER_MINUTE_TOTAL
