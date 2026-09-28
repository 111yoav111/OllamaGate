"""Phase 4: body policy, token accounting, the priority gate and bans (unit tests)."""

from __future__ import annotations

import asyncio
import json

import pytest

from ollamagate.bans import BanList
from ollamagate.server.policy import apply_body_policy, filter_model_list, model_allowed, normalize_model
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
    assert r.error is None and r.streaming is True


def test_sets_missing_limits_and_keeps_lower_values():
    data = json.loads(apply_body_policy(LIM, "/api/generate", body(model="m", stream=False)).body)
    assert data["options"] == {"num_ctx": 4096, "num_predict": 512}
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
    assert apply_body_policy(LIM, "/api/pull", raw).body is raw


def test_unchanged_bodies_are_not_reserialized():
    lim = DeviceLimits(max_num_ctx=0, max_num_predict=0)
    raw = body(model="m", messages=[])
    assert apply_body_policy(lim, "/api/embed", raw).body is raw


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
