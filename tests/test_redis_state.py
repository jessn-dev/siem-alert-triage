"""Redis backend parity.

Horizontal scaling is only a real claim if the shared backend produces the same
detections as the in-process one. These run against fakeredis, so CI needs no
Redis server.
"""

import pytest

fakeredis = pytest.importorskip("fakeredis")

from siem_engine import DetectionEngine  # noqa: E402
from src.state.memory import MemoryState  # noqa: E402
from src.state.redis_state import RedisState  # noqa: E402

BASE = "2026-07-24T10:00:"


@pytest.fixture
def redis_state():
    return RedisState(client=fakeredis.FakeStrictRedis(decode_responses=True))


@pytest.fixture(params=["memory", "redis"])
def backend(request):
    if request.param == "memory":
        return MemoryState()
    return RedisState(client=fakeredis.FakeStrictRedis(decode_responses=True))


def test_backends_agree_on_brute_force(rules_file, backend, make_event):
    """Same events, same alerts, regardless of where state lives."""
    engine = DetectionEngine(rules_file, backend)

    alerts = []
    for i in range(3):
        alerts = engine.evaluate(make_event("10.0.0.1", "admin", "failed", f"{BASE}0{i}Z"))

    assert [a["rule"]["id"] for a in alerts] == ["R001"]


def test_backends_agree_on_sequence_rule(rules_file, backend, make_event):
    engine = DetectionEngine(rules_file, backend)
    for i in range(3):
        engine.evaluate(make_event("10.0.0.2", "admin", "failed", f"{BASE}0{i}Z"))
    alerts = engine.evaluate(make_event("10.0.0.2", "admin", "success", f"{BASE}05Z"))
    assert "R002" in [a["rule"]["id"] for a in alerts]


def test_backends_agree_on_cooldown(rules_file, backend, make_event):
    engine = DetectionEngine(rules_file, backend)
    for i in range(3):
        alerts = engine.evaluate(make_event("10.0.0.3", "admin", "failed", f"{BASE}0{i}Z"))
    assert "R001" in [a["rule"]["id"] for a in alerts]

    repeat = engine.evaluate(make_event("10.0.0.3", "admin", "failed", f"{BASE}04Z"))
    assert "R001" not in [a["rule"]["id"] for a in repeat]


def test_redis_watermark_is_per_key(redis_state):
    redis_state.update_watermark("1.1.1.1", 1000.0)
    redis_state.update_watermark("2.2.2.2", 5000.0)

    assert redis_state.get_watermark("1.1.1.1") == 1000.0
    assert redis_state.get_watermark("2.2.2.2") == 5000.0


def test_redis_windows_are_bounded(redis_state):
    """Regression: a stubbed watermark made every query return all history."""
    redis_state.update_watermark("1.2.3.4", 2000.0)
    redis_state.add_event("1.2.3.4", "Failure", (1000.0, "old", "e-old", "raw"))
    redis_state.add_event("1.2.3.4", "Failure", (1990.0, "recent", "e-new", "raw"))

    within = redis_state.get_events("1.2.3.4", "Failure", 30)
    assert [e[1] for e in within] == ["recent"]


def test_redis_dedup_is_atomic(redis_state):
    assert redis_state.is_duplicate("event-1") is False
    assert redis_state.is_duplicate("event-1") is True


def test_redis_sweep_trims_aged_members(redis_state):
    redis_state.update_watermark("1.2.3.4", 2000.0)
    redis_state.add_event("1.2.3.4", "Failure", (1000.0, "old", "e1", "raw"))
    redis_state.add_event("1.2.3.4", "Failure", (1995.0, "new", "e2", "raw"))

    redis_state.sweep(max_window=60, max_suppression=120)

    remaining = redis_state.client.zrange(redis_state._events_key("1.2.3.4", "Failure"), 0, -1)
    assert len(remaining) == 1


def test_redis_active_count_uses_scan(redis_state):
    redis_state.update_watermark("1.1.1.1", 1000.0)
    redis_state.add_event("1.1.1.1", "Failure", (1000.0, "admin", "e1", "raw"))
    redis_state.add_event("2.2.2.2", "Success", (1000.0, "bob", "e2", "raw"))

    assert redis_state.get_active_count() == 1


def test_redis_key_parsing_survives_ipv6(redis_state):
    assert RedisState._ip_from_events_key("siem:events:2001:db8::1:Failure") == "2001:db8::1"
    assert RedisState._ip_from_events_key("siem:events:10.0.0.1:Failure") == "10.0.0.1"
