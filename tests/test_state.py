"""State-layer invariants: clock isolation, dedup durability, sweep bounds."""

from conftest import rule_ids

from src.state.memory import MemoryState

BASE = "2026-07-24T10:00:"


def test_watermark_is_per_key(state):
    """One IP's clock must never advance another IP's window."""
    state.update_watermark("1.1.1.1", 1000.0)
    state.update_watermark("2.2.2.2", 5000.0)

    assert state.get_watermark("1.1.1.1") == 1000.0
    assert state.get_watermark("2.2.2.2") == 5000.0


def test_skewed_host_cannot_flush_another_ips_window(detector, make_event, state):
    """Regression: a global watermark let one desynced clock blind the engine.

    A host reporting 50 minutes into the future sits inside the max-skew bound,
    so it is accepted - and must still not touch the attacker's window.
    """
    for i in range(2):
        detector.evaluate(make_event("6.6.6.6", "admin", "failed", f"{BASE}0{i}Z"))
    assert len(state.get_events("6.6.6.6", "Failure", 30)) == 2

    # Unrelated host, clock 50 minutes ahead.
    detector.evaluate(make_event("7.7.7.7", "bob", "failed", "2026-07-24T10:50:00Z"))

    assert len(state.get_events("6.6.6.6", "Failure", 30)) == 2
    alerts = detector.evaluate(make_event("6.6.6.6", "admin", "failed", f"{BASE}02Z"))
    assert "R001" in rule_ids(alerts)


def test_events_beyond_max_skew_are_rejected(detector, make_event, state):
    """Timestamps far enough ahead to freeze an IP's own window are dropped."""
    detector.max_clock_skew = 60
    assert detector.evaluate(make_event("8.8.8.8", "admin", "failed", "2099-01-01T00:00:00Z")) == []
    assert "8.8.8.8" not in state.state


def test_dedup_evicts_oldest_only(state):
    """Bounded LRU: a full cache must not drop every id at once."""
    small = MemoryState(dedup_capacity=3)
    assert small.is_duplicate("first") is False
    for i in range(2):
        small.is_duplicate(f"noise-{i}")

    # Still remembered while within capacity.
    assert small.is_duplicate("first") is True

    # Overflow evicts strictly the oldest entry.
    small.is_duplicate("overflow-a")
    small.is_duplicate("overflow-b")
    assert small.is_duplicate("noise-1") is True


def test_duplicate_event_counts_once(detector, parser, state):
    """At-least-once delivery must not inflate a threshold into a false positive."""
    import json

    raw = json.dumps({
        "event_id": "fixed-id",
        "status": "failed",
        "source_ip": "9.9.9.9",
        "user": "bob",
        "timestamp": f"{BASE}00Z",
    })

    results = [detector.evaluate(parser.parse(raw)) for _ in range(5)]
    assert all(r == [] for r in results)
    assert len(state.state["9.9.9.9"]["Failure"]) == 1


def test_sweep_evicts_idle_ips(rules_file, make_event):
    """GC runs on arrival time: an IP that stops sending is eventually dropped.

    An idle IP's own event clock never advances, so event time alone could
    never age it out and the state would leak.
    """
    from siem_engine import DetectionEngine

    clock = [1000.0]
    state = MemoryState(time_source=lambda: clock[0])
    detector = DetectionEngine(rules_file, state)

    detector.evaluate(make_event("5.5.5.5", "admin", "failed", f"{BASE}00Z"))
    assert "5.5.5.5" in state.state

    detector.sweep()
    assert "5.5.5.5" in state.state, "must survive while recently seen"

    # Past max_window (60) + max_suppression (120) of wall time with no traffic.
    clock[0] += 200
    detector.sweep()
    assert "5.5.5.5" not in state.state
    assert "5.5.5.5" not in state.watermarks


def test_sweep_keeps_ip_under_active_attack(rules_file, make_event):
    """Long, slow attacks must not be garbage collected mid-detection."""
    from siem_engine import DetectionEngine

    clock = [1000.0]
    state = MemoryState(time_source=lambda: clock[0])
    detector = DetectionEngine(rules_file, state)

    for minute in range(6):
        clock[0] += 100
        detector.evaluate(make_event("3.3.3.3", "admin", "failed", f"2026-07-24T10:0{minute}:00Z"))
        detector.sweep()

    assert "3.3.3.3" in state.state


def test_sweep_retains_state_inside_window(detector, make_event, state):
    detector.evaluate(make_event("4.4.4.4", "admin", "failed", f"{BASE}00Z"))
    detector.sweep()
    assert "4.4.4.4" in state.state


def test_sweep_windows_derive_from_rules(detector):
    """Sweep bounds come from rules.yml, not hardcoded constants."""
    assert detector.max_time_window == 60
    assert detector.max_suppression_window == 120
