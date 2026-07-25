"""Rule-level behaviour: thresholds, sequences, sprays, suppression, tuning."""

from conftest import rule_ids

BASE = "2026-07-24T10:00:"


def test_threshold_boundary_not_reached(detector, make_event):
    """Threshold is 3. Two failures must stay silent."""
    detector.evaluate(make_event("10.0.0.1", "admin", "failed", f"{BASE}00Z"))
    alerts = detector.evaluate(make_event("10.0.0.1", "admin", "failed", f"{BASE}01Z"))
    assert alerts == []


def test_threshold_fires_at_boundary(detector, make_event):
    for i in range(2):
        detector.evaluate(make_event("10.0.0.1", "admin", "failed", f"{BASE}0{i}Z"))
    alerts = detector.evaluate(make_event("10.0.0.1", "admin", "failed", f"{BASE}02Z"))
    assert "R001" in rule_ids(alerts)


def test_success_does_not_advance_threshold_rule(detector, make_event):
    """A successful login must not push a volume rule over its threshold."""
    for i in range(2):
        detector.evaluate(make_event("10.0.0.2", "admin", "failed", f"{BASE}0{i}Z"))
    alerts = detector.evaluate(make_event("10.0.0.2", "admin", "success", f"{BASE}03Z"))
    assert "R001" not in rule_ids(alerts)


def test_window_expiry_ages_out_old_failures(detector, make_event, state):
    """Failures older than time_window stop counting toward the threshold."""
    for i in range(2):
        detector.evaluate(make_event("10.0.0.3", "alice", "failed", f"{BASE}0{i}Z"))

    # 40s later, outside the 30s window.
    alerts = detector.evaluate(make_event("10.0.0.3", "alice", "failed", "2026-07-24T10:00:42Z"))
    assert alerts == []
    assert len(state.get_events("10.0.0.3", "Failure", 30)) == 1


def test_cooldown_suppresses_repeat_alerts(detector, make_event):
    for i in range(3):
        alerts = detector.evaluate(make_event("10.0.0.4", "admin", "failed", f"{BASE}0{i}Z"))
    assert "R001" in rule_ids(alerts)

    # Still inside the 60s suppression window.
    repeat = detector.evaluate(make_event("10.0.0.4", "admin", "failed", f"{BASE}04Z"))
    assert "R001" not in rule_ids(repeat)


def test_cooldown_expires_and_rule_can_fire_again(detector, make_event):
    for i in range(3):
        detector.evaluate(make_event("10.0.0.5", "admin", "failed", f"{BASE}0{i}Z"))

    # Past both the 30s window and the 60s suppression window.
    for i in range(3):
        alerts = detector.evaluate(make_event("10.0.0.5", "admin", "failed", f"2026-07-24T10:02:0{i}Z"))
    assert "R001" in rule_ids(alerts)


def test_sequence_rule_fires_on_targeted_account(detector, make_event):
    for i in range(3):
        detector.evaluate(make_event("10.0.0.6", "admin", "failed", f"{BASE}0{i}Z"))
    alerts = detector.evaluate(make_event("10.0.0.6", "admin", "success", f"{BASE}05Z"))

    assert "R002" in rule_ids(alerts)
    compromise = next(a for a in alerts if a["rule"]["id"] == "R002")
    assert compromise["targets"] == ["admin"]
    # Evidence carries the failure burst plus the successful login.
    assert len(compromise["evidence"]) == 4


def test_sequence_rule_ignores_untargeted_account(detector, make_event):
    """The NAT-gateway guard: shared egress IP, unrelated user logs in fine."""
    for i in range(3):
        detector.evaluate(make_event("10.0.0.7", "admin", "failed", f"{BASE}0{i}Z"))
    alerts = detector.evaluate(make_event("10.0.0.7", "unrelated", "success", f"{BASE}05Z"))
    assert "R002" not in rule_ids(alerts)


def test_spray_rule_counts_unique_targets(detector, make_event):
    for i, user in enumerate(["alice", "bob", "charlie"]):
        alerts = detector.evaluate(make_event("10.0.0.8", user, "failed", f"{BASE}0{i}Z"))

    assert "R003" in rule_ids(alerts)
    spray = next(a for a in alerts if a["rule"]["id"] == "R003")
    assert spray["targets"] == ["alice", "bob", "charlie"]


def test_spray_rule_ignores_repeat_of_same_account(detector, make_event):
    """Volume against one account is brute force, not spray."""
    for i in range(3):
        alerts = detector.evaluate(make_event("10.0.0.9", "admin", "failed", f"{BASE}0{i}Z"))
    assert "R003" not in rule_ids(alerts)


def test_allowlisted_ip_is_never_tracked(detector, make_event, state):
    for i in range(4):
        assert detector.evaluate(make_event("10.0.0.254", "admin", "failed", f"{BASE}0{i}Z")) == []
    assert "10.0.0.254" not in state.state


def test_allowlisted_user_is_never_tracked(detector, make_event, state):
    for i in range(4):
        assert detector.evaluate(make_event("10.1.1.1", "healthcheck_service", "failed", f"{BASE}0{i}Z")) == []
    assert "10.1.1.1" not in state.state


def test_unknown_rule_type_is_skipped_not_fatal(rules_file, state, make_event, tmp_path):
    from siem_engine import DetectionEngine

    path = tmp_path / "bad.yml"
    path.write_text(
        'rules:\n'
        '  - id: "R900"\n'
        '    name: "Unsupported"\n'
        '    type: "ml_magic"\n'
        '    time_window: 30\n'
        '    suppression_window: 60\n'
    )
    engine = DetectionEngine(str(path), state)
    assert engine.evaluate(make_event("10.2.2.2", "admin", "failed", f"{BASE}00Z")) == []
