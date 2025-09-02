import pytest
from datetime import datetime
from siem_engine import BruteForceDetector, parse_log

def test_parse_log_valid():
    """Test valid JSON log parsing."""
    log_line = '{"event_type": "authentication", "status": "failed"}'
    result = parse_log(log_line)
    assert result["status"] == "failed"

def test_parse_log_malformed():
    """Test handling of malformed JSON strings."""
    log_line = '{"event_type": "authentication", "status": "fail' # Broken JSON
    result = parse_log(log_line)
    assert result is None

def test_detector_missing_fields():
    """Test handling of dictionaries missing required fields."""
    detector = BruteForceDetector()
    # Missing source_ip and timestamp
    log_dict = {"event_type": "authentication", "status": "failed", "user": "admin"}
    assert detector.evaluate(log_dict) is None
    assert len(detector.failed_logins) == 0

def test_detector_threshold_boundary():
    """Test that the threshold boundary (3 vs 4) is respected."""
    detector = BruteForceDetector(threshold=3, time_window=30, suppression_window=60)
    ip = "10.0.0.1"
    
    # 1st attempt
    assert detector.evaluate({"event_type": "authentication", "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:00Z"}) is None
    # 2nd attempt
    assert detector.evaluate({"event_type": "authentication", "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:01Z"}) is None
    # 3rd attempt (Equal to threshold, should NOT fire)
    assert detector.evaluate({"event_type": "authentication", "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:02Z"}) is None
    # 4th attempt (Exceeds threshold, MUST fire)
    assert detector.evaluate({"event_type": "authentication", "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:03Z"}) == ["admin"]
    
    # State should remain intact, but last_alerted timestamp should be set for cooldown
    assert len(detector.failed_logins[ip]) == 4
    assert ip in detector.last_alerted

def test_detector_window_expiry():
    """Test that old attempts age out correctly based on the time window."""
    detector = BruteForceDetector(threshold=3, time_window=30)
    ip = "10.0.0.2"
    
    # 3 attempts far in the past
    detector.evaluate({"event_type": "authentication", "status": "failed", "source_ip": ip, "user": "alice", "timestamp": "2026-07-24T10:00:00Z"})
    detector.evaluate({"event_type": "authentication", "status": "failed", "source_ip": ip, "user": "alice", "timestamp": "2026-07-24T10:00:01Z"})
    detector.evaluate({"event_type": "authentication", "status": "failed", "source_ip": ip, "user": "alice", "timestamp": "2026-07-24T10:00:02Z"})
    
    # 4th attempt happens 40 seconds later, well outside the 30s window.
    # The first 3 should be aged out, leaving only this new 1 attempt in state.
    res = detector.evaluate({"event_type": "authentication", "status": "failed", "source_ip": ip, "user": "alice", "timestamp": "2026-07-24T10:00:42Z"})
    
    assert res is None # Should NOT fire
    assert len(detector.failed_logins[ip]) == 1 # Only the new attempt remains

def test_detector_cooldown():
    """Test that cooldown prevents spamming alerts."""
    detector = BruteForceDetector(threshold=3, time_window=30, suppression_window=60)
    ip = "10.0.0.3"
    
    # Send 4 attempts rapidly to trigger alert
    for i in range(4):
        res = detector.evaluate({"event_type": "authentication", "status": "failed", "source_ip": ip, "user": "admin", "timestamp": f"2026-07-24T10:00:0{i}Z"})
    assert res == ["admin"]
    
    # 5th attempt immediately after should be suppressed
    res2 = detector.evaluate({"event_type": "authentication", "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:05Z"})
    assert res2 is None
    
    # 70 seconds later... the attacker sends another burst of 4
    # The original 5 are aged out (30s window), so we need 4 new ones to trigger again.
    for i in range(4):
        res3 = detector.evaluate({"event_type": "authentication", "status": "failed", "source_ip": ip, "user": "admin", "timestamp": f"2026-07-24T10:01:1{i}Z"})
    
    # The 4th new attempt (outside suppression window) should trigger a new alert
    assert res3 == ["admin"]

def test_detector_global_sweep():
    """Test that the global sweep correctly frees unbounded memory."""
    detector = BruteForceDetector(threshold=3, time_window=30, suppression_window=60)
    ip = "10.0.0.4"
    
    detector.evaluate({"event_type": "authentication", "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:00Z"})
    assert ip in detector.failed_logins
    
    # Sweep with current time 100 seconds later (past time window and cooldown window)
    current_time_mock = datetime.fromisoformat("2026-07-24T10:01:40+00:00").timestamp()
    detector.sweep_global_state(current_time_mock)
    
    assert ip not in detector.failed_logins
