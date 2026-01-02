import pytest
import os
import uuid
from datetime import datetime
from siem_engine import DetectionEngine, parse_log

# Create a mock rules file for testing
RULES_CONTENT = """
rules:
  - id: "R001"
    name: "Potential Brute Force Attack"
    severity: "MEDIUM"
    threshold: 3
    time_window: 30
    suppression_window: 60
  - id: "R002"
    name: "Successful Compromise Following Brute Force"
    severity: "CRITICAL"
    threshold: 3
    time_window: 60
    suppression_window: 120
"""

@pytest.fixture(autouse=True)
def setup_rules(tmp_path):
    rules_file = tmp_path / "rules.yml"
    rules_file.write_text(RULES_CONTENT)
    return str(rules_file)

def test_parse_log_valid():
    """Test valid JSON log parsing."""
    log_line = '{"event_type": "authentication", "status": "failed", "event_id": "123"}'
    result = parse_log(log_line)
    assert result["status"] == "failed"

def test_parse_log_malformed():
    """Test handling of malformed JSON strings."""
    log_line = '{"event_type": "authentication", "status": "fail'
    result = parse_log(log_line)
    assert result is None

def test_detector_idempotency(setup_rules):
    """Test that duplicate events are ignored."""
    detector = DetectionEngine(setup_rules)
    event_id = str(uuid.uuid4())
    log_dict = {"event_id": event_id, "event_type": "authentication", "status": "failed", "source_ip": "1.2.3.4", "user": "admin", "timestamp": "2026-07-24T10:00:00Z"}
    
    # Send it 4 times
    assert detector.evaluate(log_dict) == []
    assert detector.evaluate(log_dict) is None
    assert detector.evaluate(log_dict) is None
    assert detector.evaluate(log_dict) is None
    
    # State should only have 1 entry
    assert len(detector.state["1.2.3.4"]["failed"]) == 1

def test_detector_threshold_boundary(setup_rules):
    """Test that the threshold boundary (3 vs 4) is respected."""
    detector = DetectionEngine(setup_rules)
    ip = "10.0.0.1"
    
    detector.evaluate({"event_id": str(uuid.uuid4()), "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:00Z"})
    detector.evaluate({"event_id": str(uuid.uuid4()), "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:01Z"})
    alerts = detector.evaluate({"event_id": str(uuid.uuid4()), "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:02Z"})
    assert len(alerts) == 1

    # Ah, I set threshold to 3, and len >= 3 triggers it. So 3rd attempt triggers it!
    # Let's adjust test to expect trigger on 3rd attempt.
    
def test_detector_brute_force_rule(setup_rules):
    detector = DetectionEngine(setup_rules)
    ip = "10.0.0.5"
    
    detector.evaluate({"event_id": str(uuid.uuid4()), "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:00Z"})
    detector.evaluate({"event_id": str(uuid.uuid4()), "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:01Z"})
    
    # 3rd failed attempt should trigger R001
    alerts = detector.evaluate({"event_id": str(uuid.uuid4()), "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:02Z"})
    assert len(alerts) == 1
    assert alerts[0]["rule"]["id"] == "R001"
    
def test_detector_compromise_rule(setup_rules):
    detector = DetectionEngine(setup_rules)
    ip = "10.0.0.6"
    
    # 3 failed attempts
    for i in range(3):
        detector.evaluate({"event_id": str(uuid.uuid4()), "status": "failed", "source_ip": ip, "user": "admin", "timestamp": f"2026-07-24T10:00:0{i}Z"})
        
    # 1 success attempt immediately after
    alerts = detector.evaluate({"event_id": str(uuid.uuid4()), "status": "success", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:05Z"})
    
    # Should trigger R002 (Compromise)
    assert len(alerts) == 1
    assert alerts[0]["rule"]["id"] == "R002"
    assert alerts[0]["targets"] == ["admin"]

def test_detector_watermark_sweep(setup_rules):
    """Test that sweep uses event watermark, not wall clock."""
    detector = DetectionEngine(setup_rules)
    ip = "10.0.0.4"
    
    detector.evaluate({"event_id": str(uuid.uuid4()), "status": "failed", "source_ip": ip, "user": "admin", "timestamp": "2026-07-24T10:00:00Z"})
    assert len(detector.state[ip]["failed"]) == 1
    
    # Sweep now. Watermark is at 10:00:00. State should NOT be cleared because window is 60s.
    detector.sweep_global_state()
    assert len(detector.state[ip]["failed"]) == 1
    
    # Process event 100 seconds later. Watermark advances.
    detector.evaluate({"event_id": str(uuid.uuid4()), "status": "success", "source_ip": "10.0.0.9", "user": "bob", "timestamp": "2026-07-24T10:01:40Z"})
    
    # Sweep now. The 10:00:00 event should be pruned from state.
    detector.sweep_global_state()
    assert ip not in detector.state
