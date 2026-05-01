import pytest
import os
import uuid
from datetime import datetime
from siem_engine import DetectionEngine
from src.state.memory import MemoryState
from src.parsers.mock import MockParser

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

@pytest.fixture
def parser():
    return MockParser()

@pytest.fixture
def detector(setup_rules):
    state = MemoryState()
    return DetectionEngine(setup_rules, state)

def test_parse_log_valid(parser):
    """Test valid JSON log parsing into OCSF schema."""
    log_line = '{"event_type": "authentication", "status": "failed", "event_id": "123", "source_ip": "10.0.0.1", "user": "admin", "timestamp": "2026-07-24T10:00:00Z"}'
    result = parser.parse(log_line)
    assert result["status"] == "Failure"
    assert result["src_endpoint"]["ip"] == "10.0.0.1"

def test_parse_log_malformed(parser):
    """Test handling of malformed JSON strings."""
    log_line = '{"event_type": "authentication", "status": "fail'
    result = parser.parse(log_line)
    assert result is None

def test_detector_idempotency(detector, parser):
    """Test that duplicate events are ignored."""
    event_id = str(uuid.uuid4())
    log_line = f'{{"event_id": "{event_id}", "event_type": "authentication", "status": "failed", "source_ip": "1.2.3.4", "user": "admin", "timestamp": "2026-07-24T10:00:00Z"}}'
    
    ocsf_event = parser.parse(log_line)
    
    assert detector.evaluate(ocsf_event) == []
    assert detector.evaluate(ocsf_event) == []
    assert detector.evaluate(ocsf_event) == []
    assert detector.evaluate(ocsf_event) == []
    
    assert len(detector.state.state["1.2.3.4"]["Failure"]) == 1

def test_detector_threshold_boundary(detector, parser):
    """Test that the threshold boundary is respected."""
    ip = "10.0.0.1"
    
    e1 = parser.parse(f'{{"event_id": "{uuid.uuid4()}", "status": "failed", "source_ip": "{ip}", "user": "admin", "timestamp": "2026-07-24T10:00:00Z"}}')
    e2 = parser.parse(f'{{"event_id": "{uuid.uuid4()}", "status": "failed", "source_ip": "{ip}", "user": "admin", "timestamp": "2026-07-24T10:00:01Z"}}')
    e3 = parser.parse(f'{{"event_id": "{uuid.uuid4()}", "status": "failed", "source_ip": "{ip}", "user": "admin", "timestamp": "2026-07-24T10:00:02Z"}}')
    
    detector.evaluate(e1)
    detector.evaluate(e2)
    alerts = detector.evaluate(e3)
    
    assert len(alerts) == 1
    assert alerts[0]["rule"]["id"] == "R001"
    
def test_detector_compromise_rule(detector, parser):
    """Test that a successful login following brute force triggers a compromise alert."""
    ip = "10.0.0.6"
    
    for i in range(3):
        e = parser.parse(f'{{"event_id": "{uuid.uuid4()}", "status": "failed", "source_ip": "{ip}", "user": "admin", "timestamp": "2026-07-24T10:00:0{i}Z"}}')
        detector.evaluate(e)
        
    e_success = parser.parse(f'{{"event_id": "{uuid.uuid4()}", "status": "success", "source_ip": "{ip}", "user": "admin", "timestamp": "2026-07-24T10:00:05Z"}}')
    alerts = detector.evaluate(e_success)
    
    assert len(alerts) == 1
    assert alerts[0]["rule"]["id"] == "R002"
    assert alerts[0]["targets"] == ["admin"]

def test_detector_watermark_sweep(detector, parser):
    """Test that sweep uses event watermark, not wall clock."""
    ip = "10.0.0.4"
    
    e1 = parser.parse(f'{{"event_id": "{uuid.uuid4()}", "status": "failed", "source_ip": "{ip}", "user": "admin", "timestamp": "2026-07-24T10:00:00Z"}}')
    detector.evaluate(e1)
    assert len(detector.state.state[ip]["Failure"]) == 1
    
    detector.sweep()
    assert len(detector.state.state[ip]["Failure"]) == 1
    
    e2 = parser.parse(f'{{"event_id": "{uuid.uuid4()}", "status": "success", "source_ip": "10.0.0.9", "user": "bob", "timestamp": "2026-07-24T10:01:40Z"}}')
    detector.evaluate(e2)
    
    detector.sweep()
    assert ip not in detector.state.state
