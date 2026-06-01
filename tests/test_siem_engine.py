import pytest
import os
import uuid
from datetime import datetime
from siem_engine import DetectionEngine, enrich_context, calculate_dynamic_risk
from src.state.memory import MemoryState
from src.parsers.mock import MockParser

RULES_CONTENT = """
global_tuning:
  allowlisted_ips:
    - "10.0.0.254"
  allowlisted_users:
    - "healthcheck"

rules:
  - id: "R001"
    name: "Potential Brute Force Attack"
    type: "threshold"
    mitre_attack: "T1110.001"
    base_risk: 40
    threshold: 3
    time_window: 30
    suppression_window: 60
  - id: "R002"
    name: "Successful Compromise Following Brute Force"
    type: "sequence"
    mitre_attack: "T1078"
    base_risk: 80
    threshold: 3
    time_window: 60
    suppression_window: 120
  - id: "R003"
    name: "Password Spraying Attack"
    type: "spray"
    mitre_attack: "T1110.003"
    base_risk: 60
    unique_targets: 3
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
    log_line = '{"event_type": "authentication", "status": "failed", "event_id": "123", "source_ip": "10.0.0.1", "user": "admin", "timestamp": "2026-07-24T10:00:00Z"}'
    result = parser.parse(log_line)
    assert result["status"] == "Failure"
    assert result["src_endpoint"]["ip"] == "10.0.0.1"

def test_detector_allowlist(detector, parser):
    """Test that allowlisted IPs and users are ignored."""
    ip = "10.0.0.254"
    e = parser.parse(f'{{"event_id": "{uuid.uuid4()}", "status": "failed", "source_ip": "{ip}", "user": "admin", "timestamp": "2026-07-24T10:00:00Z"}}')
    assert len(detector.evaluate(e)) == 0
    assert len(detector.state.state[ip]["Failure"]) == 0

def test_detector_password_spray(detector, parser):
    """Test Password Spray rule triggering on unique targets."""
    ip = "10.0.0.7"
    e1 = parser.parse(f'{{"event_id": "{uuid.uuid4()}", "status": "failed", "source_ip": "{ip}", "user": "alice", "timestamp": "2026-07-24T10:00:00Z"}}')
    e2 = parser.parse(f'{{"event_id": "{uuid.uuid4()}", "status": "failed", "source_ip": "{ip}", "user": "bob", "timestamp": "2026-07-24T10:00:01Z"}}')
    e3 = parser.parse(f'{{"event_id": "{uuid.uuid4()}", "status": "failed", "source_ip": "{ip}", "user": "charlie", "timestamp": "2026-07-24T10:00:02Z"}}')
    
    detector.evaluate(e1)
    detector.evaluate(e2)
    alerts = detector.evaluate(e3)
    
    rule_ids = [a["rule"]["id"] for a in alerts]
    assert "R003" in rule_ids
    # R001 (Threshold) will also fire since 3 fails = threshold, which is expected behavior
    spray_alert = next(a for a in alerts if a["rule"]["id"] == "R003")
    assert len(spray_alert["targets"]) == 3

def test_dynamic_risk_scoring():
    """Test that risk score correctly bumps up based on GeoIP and asset criticality."""
    enrichment = enrich_context("100.1.1.1", ["admin", "bob"])
    assert enrichment["geoip"]["country"] == "RU"
    assert enrichment["asset_context"]["critical_targets_hit"] == 1
    
    # base 40 + 20 (RU) + 10 (1 critical admin) = 70 (HIGH)
    score, sev = calculate_dynamic_risk(40, enrichment)
    assert score == 70
    assert sev == "HIGH"

def test_detector_idempotency(detector, parser):
    event_id = str(uuid.uuid4())
    log_line = f'{{"event_id": "{event_id}", "event_type": "authentication", "status": "failed", "source_ip": "1.2.3.4", "user": "admin", "timestamp": "2026-07-24T10:00:00Z"}}'
    
    ocsf_event = parser.parse(log_line)
    assert detector.evaluate(ocsf_event) == []
    assert detector.evaluate(ocsf_event) == []
    
    assert len(detector.state.state["1.2.3.4"]["Failure"]) == 1
