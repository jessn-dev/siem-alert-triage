import json
import uuid

import pytest

from siem_engine import DetectionEngine
from src.parsers.mock import MockParser
from src.state.memory import MemoryState

RULES_CONTENT = """
global_tuning:
  allowlisted_ips:
    - "10.0.0.254"
  allowlisted_users:
    - "healthcheck_service"

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


@pytest.fixture
def rules_file(tmp_path):
    path = tmp_path / "rules.yml"
    path.write_text(RULES_CONTENT)
    return str(path)


@pytest.fixture
def parser():
    return MockParser()


@pytest.fixture
def state():
    return MemoryState()


@pytest.fixture
def detector(rules_file, state):
    return DetectionEngine(rules_file, state)


@pytest.fixture
def make_event(parser):
    """Builds a parsed OCSF event with a unique id unless one is supplied."""

    def _make(ip, user, status, ts, event_id=None):
        raw = json.dumps({
            "event_id": event_id or str(uuid.uuid4()),
            "event_type": "authentication",
            "status": status,
            "source_ip": ip,
            "user": user,
            "timestamp": ts,
        })
        return parser.parse(raw)

    return _make


def rule_ids(alerts):
    return sorted(a["rule"]["id"] for a in alerts)
