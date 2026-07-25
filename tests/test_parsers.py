"""Normalization: every source must produce one OCSF shape the rules understand."""

import json

import pytest

from src.parsers.base import to_epoch_millis
from src.parsers.cloudtrail import CloudTrailParser
from src.parsers.mock import MockParser

CLOUDTRAIL_FAILURE = json.dumps({
    "eventVersion": "1.08",
    "eventTime": "2026-07-24T10:00:00Z",
    "eventSource": "signin.amazonaws.com",
    "eventName": "ConsoleLogin",
    "eventID": "b1a2c3d4-0000-4444-8888-999900001111",
    "sourceIPAddress": "203.0.113.5",
    "userIdentity": {"type": "IAMUser", "userName": "deploy-bot"},
    "responseElements": {"ConsoleLogin": "Failure"},
})

CLOUDTRAIL_ROOT_SUCCESS = json.dumps({
    "eventTime": "2026-07-24T10:00:05Z",
    "eventName": "ConsoleLogin",
    "eventID": "root-login-1",
    "sourceIPAddress": "198.51.100.22",
    "userIdentity": {"type": "Root"},
    "responseElements": {"ConsoleLogin": "Success"},
})

MOCK_LINE = json.dumps({
    "event_id": "abc-123",
    "status": "failed",
    "source_ip": "10.0.0.1",
    "user": "admin",
    "timestamp": "2026-07-24T10:00:00Z",
})


def test_mock_parser_emits_ocsf_authentication():
    event = MockParser().parse(MOCK_LINE)

    assert event["class_uid"] == 3002
    assert event["category_uid"] == 3
    assert event["type_uid"] == 300201
    assert event["activity_id"] == 1
    assert event["activity_name"] == "Logon"
    assert event["status_id"] == 2
    assert event["status"] == "Failure"
    assert event["src_endpoint"]["ip"] == "10.0.0.1"
    assert event["user"]["name"] == "admin"
    assert event["metadata"]["event_id"] == "abc-123"


def test_ocsf_time_is_integer_epoch_millis():
    event = MockParser().parse(MOCK_LINE)
    assert isinstance(event["time"], int)
    assert event["time"] == 1784887200000  # 2026-07-24T10:00:00Z
    assert event["time_dt"] == "2026-07-24T10:00:00Z"


def test_cloudtrail_parser_matches_mock_parser_shape():
    """The agnosticism claim: two clouds, one schema, identical key set."""
    mock_event = MockParser().parse(MOCK_LINE)
    ct_event = CloudTrailParser().parse(CLOUDTRAIL_FAILURE)

    assert set(mock_event) == set(ct_event)
    assert ct_event["class_uid"] == mock_event["class_uid"]
    assert ct_event["status"] == "Failure"
    assert ct_event["user"]["name"] == "deploy-bot"
    assert ct_event["src_endpoint"]["ip"] == "203.0.113.5"
    assert ct_event["metadata"]["product"]["name"] == "AWS CloudTrail"


def test_cloudtrail_root_login_without_username():
    event = CloudTrailParser().parse(CLOUDTRAIL_ROOT_SUCCESS)
    assert event["user"]["name"] == "Root"
    assert event["status_id"] == 1


def test_cloudtrail_ignores_non_login_events():
    assert CloudTrailParser().parse(json.dumps({"eventName": "PutObject"})) is None


@pytest.mark.parametrize("parser", [MockParser(), CloudTrailParser()])
def test_parsers_reject_malformed_input(parser):
    assert parser.parse('{"broken": ') is None
    assert parser.parse("[]") is None


def test_cloudtrail_events_drive_the_same_rules(rules_file, state):
    """A CloudTrail brute force fires R001 with zero rule changes."""
    from siem_engine import DetectionEngine

    engine = DetectionEngine(rules_file, state)
    parser = CloudTrailParser()

    alerts = []
    for i in range(3):
        raw = json.dumps({
            "eventTime": f"2026-07-24T10:00:0{i}Z",
            "eventName": "ConsoleLogin",
            "eventID": f"ct-{i}",
            "sourceIPAddress": "203.0.113.5",
            "userIdentity": {"type": "IAMUser", "userName": "deploy-bot"},
            "responseElements": {"ConsoleLogin": "Failure"},
        })
        alerts = engine.evaluate(parser.parse(raw))

    assert [a["rule"]["id"] for a in alerts] == ["R001"]


def test_to_epoch_millis_handles_bad_input():
    assert to_epoch_millis(None) == 0
    assert to_epoch_millis("not-a-date") == 0
    assert to_epoch_millis(1784887200000) == 1784887200000
