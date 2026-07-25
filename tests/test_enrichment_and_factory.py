"""Risk scoring, alert payload shape, and backend selection."""

import importlib

import pytest

from siem_engine import build_alert_payload
from src.enrichment import calculate_dynamic_risk, enrich_context, lookup_country


def test_internal_ip_is_recognised():
    ctx = enrich_context("192.168.1.50", ["testuser"])
    assert ctx["geoip"]["country"] == "INTERNAL"
    assert ctx["geoip"]["is_internal"] is True


def test_public_ip_resolves_to_geography():
    assert lookup_country("203.0.113.5") == "RU"
    assert lookup_country("198.51.100.22") == "CN"
    assert lookup_country("8.8.8.8") == "UNKNOWN"


def test_identical_attack_scores_lower_from_internal_network():
    """Same rule, same account - context decides whether it pages."""
    internal = enrich_context("192.168.1.50", ["testuser"])
    external = enrich_context("203.0.113.5", ["admin"])

    internal_score, internal_sev = calculate_dynamic_risk(40, internal)
    external_score, external_sev = calculate_dynamic_risk(40, external)

    assert (internal_score, internal_sev) == (40, "MEDIUM")
    assert (external_score, external_sev) == (70, "HIGH")


def test_critical_account_raises_score():
    ctx = enrich_context("203.0.113.5", ["admin", "root", "bob"])
    assert ctx["asset_context"]["critical_targets_hit"] == 2
    score, severity = calculate_dynamic_risk(40, ctx)
    assert score == 80
    assert severity == "CRITICAL"


def test_score_is_capped_at_100():
    ctx = enrich_context("100.20.30.40", ["admin", "root", "ceo"])
    score, severity = calculate_dynamic_risk(80, ctx)
    assert score == 100
    assert severity == "CRITICAL"


def test_alert_payload_carries_triage_context():
    alert = {
        "rule": {
            "id": "R002",
            "name": "Successful Compromise Following Brute Force",
            "mitre_attack": "T1078",
            "base_risk": 80,
        },
        "ip": "203.0.113.5",
        "event_ts": 1784887200.0,
        "targets": ["admin"],
        "evidence": ['{"raw": "line"}'],
    }

    payload = build_alert_payload(alert)

    assert payload["rule_id"] == "R002"
    assert payload["severity"] == "CRITICAL"
    assert payload["mitre_attack"] == "T1078"
    assert payload["risk_score"] == 100
    assert payload["evidence"] == ['{"raw": "line"}']
    assert payload["detected_event_time"] == "2026-07-24T10:00:00Z"
    assert payload["alert_id"].startswith("ALERT-R002-")


@pytest.fixture
def factory(monkeypatch):
    import src.config
    import src.factory

    def _reload(**env):
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        importlib.reload(src.config)
        module = importlib.reload(src.factory)
        return module

    yield _reload
    importlib.reload(src.config)
    importlib.reload(src.factory)


def test_factory_defaults_to_local_backends(factory):
    module = factory()
    assert type(module.get_state()).__name__ == "MemoryState"
    assert type(module.get_parser()).__name__ == "MockParser"


def test_factory_selects_cloudtrail_parser(factory):
    module = factory(SIEM_PARSER_TYPE="cloudtrail")
    assert type(module.get_parser()).__name__ == "CloudTrailParser"


def test_factory_rejects_unknown_backend(factory):
    module = factory(SIEM_SOURCE_TYPE="carrier-pigeon")
    with pytest.raises(ValueError, match="carrier-pigeon"):
        module.get_source()


def test_factory_rejects_port_collision(factory):
    """Webhook listener and metrics endpoint cannot share a port."""
    module = factory(SIEM_SOURCE_TYPE="webhook", SIEM_WEBHOOK_LISTEN_PORT="9999", SIEM_METRICS_PORT="9999")
    with pytest.raises(ValueError, match="cannot share a port"):
        module.get_source()
