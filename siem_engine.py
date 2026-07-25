import signal
import time
import uuid
from datetime import datetime, timezone

import yaml
from prometheus_client import Counter, Gauge, Histogram, start_http_server

from src.config import Config
from src.enrichment import calculate_dynamic_risk, enrich_context

# Metrics
LOGS_PROCESSED = Counter('siem_logs_processed_total', 'Total logs parsed by the SIEM')
LOGS_MALFORMED = Counter('siem_logs_malformed_total', 'Total logs that failed parsing')
ALERTS_GENERATED = Counter('siem_alerts_generated_total', 'Total alerts generated', ['severity', 'rule_id'])
ACTIVE_THREATS = Gauge('siem_active_tracked_ips', 'Number of IPs currently being tracked')
EVENTS_REJECTED = Counter('siem_events_rejected_total', 'Events rejected from processing', ['reason'])
EVENTS_DROPPED = Counter('siem_events_dropped_total', 'Events dropped or degraded during processing', ['reason'])
# Buckets span sub-second (local file tail) through hours (cloud audit log lag).
MTTD = Histogram(
    'siem_mttd_seconds',
    'Detection latency: event time to alert time',
    buckets=(0.1, 0.5, 1, 2, 5, 15, 60, 300, 900, 3600, 7200, float("inf")),
)

running = True


def handle_sigterm(signum, frame):
    global running
    print("\nShutting down SIEM Engine...")
    running = False


signal.signal(signal.SIGINT, handle_sigterm)
signal.signal(signal.SIGTERM, handle_sigterm)


class DetectionEngine:
    """Evaluates OCSF events against rules.yml.

    Rule behaviour is dispatched on the rule's `type`, so a new detection of an
    existing type is a YAML edit with no Python change.
    """

    def __init__(self, rules_file, state_backend, max_clock_skew=None):
        with open(rules_file) as f:
            config = yaml.safe_load(f) or {}

        self.rules = {r['id']: r for r in config.get('rules', [])}
        self.tuning = config.get('global_tuning', {})
        self.allowlisted_ips = set(self.tuning.get("allowlisted_ips", []))
        self.allowlisted_users = set(self.tuning.get("allowlisted_users", []))

        windows = [r.get('time_window', 0) for r in self.rules.values()]
        suppressions = [r.get('suppression_window', 0) for r in self.rules.values()]
        self.max_time_window = max(windows) if windows else 60
        self.max_suppression_window = max(suppressions) if suppressions else 120

        self.state = state_backend
        self.max_clock_skew = (
            Config.MAX_CLOCK_SKEW_SECONDS if max_clock_skew is None else max_clock_skew
        )

        self.handlers = {
            "threshold": self._eval_threshold,
            "sequence": self._eval_sequence,
            "spray": self._eval_spray,
        }

    # -- event intake ----------------------------------------------------
    def _event_timestamp(self, ocsf_event):
        """OCSF `time` is epoch millis; `time_dt` is the ISO original."""
        raw = ocsf_event.get("time")
        if isinstance(raw, (int, float)) and raw > 0:
            return raw / 1000.0
        try:
            iso = str(ocsf_event.get("time_dt")).replace('Z', '+00:00')
            return datetime.fromisoformat(iso).timestamp()
        except (ValueError, TypeError):
            return None

    def evaluate(self, ocsf_event):
        if not ocsf_event:
            return []

        ip = ocsf_event["src_endpoint"]["ip"]
        user = ocsf_event["user"]["name"]

        if ip in self.allowlisted_ips or user in self.allowlisted_users:
            EVENTS_REJECTED.labels(reason="allowlisted").inc()
            return []

        ts = self._event_timestamp(ocsf_event)
        if ts is None:
            EVENTS_REJECTED.labels(reason="unparseable_time").inc()
            return []

        # Per-IP watermarks already contain a skewed host's blast radius to
        # itself. This bound is a second line of defence against timestamps so
        # far in the future they would freeze that IP's own window forever.
        if ts - time.time() > self.max_clock_skew:
            EVENTS_REJECTED.labels(reason="clock_skew").inc()
            return []

        event_id = ocsf_event.get("metadata", {}).get("event_id")
        if not event_id:
            # Synthesize a stable id so sources without one still dedupe, but
            # make the degradation visible rather than silent.
            EVENTS_DROPPED.labels(reason="missing_event_id").inc()
            event_id = f"synth-{hash((ocsf_event.get('raw_data', ''), ts))}"

        if self.state.is_duplicate(event_id):
            EVENTS_REJECTED.labels(reason="duplicate").inc()
            return []

        status = ocsf_event["status"]
        self.state.update_watermark(ip, ts)
        self.state.add_event(ip, status, (ts, user, event_id, ocsf_event["raw_data"]))

        context = {
            "ip": ip,
            "user": user,
            "status": status,
            "watermark": self.state.get_watermark(ip),
        }

        alerts = []
        for rule_id, rule in self.rules.items():
            handler = self.handlers.get(rule.get("type", "threshold"))
            if handler is None:
                EVENTS_DROPPED.labels(reason="unknown_rule_type").inc()
                continue
            alert = handler(rule_id, rule, context)
            if alert:
                alerts.append(alert)
        return alerts

    # -- rule types ------------------------------------------------------
    def _fire(self, rule_id, rule, context, targets, evidence):
        if not self.state.check_and_set_cooldown(context["ip"], rule_id, rule["suppression_window"]):
            return None
        return {
            "rule": rule,
            "ip": context["ip"],
            "event_ts": context["watermark"],
            "targets": targets,
            "evidence": evidence,
        }

    def _eval_threshold(self, rule_id, rule, context):
        """Volume of failures from one IP. Only a failure can advance it."""
        if context["status"] != "Failure":
            return None
        fails = self.state.get_events(context["ip"], "Failure", rule["time_window"])
        if len(fails) < rule["threshold"]:
            return None
        return self._fire(rule_id, rule, context, sorted({x[1] for x in fails}), [x[3] for x in fails])

    def _eval_sequence(self, rule_id, rule, context):
        """Success following a failure burst *against that same account*.

        The account correlation is what keeps shared-egress NAT gateways from
        generating a compromise alert every time anyone logs in successfully.
        """
        if context["status"] != "Success":
            return None
        fails = self.state.get_events(context["ip"], "Failure", rule["time_window"])
        targeted = {x[1] for x in fails}
        if len(fails) < rule["threshold"] or context["user"] not in targeted:
            return None
        successes = self.state.get_events(context["ip"], "Success", rule["time_window"])
        evidence = [x[3] for x in fails] + [x[3] for x in successes if x[1] == context["user"]]
        return self._fire(rule_id, rule, context, sorted(targeted), evidence)

    def _eval_spray(self, rule_id, rule, context):
        """One IP against many accounts. Breadth, not volume."""
        if context["status"] != "Failure":
            return None
        fails = self.state.get_events(context["ip"], "Failure", rule["time_window"])
        targeted = {x[1] for x in fails}
        if len(targeted) < rule["unique_targets"]:
            return None
        return self._fire(rule_id, rule, context, sorted(targeted), [x[3] for x in fails])

    # -- housekeeping ----------------------------------------------------
    def sweep(self):
        self.state.sweep(self.max_time_window, self.max_suppression_window)
        ACTIVE_THREATS.set(self.state.get_active_count())


def build_alert_payload(alert):
    """Detection + enrichment -> the artifact an analyst actually triages."""
    enrichment = enrich_context(alert['ip'], alert['targets'])
    risk_score, severity = calculate_dynamic_risk(alert['rule'].get('base_risk', 40), enrichment)
    rule = alert['rule']

    return {
        "alert_id": f"ALERT-{rule['id']}-{uuid.uuid4()}",
        "rule_id": rule['id'],
        "severity": severity,
        "risk_score": risk_score,
        "mitre_attack": rule.get('mitre_attack', 'Unknown'),
        "title": rule['name'],
        "source_ip": alert['ip'],
        "targeted_users": alert['targets'],
        "enrichment": enrichment,
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "detected_event_time": datetime.fromtimestamp(
            alert['event_ts'], timezone.utc
        ).isoformat().replace('+00:00', 'Z'),
        "evidence": alert['evidence'],
    }


def main():
    from src import factory

    print(f"Starting Prometheus endpoint on port {Config.METRICS_PORT}...")
    start_http_server(Config.METRICS_PORT)

    state_backend = factory.get_state()
    source = factory.get_source()
    sink = factory.get_sink()
    parser = factory.get_parser()
    detector = DetectionEngine(Config.RULES_FILE, state_backend)

    print(f"[*] source={Config.SOURCE_TYPE} sink={Config.SINK_TYPE} "
          f"state={Config.STATE_BACKEND} parser={Config.PARSER_TYPE}")
    print(f"[*] {len(detector.rules)} rules loaded from {Config.RULES_FILE}")

    last_sweep = time.time()

    for line in source.read_events():
        if not running:
            source.running = False
            break

        # Housekeeping runs before any continue, so a stream of unparseable
        # logs can never starve the sweep and leak the window state.
        now = time.time()
        if now - last_sweep > Config.SWEEP_INTERVAL_SECONDS:
            detector.sweep()
            shed = source.drain_dropped()
            if shed:
                EVENTS_DROPPED.labels(reason="queue_full").inc(shed)
            last_sweep = now

        if line is None:
            continue

        ocsf_event = parser.parse(line)
        if not ocsf_event:
            LOGS_MALFORMED.inc()
            continue

        LOGS_PROCESSED.inc()

        for alert in detector.evaluate(ocsf_event):
            payload = build_alert_payload(alert)
            ALERTS_GENERATED.labels(severity=payload['severity'], rule_id=payload['rule_id']).inc()
            MTTD.observe(max(0.0, time.time() - alert['event_ts']))
            sink.write_alert(payload)


if __name__ == "__main__":
    main()
