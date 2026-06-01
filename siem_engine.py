import yaml
import time
import uuid
import signal
import sys
from datetime import datetime, timezone
from prometheus_client import start_http_server, Counter, Gauge, Histogram

from src.config import Config
from src.sources.file_source import FileSource
from src.sinks.file_sink import FileSink
from src.state.memory import MemoryState
from src.parsers.mock import MockParser

# Metrics
LOGS_PROCESSED = Counter('siem_logs_processed_total', 'Total logs parsed by the SIEM')
LOGS_MALFORMED = Counter('siem_logs_malformed_total', 'Total logs that failed JSON parsing')
ALERTS_GENERATED = Counter('siem_alerts_generated_total', 'Total alerts generated', ['severity', 'rule_id'])
ACTIVE_THREATS = Gauge('siem_active_tracked_ips', 'Number of IPs currently being tracked')
MTTD = Histogram('siem_mttd_seconds', 'Mean Time To Detect (Detection Latency)', buckets=(5, 30, 60, 300, 900, 3600, 7200, float("inf")))
EVENTS_REJECTED = Counter('siem_events_rejected_total', 'Events rejected from processing', ['reason'])
EVENTS_DROPPED = Counter('siem_events_dropped_total', 'Events dropped or modified during processing', ['reason'])

running = True
def handle_sigterm(signum, frame):
    global running
    print("\\nShutting down SIEM Engine...")
    running = False
signal.signal(signal.SIGINT, handle_sigterm)
signal.signal(signal.SIGTERM, handle_sigterm)

def enrich_context(ip: str, users: list):
    """Mocks external API enrichment for GeoIP and Asset Inventory."""
    country = "RU" if ip.startswith("100.") or ip.startswith("9.") else "US"
    critical_accounts = {"admin", "root", "ceo", "svc_db", "administrator"}
    critical_targets = [u for u in users if u in critical_accounts]
    
    return {
        "geoip": {"ip": ip, "country": country},
        "asset_context": {
            "critical_targets_hit": len(critical_targets),
            "critical_users": critical_targets
        }
    }

def calculate_dynamic_risk(base_risk: int, enrichment: dict) -> tuple:
    """Calculates risk dynamically based on enrichment and assigns severity."""
    score = base_risk
    if enrichment["geoip"]["country"] != "US":
        score += 20
    score += (10 * enrichment["asset_context"]["critical_targets_hit"])
    score = min(100, score)
    
    if score >= 80: sev = "CRITICAL"
    elif score >= 60: sev = "HIGH"
    elif score >= 40: sev = "MEDIUM"
    else: sev = "LOW"
    return score, sev

class DetectionEngine:
    def __init__(self, rules_file, state_backend):
        with open(rules_file, 'r') as f:
            config = yaml.safe_load(f)
            self.rules = {r['id']: r for r in config.get('rules', [])}
            self.tuning = config.get('global_tuning', {})
            
        self.max_time_window = max([r.get('time_window', 0) for r in self.rules.values()]) if self.rules else 60
        self.max_suppression_window = max([r.get('suppression_window', 0) for r in self.rules.values()]) if self.rules else 120
        
        self.allowlisted_ips = set(self.tuning.get("allowlisted_ips", []))
        self.allowlisted_users = set(self.tuning.get("allowlisted_users", []))
        self.state = state_backend
        
    def evaluate(self, ocsf_event):
        if not ocsf_event:
            return []
            
        ip = ocsf_event["src_endpoint"]["ip"]
        user = ocsf_event["user"]["name"]
        
        # Tuning: Ignore allowlisted entities immediately
        if ip in self.allowlisted_ips or user in self.allowlisted_users:
            return []
            
        ts_str = ocsf_event["time"]
        try:
            ts = datetime.fromisoformat(str(ts_str).replace('Z', '+00:00')).timestamp()
        except ValueError:
            return []
            
        if ts - time.time() > 3600:
            EVENTS_REJECTED.labels(reason="clock_skew").inc()
            return []
            
        event_id = ocsf_event["metadata"].get("event_id")
        if not event_id:
            EVENTS_DROPPED.labels(reason="missing_id").inc()
            event_id = str(hash(ocsf_event.get("raw_data", "") + str(ts)))
            
        if self.state.is_duplicate(event_id):
            return []
            
        status = ocsf_event["status"]
        
        self.state.update_watermark(ts)
        event_tuple = (ts, user, event_id, ocsf_event["raw_data"])
        self.state.add_event(ip, status, event_tuple)
        
        alerts_to_fire = []
        watermark = self.state.get_watermark()
        
        for rule_id, rule in self.rules.items():
            rule_type = rule.get("type", "threshold")
            
            if rule_type == "threshold":
                fails = self.state.get_events(ip, "Failure", rule["time_window"])
                if len(fails) >= rule["threshold"]:
                    if self.state.check_and_set_cooldown(ip, rule_id, rule["suppression_window"]):
                        targets = list(set([x[1] for x in fails]))
                        alerts_to_fire.append({
                            "rule": rule, "ip": ip, "event_ts": watermark,
                            "targets": targets,
                            "evidence": [x[3] for x in fails]
                        })
                        
            elif rule_type == "sequence":
                if status == "Success":
                    fails = self.state.get_events(ip, "Failure", rule["time_window"])
                    targeted_users = set([x[1] for x in fails])
                    
                    if len(fails) >= rule["threshold"] and user in targeted_users:
                        if self.state.check_and_set_cooldown(ip, rule_id, rule["suppression_window"]):
                            alerts_to_fire.append({
                                "rule": rule, "ip": ip, "event_ts": watermark,
                                "targets": list(targeted_users) + [user],
                                "evidence": [x[3] for x in fails] + [ocsf_event["raw_data"]]
                            })
                            
            elif rule_type == "spray":
                fails = self.state.get_events(ip, "Failure", rule["time_window"])
                targeted_users = set([x[1] for x in fails])
                
                if len(targeted_users) >= rule["unique_targets"]:
                    if self.state.check_and_set_cooldown(ip, rule_id, rule["suppression_window"]):
                        alerts_to_fire.append({
                            "rule": rule, "ip": ip, "event_ts": watermark,
                            "targets": list(targeted_users),
                            "evidence": [x[3] for x in fails]
                        })
                            
        return alerts_to_fire
        
    def sweep(self):
        self.state.sweep(self.max_time_window, self.max_suppression_window)
        ACTIVE_THREATS.set(self.state.get_active_count())

def main():
    print(f"Starting Prometheus endpoint on port {Config.METRICS_PORT}...")
    start_http_server(Config.METRICS_PORT)
    
    state_backend = MemoryState()
    source = FileSource(Config.LOG_FILE)
    sink = FileSink(Config.ALERT_DIR)
    parser = MockParser()
    detector = DetectionEngine(Config.RULES_FILE, state_backend)
    
    last_sweep = time.time()
    
    for line in source.read_events():
        if not running:
            source.running = False
            break
            
        now = time.time()
        if now - last_sweep > 10:
            detector.sweep()
            last_sweep = now
            
        if line is None:
            continue
            
        ocsf_event = parser.parse(line)
        if not ocsf_event:
            LOGS_MALFORMED.inc()
            continue
            
        LOGS_PROCESSED.inc()
        alerts = detector.evaluate(ocsf_event)
        
        for alert in alerts:
            # Enrichment & Dynamic Risk Scoring
            enrichment = enrich_context(alert['ip'], alert['targets'])
            risk_score, dynamic_severity = calculate_dynamic_risk(alert['rule'].get('base_risk', 40), enrichment)
            
            ALERTS_GENERATED.labels(severity=dynamic_severity, rule_id=alert['rule']['id']).inc()
            
            wall_clock = time.time()
            mttd_val = max(0, wall_clock - alert['event_ts'])
            MTTD.observe(mttd_val)
            
            alert_id = f"ALERT-{alert['rule']['id']}-{uuid.uuid4()}"
            alert_payload = {
                "alert_id": alert_id,
                "rule_id": alert['rule']['id'],
                "severity": dynamic_severity,
                "risk_score": risk_score,
                "mitre_attack": alert['rule'].get('mitre_attack', 'Unknown'),
                "title": alert['rule']['name'],
                "source_ip": alert['ip'],
                "targeted_users": alert['targets'],
                "enrichment": enrichment,
                "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "evidence": alert['evidence'],
            }
            sink.write_alert(alert_payload)

if __name__ == "__main__":
    main()
