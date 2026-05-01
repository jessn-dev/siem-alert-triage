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
ALERTS_GENERATED = Counter('siem_alerts_generated_total', 'Total alerts generated', ['severity'])
ACTIVE_THREATS = Gauge('siem_active_tracked_ips', 'Number of IPs currently being tracked')
MTTD = Histogram('siem_mttd_seconds', 'Mean Time To Detect (Detection Latency)')

running = True
def handle_sigterm(signum, frame):
    global running
    print("\nShutting down SIEM Engine...")
    running = False
signal.signal(signal.SIGINT, handle_sigterm)
signal.signal(signal.SIGTERM, handle_sigterm)

class DetectionEngine:
    def __init__(self, rules_file, state_backend):
        with open(rules_file, 'r') as f:
            self.rules = {r['id']: r for r in yaml.safe_load(f)['rules']}
        self.state = state_backend
        
    def evaluate(self, ocsf_event):
        if not ocsf_event:
            return []
            
        event_id = ocsf_event["metadata"]["event_id"]
        if not event_id or self.state.is_duplicate(event_id):
            return []
            
        ip = ocsf_event["src_endpoint"]["ip"]
        user = ocsf_event["user"]["name"]
        ts_str = ocsf_event["time"]
        status = ocsf_event["status"]
        
        try:
            ts = datetime.fromisoformat(str(ts_str).replace('Z', '+00:00')).timestamp()
        except ValueError:
            return []
            
        self.state.update_watermark(ts)
        event_tuple = (ts, user, event_id, ocsf_event["raw_data"])
        self.state.add_event(ip, status, event_tuple)
        
        alerts_to_fire = []
        watermark = self.state.get_watermark()
        
        r1 = self.rules.get("R001")
        if r1:
            fails = self.state.get_events(ip, "Failure", r1["time_window"])
            if len(fails) >= r1["threshold"]:
                if self.state.check_and_set_cooldown(ip, "R001", r1["suppression_window"]):
                    alerts_to_fire.append({
                        "rule": r1, "ip": ip, "event_ts": watermark,
                        "targets": list(set([x[1] for x in fails])),
                        "evidence": [x[3] for x in fails]
                    })
                    
        r2 = self.rules.get("R002")
        if r2 and status == "Success":
            fails = self.state.get_events(ip, "Failure", r2["time_window"])
            if len(fails) >= r2["threshold"]:
                if self.state.check_and_set_cooldown(ip, "R002", r2["suppression_window"]):
                    alerts_to_fire.append({
                        "rule": r2, "ip": ip, "event_ts": watermark,
                        "targets": list(set([x[1] for x in fails] + [user])),
                        "evidence": [x[3] for x in fails] + [ocsf_event["raw_data"]]
                    })
                    
        return alerts_to_fire
        
    def sweep(self):
        self.state.sweep(60, 120)
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
            
        if line is not None:
            ocsf_event = parser.parse(line)
            if not ocsf_event:
                LOGS_MALFORMED.inc()
                continue
                
            LOGS_PROCESSED.inc()
            alerts = detector.evaluate(ocsf_event)
            
            for alert in alerts:
                ALERTS_GENERATED.labels(severity=alert['rule']['severity']).inc()
                
                wall_clock = time.time()
                mttd_val = max(0, wall_clock - alert['event_ts'])
                MTTD.observe(mttd_val)
                
                alert_id = f"ALERT-{alert['rule']['id']}-{uuid.uuid4()}"
                alert_payload = {
                    "alert_id": alert_id,
                    "rule_id": alert['rule']['id'],
                    "severity": alert['rule']['severity'],
                    "mitre_attack": alert['rule'].get('mitre_attack', 'Unknown'),
                    "title": alert['rule']['name'],
                    "source_ip": alert['ip'],
                    "targeted_users": alert['targets'],
                    "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    "evidence": alert['evidence'],
                }
                sink.write_alert(alert_payload)
                
        now = time.time()
        if now - last_sweep > 10:
            detector.sweep()
            last_sweep = now

if __name__ == "__main__":
    main()
