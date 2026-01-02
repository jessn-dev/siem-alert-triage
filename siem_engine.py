import json
import time
import os
import uuid
import signal
import sys
import yaml
from collections import defaultdict
from datetime import datetime, timezone
from prometheus_client import start_http_server, Counter, Gauge, Histogram

LOG_FILE = "logs/auth.log"
ALERT_DIR = "alerts/"
RULES_FILE = "rules.yml"
running = True

# Metrics
LOGS_PROCESSED = Counter('siem_logs_processed_total', 'Total logs parsed by the SIEM')
LOGS_MALFORMED = Counter('siem_logs_malformed_total', 'Total logs that failed JSON parsing')
ALERTS_GENERATED = Counter('siem_alerts_generated_total', 'Total alerts generated', ['severity'])
ACTIVE_THREATS = Gauge('siem_active_tracked_ips', 'Number of IPs currently being tracked')
MTTD = Histogram('siem_mttd_seconds', 'Mean Time To Detect (Detection Latency)')

def handle_sigterm(signum, frame):
    global running
    print("\nReceived SIGTERM/SIGINT. Initiating graceful shutdown of SIEM Engine...")
    running = False

signal.signal(signal.SIGINT, handle_sigterm)
signal.signal(signal.SIGTERM, handle_sigterm)

class DetectionEngine:
    def __init__(self, rules_file):
        with open(rules_file, 'r') as f:
            config = yaml.safe_load(f)
        self.rules = {r['id']: r for r in config['rules']}
        
        # state[ip]["failed"] = [(ts, user, event_id, raw_log), ...]
        self.state = defaultdict(lambda: {"failed": [], "success": []})
        self.last_alerted = {} # ip -> { rule_id: ts }
        self.watermark = 0.0 # Fix 1: Single clock domain (Max event time seen)
        self.seen_events = set() # Fix 2: Idempotency deduplication
    
    def evaluate(self, log_entry):
        if not log_entry:
            return None
            
        event_id = log_entry.get("event_id")
        if not event_id or event_id in self.seen_events:
            return None # Ignore duplicates
            
        self.seen_events.add(event_id)
        if len(self.seen_events) > 10000:
            # Naive cleanup for simulation memory management
            self.seen_events.clear()
            
        ip = log_entry.get("source_ip")
        user = log_entry.get("user")
        ts_str = log_entry.get("timestamp")
        status = log_entry.get("status")
        
        if not ip or not user or not ts_str or not status:
            return None
            
        try:
            ts = datetime.fromisoformat(str(ts_str).replace('Z', '+00:00')).timestamp()
        except ValueError:
            return None
            
        # Update event-time watermark
        if ts > self.watermark:
            self.watermark = ts
            
        if status == "failed":
            self.state[ip]["failed"].append((ts, user, event_id, log_entry))
        elif status == "success":
            self.state[ip]["success"].append((ts, user, event_id, log_entry))
            
        alerts_to_fire = []
        
        # Rule 1: Brute Force
        r1 = self.rules.get("R001")
        if r1:
            self.state[ip]["failed"] = [x for x in self.state[ip]["failed"] if self.watermark - x[0] <= r1["time_window"]]
            
            if len(self.state[ip]["failed"]) >= r1["threshold"]:
                last_alert = self.last_alerted.get(ip, {}).get("R001", 0)
                if self.watermark - last_alert > r1["suppression_window"]:
                    targets = list(set([x[1] for x in self.state[ip]["failed"]]))
                    evidence = [x[3] for x in self.state[ip]["failed"]]
                    alerts_to_fire.append({
                        "rule": r1,
                        "ip": ip,
                        "targets": targets,
                        "evidence": evidence,
                        "event_ts": self.watermark
                    })
                    if ip not in self.last_alerted: self.last_alerted[ip] = {}
                    self.last_alerted[ip]["R001"] = self.watermark

        # Rule 2: Successful Compromise
        r2 = self.rules.get("R002")
        if r2 and status == "success":
            fails = [x for x in self.state[ip]["failed"] if self.watermark - x[0] <= r2["time_window"]]
            if len(fails) >= r2["threshold"]:
                last_alert = self.last_alerted.get(ip, {}).get("R002", 0)
                if self.watermark - last_alert > r2["suppression_window"]:
                    targets = list(set([x[1] for x in fails] + [user]))
                    evidence = [x[3] for x in fails] + [log_entry]
                    alerts_to_fire.append({
                        "rule": r2,
                        "ip": ip,
                        "targets": targets,
                        "evidence": evidence,
                        "event_ts": self.watermark
                    })
                    if ip not in self.last_alerted: self.last_alerted[ip] = {}
                    self.last_alerted[ip]["R002"] = self.watermark
                    
        return alerts_to_fire
        
    def sweep_global_state(self):
        """Sweeps stale memory using the event-time watermark, NOT wall clock."""
        ips = list(self.state.keys())
        for ip in ips:
            # Assume max lookback window across all rules is 60s
            max_window = 60
            valid_fails = [x for x in self.state[ip]["failed"] if self.watermark - x[0] <= max_window]
            valid_success = [x for x in self.state[ip]["success"] if self.watermark - x[0] <= max_window]
            
            self.state[ip]["failed"] = valid_fails
            self.state[ip]["success"] = valid_success
            
            if not valid_fails and not valid_success:
                # Check cooldowns
                safe_to_delete = True
                if ip in self.last_alerted:
                    for rule_id, last_ts in self.last_alerted[ip].items():
                        if self.watermark - last_ts <= 120: # max global suppression
                            safe_to_delete = False
                            break
                if safe_to_delete:
                    del self.state[ip]
                    if ip in self.last_alerted:
                        del self.last_alerted[ip]
        
    def get_active_threat_count(self):
        return len([ip for ip, data in self.state.items() if len(data["failed"]) > 0])


def parse_log(log_line):
    try:
        return json.loads(log_line)
    except (json.JSONDecodeError, TypeError):
        LOGS_MALFORMED.inc()
        return None

def write_alert(alert):
    alert_id = f"ALERT-{alert['rule']['id']}-{uuid.uuid4()}"
    rule = alert['rule']
    
    # Calculate MTTD (Wall clock time - max Event Time)
    wall_clock = time.time()
    mttd_val = wall_clock - alert['event_ts']
    if mttd_val < 0: mttd_val = 0
    MTTD.observe(mttd_val)
    
    alert_data = {
        "alert_id": alert_id,
        "rule_id": rule['id'],
        "severity": rule['severity'],
        "mitre_attack": rule.get('mitre_attack', 'Unknown'),
        "title": rule['name'],
        "source_ip": alert['ip'],
        "targeted_users": alert['targets'],
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "evidence": alert['evidence'],
        "triage_steps": [
            "1. Verify if the source IP is known or trusted.",
            "2. Review the raw evidence payload attached to this alert.",
            "3. Block IP or force password reset if malicious."
        ]
    }
    
    alert_filepath = os.path.join(ALERT_DIR, f"{alert_id}.json")
    with open(alert_filepath, "w") as f:
        json.dump(alert_data, f, indent=4)
        
    print(f"[!] {rule['severity']} ALERT GENERATED: {alert_id} ({rule['name']})")


def robust_tail(filepath, backfill=False):
    """Tails log file. Yields None as a heartbeat when idle."""
    if not os.path.exists(filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        open(filepath, 'a').close()
        
    with open(filepath, "r") as f:
        if not backfill:
            f.seek(0, 2)
            
        last_inode = os.stat(filepath).st_ino
        last_size = os.stat(filepath).st_size
        
        while running:
            line = f.readline()
            if not line:
                try:
                    stat = os.stat(filepath)
                    if stat.st_ino != last_inode or stat.st_size < last_size:
                        print(f"[*] Log rotation detected for {filepath}, reopening...")
                        break
                    last_size = stat.st_size
                except FileNotFoundError:
                    break
                    
                time.sleep(0.5)
                yield None # Fix 3: Heartbeat prevents loop blocking
                continue
            yield line


if __name__ == "__main__":
    if not os.path.exists(ALERT_DIR):
        os.makedirs(ALERT_DIR)
        
    print("Starting Prometheus metrics endpoint on port 8002...")
    start_http_server(8002)
    
    detector = DetectionEngine(RULES_FILE)
    
    print(f"[*] Starting SIEM Engine...")
    print(f"[*] Monitoring {LOG_FILE} for suspicious activity...\n")
    
    last_sweep = time.time()
    
    while running:
        for line in robust_tail(LOG_FILE, backfill=False):
            if not running:
                break
                
            if line is not None:
                log_dict = parse_log(line)
                if log_dict:
                    LOGS_PROCESSED.inc()
                    alerts = detector.evaluate(log_dict)
                    
                    if alerts:
                        for alert in alerts:
                            ALERTS_GENERATED.labels(severity=alert['rule']['severity']).inc()
                            write_alert(alert)
            
            # The loop runs every 0.5s even if idle due to 'yield None'
            now = time.time()
            if now - last_sweep > 10:
                detector.sweep_global_state()
                ACTIVE_THREATS.set(detector.get_active_threat_count())
                last_sweep = now
                
        if running:
            time.sleep(1) 
            
    print("SIEM Engine exited gracefully.")
    sys.exit(0)
