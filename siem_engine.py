import json
import time
import os
import uuid
import signal
import sys
from collections import defaultdict
from datetime import datetime, timezone
from prometheus_client import start_http_server, Counter, Gauge

LOG_FILE = "logs/auth.log"
ALERT_DIR = "alerts/"
running = True

# Metrics
LOGS_PROCESSED = Counter('siem_logs_processed_total', 'Total logs parsed by the SIEM')
LOGS_MALFORMED = Counter('siem_logs_malformed_total', 'Total logs that failed JSON parsing') # Fix: Added parsing metric
ALERTS_GENERATED = Counter('siem_alerts_generated_total', 'Total alerts generated', ['severity'])
ACTIVE_THREATS = Gauge('siem_active_tracked_ips', 'Number of IPs currently being tracked')

def handle_sigterm(signum, frame):
    global running
    print("\nReceived SIGTERM/SIGINT. Initiating graceful shutdown of SIEM Engine...")
    running = False

# Fix: Added SIGTERM/SIGINT handlers for state preservation/graceful exit
signal.signal(signal.SIGINT, handle_sigterm)
signal.signal(signal.SIGTERM, handle_sigterm)

class BruteForceDetector:
    def __init__(self, threshold=3, time_window=30, suppression_window=60):
        self.threshold = threshold
        self.time_window = time_window
        self.suppression_window = suppression_window
        self.failed_logins = defaultdict(list)
        self.last_alerted = {} # Track last alert time for cooldown
    
    def evaluate(self, log_entry):
        if not log_entry:
            return None
            
        if log_entry.get("event_type") == "authentication" and log_entry.get("status") == "failed":
            ip = log_entry.get("source_ip")
            user = log_entry.get("user")
            ts_str = log_entry.get("timestamp")
            
            if not ip or not user or not ts_str:
                return None
                
            try:
                # Fix: Defensive casting to str to prevent uncaught AttributeError if somehow not a string
                ts = datetime.fromisoformat(str(ts_str).replace('Z', '+00:00')).timestamp()
            except ValueError:
                return None
                
            self.failed_logins[ip].append((ts, user))
            
            # Local sweep for this specific IP
            self.failed_logins[ip] = [(t, u) for t, u in self.failed_logins[ip] if ts - t <= self.time_window]
            
            if len(self.failed_logins[ip]) > self.threshold:
                # Fix: Implement alert suppression/cooldown instead of state-wiping
                last_alert = self.last_alerted.get(ip, 0)
                if ts - last_alert > self.suppression_window:
                    targets = list(set([u for t, u in self.failed_logins[ip]]))
                    self.last_alerted[ip] = ts
                    return targets
                
        return None
        
    def sweep_global_state(self, current_ts):
        """Fix: Global sweep to prevent unbounded memory growth and stale active threat counts."""
        ips = list(self.failed_logins.keys())
        for ip in ips:
            # Keep attempts strictly within the time window
            valid_attempts = [(t, u) for t, u in self.failed_logins[ip] if current_ts - t <= self.time_window]
            self.failed_logins[ip] = valid_attempts
            
            # If IP has no active attempts and is past cooldown, delete entirely from memory
            if not valid_attempts:
                last_alert = self.last_alerted.get(ip, 0)
                if current_ts - last_alert > self.suppression_window:
                    del self.failed_logins[ip]
                    if ip in self.last_alerted:
                        del self.last_alerted[ip]
        
    def get_active_threat_count(self):
        return len([ip for ip, attempts in self.failed_logins.items() if len(attempts) > 0])


def parse_log(log_line):
    try:
        return json.loads(log_line)
    except (json.JSONDecodeError, TypeError):
        # Fix: Now increments the malformed logs metric to avoid blind spots
        LOGS_MALFORMED.inc()
        return None

def write_alert(ip, targets):
    # Fix: Replaced time.time() with uuid4 to prevent collision overwrites
    alert_id = f"ALERT-BRUTEFORCE-{uuid.uuid4()}"
    alert_data = {
        "alert_id": alert_id,
        "severity": "HIGH",
        "title": "Potential Brute Force Attack Detected",
        "source_ip": ip,
        "targeted_users": targets,
        # Fix: Replaced deprecated utcnow
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "triage_steps": [
            "1. Verify if the source IP is known or trusted.",
            "2. Check if the targeted accounts were successfully compromised after the alert.",
            "3. If malicious, block the IP at the firewall level."
        ]
    }
    
    alert_filepath = os.path.join(ALERT_DIR, f"{alert_id}.json")
    with open(alert_filepath, "w") as f:
        json.dump(alert_data, f, indent=4)
        
    print(f"[!] HIGH SEVERITY ALERT GENERATED: {alert_id} from {ip}")


def robust_tail(filepath, backfill=False):
    """Fix: Tolerates log rotation/truncation and can backfill."""
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
                    # Detect rotation via inode change or truncation via size shrink
                    if stat.st_ino != last_inode or stat.st_size < last_size:
                        print(f"[*] Log rotation detected for {filepath}, reopening...")
                        break
                    last_size = stat.st_size
                except FileNotFoundError:
                    break
                    
                time.sleep(0.5)
                continue
            yield line


if __name__ == "__main__":
    if not os.path.exists(ALERT_DIR):
        os.makedirs(ALERT_DIR)
        
    print("Starting Prometheus metrics endpoint on port 8002...")
    start_http_server(8002)
    
    detector = BruteForceDetector(threshold=3, time_window=30, suppression_window=60)
    
    print(f"[*] Starting SIEM Engine...")
    print(f"[*] Monitoring {LOG_FILE} for suspicious activity...\n")
    
    last_sweep = time.time()
    
    while running:
        for line in robust_tail(LOG_FILE, backfill=False):
            if not running:
                break
                
            log_dict = parse_log(line)
            if log_dict:
                LOGS_PROCESSED.inc()
                ip = log_dict.get("source_ip")
                targets = detector.evaluate(log_dict)
                
                if targets:
                    ALERTS_GENERATED.labels(severity="HIGH").inc()
                    write_alert(ip, targets)
            
            # Global cleanup every 10 seconds
            now = time.time()
            if now - last_sweep > 10:
                detector.sweep_global_state(now)
                ACTIVE_THREATS.set(detector.get_active_threat_count())
                last_sweep = now
                
        if running:
            # Short sleep before inner while loop resumes from robust_tail break
            time.sleep(1) 
            
    print("SIEM Engine exited gracefully.")
    sys.exit(0)
