import json
import time
import os
from collections import defaultdict
from datetime import datetime
from prometheus_client import start_http_server, Counter, Gauge

# Prometheus Metrics
LOGS_PROCESSED = Counter('siem_logs_processed_total', 'Total logs parsed by the SIEM')
ALERTS_GENERATED = Counter('siem_alerts_generated_total', 'Total alerts generated', ['severity'])
ACTIVE_THREATS = Gauge('siem_active_tracked_ips', 'Number of IPs currently being tracked for suspicious activity')

LOG_FILE = "logs/auth.log"
ALERT_DIR = "alerts/"

# Stateful memory for our "SIEM" rule
failed_logins = defaultdict(list)
THRESHOLD = 3 # Generate alert if > 3 failed logins from the same IP
TIME_WINDOW = 30 # Time window in seconds

def process_log_entry(entry):
    """Parses a log line and applies detection logic."""
    try:
        log = json.loads(entry)
        LOGS_PROCESSED.inc()
    except json.JSONDecodeError:
        return

    # Detection Rule 1: High frequency of failed logins (Brute Force Simulation)
    if log.get("event_type") == "authentication" and log.get("status") == "failed":
        ip = log.get("source_ip")
        user = log.get("user")
        ts_str = log.get("timestamp")
        
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00')).timestamp()
        except ValueError:
            ts = time.time()
            
        failed_logins[ip].append((ts, user))
        
        # Clean up old entries outside the sliding time window
        failed_logins[ip] = [(t, u) for t, u in failed_logins[ip] if ts - t <= TIME_WINDOW]
        
        # Update Gauge metric for currently tracked IPs that have > 0 active attempts
        tracked_ips_count = len([ip for ip, attempts in failed_logins.items() if len(attempts) > 0])
        ACTIVE_THREATS.set(tracked_ips_count)
        
        # Check if the threshold is breached
        if len(failed_logins[ip]) > THRESHOLD:
            generate_alert(ip, failed_logins[ip])
            failed_logins[ip] = []
            # Reset active threats gauge after alert fires and state is cleared
            ACTIVE_THREATS.set(len([ip for ip, attempts in failed_logins.items() if len(attempts) > 0]))

def generate_alert(ip, attempts):
    """Writes an alert artifact and updates metrics."""
    alert_id = f"ALERT-BRUTEFORCE-{int(time.time())}"
    users_targeted = list(set([u for t, u in attempts]))
    
    # Expose metric to Prometheus
    ALERTS_GENERATED.labels(severity="HIGH").inc()
    
    alert_data = {
        "alert_id": alert_id,
        "severity": "HIGH",
        "title": "Potential Brute Force Attack Detected",
        "description": f"Detected {len(attempts)} failed login attempts from IP {ip} within {TIME_WINDOW} seconds.",
        "source_ip": ip,
        "targeted_users": users_targeted,
        "timestamp": datetime.utcnow().isoformat() + "Z",
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

def tail_file(filepath):
    if not os.path.exists(filepath):
        open(filepath, 'a').close()
        
    with open(filepath, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

if __name__ == "__main__":
    if not os.path.exists(ALERT_DIR):
        os.makedirs(ALERT_DIR)
        
    # Start up the server to expose the metrics on port 8002
    print("Starting Prometheus metrics endpoint on port 8002...")
    start_http_server(8002)
        
    print(f"[*] Starting SIEM Engine...")
    print(f"[*] Monitoring {LOG_FILE} for suspicious activity...")
    print(f"[*] Rule: > {THRESHOLD} failed logins within {TIME_WINDOW}s from a single IP.\n")
    
    for line in tail_file(LOG_FILE):
        process_log_entry(line)
