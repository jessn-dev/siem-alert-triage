import json
import time
import random
import os
import signal
import sys
import uuid
from datetime import datetime, timezone
from prometheus_client import start_http_server, Counter

# Metrics
LOGS_GENERATED = Counter('mock_logs_generated_total', 'Total number of logs generated', ['status', 'event_type'])
BRUTE_FORCE_SIMULATIONS = Counter('mock_bruteforce_simulations_total', 'Number of brute force events simulated')
COMPROMISE_SIMULATIONS = Counter('mock_compromise_simulations_total', 'Number of successful compromises simulated')

USERS = ["admin", "alice", "bob", "testuser", "service_account"]
IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.50", "203.0.113.5", "198.51.100.22"]
LOG_FILE = "logs/auth.log"
MAX_LOG_SIZE = 5 * 1024 * 1024 # 5 MB

running = True
brute_force_active = 0
compromise_next = False

def handle_sigterm(signum, frame):
    global running
    print("\nReceived SIGTERM/SIGINT. Shutting down log generator gracefully...")
    running = False

signal.signal(signal.SIGINT, handle_sigterm)
signal.signal(signal.SIGTERM, handle_sigterm)

def generate_log():
    global brute_force_active, compromise_next
    
    timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    user = random.choice(USERS)
    ip = random.choice(IPS)
    status = "success" if random.random() < 0.80 else "failed"
    
    # Simulate advanced attack: Brute force followed by compromise
    if brute_force_active > 0:
        user = "admin"
        ip = "203.0.113.5"
        status = "failed"
        brute_force_active -= 1
        BRUTE_FORCE_SIMULATIONS.inc()
        if brute_force_active == 0:
            compromise_next = True
    elif compromise_next:
        user = "admin"
        ip = "203.0.113.5"
        status = "success"
        compromise_next = False
        COMPROMISE_SIMULATIONS.inc()
    elif random.random() < 0.05: # 5% chance to start a new attack burst
        brute_force_active = 4

    LOGS_GENERATED.labels(status=status, event_type='authentication').inc()

    log_entry = {
        "event_id": str(uuid.uuid4()), # Fix: Add event_id for idempotency deduplication
        "timestamp": timestamp,
        "event_type": "authentication",
        "user": user,
        "source_ip": ip,
        "status": status,
        "message": f"User {user} authentication {status} from {ip}"
    }
    return json.dumps(log_entry)

if __name__ == "__main__":
    print("Starting Prometheus metrics endpoint on port 8001...")
    start_http_server(8001)
    
    webhook_url = os.getenv("WEBHOOK_URL")
    
    if webhook_url:
        import requests
        print(f"Log generator running in webhook mode to {webhook_url}")
        while running:
            log_line = generate_log()
            try:
                requests.post(webhook_url, data=log_line.encode('utf-8'), timeout=1)
                time.sleep(random.uniform(0.1, 0.5))
            except Exception as e:
                print(f"Failed to post to webhook: {e}")
                time.sleep(2)
    else:
        print(f"Log generator started. Writing to {LOG_FILE}...")
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            while running:
                if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
                    print("Log file reached 5MB limit. Truncating to simulate log rotation...")
                    f.truncate(0)
                log_line = generate_log()
                f.write(log_line + "\n")
                f.flush()
                time.sleep(random.uniform(0.1, 0.5))
                
    print("Log generator exited.")
    sys.exit(0)
