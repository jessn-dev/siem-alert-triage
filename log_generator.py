import json
import time
import random
import os
import signal
import sys
from datetime import datetime, timezone
from prometheus_client import start_http_server, Counter

# Metrics
LOGS_GENERATED = Counter('mock_logs_generated_total', 'Total number of logs generated', ['status', 'event_type'])
BRUTE_FORCE_SIMULATIONS = Counter('mock_bruteforce_simulations_total', 'Number of brute force events simulated')

USERS = ["admin", "alice", "bob", "testuser", "service_account"]
IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.50", "203.0.113.5", "198.51.100.22"]
LOG_FILE = "logs/auth.log"
MAX_LOG_SIZE = 5 * 1024 * 1024 # 5 MB

running = True

def handle_sigterm(signum, frame):
    global running
    print("\nReceived SIGTERM/SIGINT. Shutting down log generator gracefully...")
    running = False

signal.signal(signal.SIGINT, handle_sigterm)
signal.signal(signal.SIGTERM, handle_sigterm)

def generate_log():
    # Fix: Use timezone.utc instead of deprecated utcnow
    timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    user = random.choice(USERS)
    ip = random.choice(IPS)
    
    if random.random() < 0.20:
        user = "admin"
        ip = "203.0.113.5"
        status = "failed"
        BRUTE_FORCE_SIMULATIONS.inc()
    else:
        status = "success" if random.random() < 0.80 else "failed"

    LOGS_GENERATED.labels(status=status, event_type='authentication').inc()

    log_entry = {
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
    
    print(f"Generating simulated auth logs into {LOG_FILE}... (Press Ctrl+C to stop)")
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    while running:
        # Fix: Prevent disk fill by simulating log rotation
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
            print("Log file reached 5MB limit. Truncating to simulate log rotation...")
            open(LOG_FILE, 'w').close()
            
        with open(LOG_FILE, "a") as f:
            for _ in range(10):
                if not running:
                    break
                f.write(generate_log() + "\n")
                f.flush()
                time.sleep(random.uniform(0.1, 1.5))
                
    print("Log generator exited.")
    sys.exit(0)
