import json
import time
import random
from datetime import datetime
from prometheus_client import start_http_server, Counter

# Prometheus Metrics
LOGS_GENERATED = Counter('mock_logs_generated_total', 'Total number of logs generated', ['status', 'event_type'])
BRUTE_FORCE_SIMULATIONS = Counter('mock_bruteforce_simulations_total', 'Number of brute force events simulated')

USERS = ["admin", "alice", "bob", "testuser", "service_account"]
IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.50", "203.0.113.5", "198.51.100.22"]

def generate_log():
    timestamp = datetime.utcnow().isoformat() + "Z"
    user = random.choice(USERS)
    ip = random.choice(IPS)
    
    # Introduce some malicious behavior: targeted brute force simulation
    # 20% of the time, force a failed login on the admin account from an external IP
    if random.random() < 0.20:
        user = "admin"
        ip = "203.0.113.5"
        status = "failed"
        BRUTE_FORCE_SIMULATIONS.inc()
    else:
        # Otherwise, 80% success rate for normal traffic
        status = "success" if random.random() < 0.80 else "failed"

    # Expose metric to Prometheus
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
    # Start up the server to expose the metrics on port 8001
    print("Starting Prometheus metrics endpoint on port 8001...")
    start_http_server(8001)
    
    print("Generating simulated auth logs into logs/auth.log... (Press Ctrl+C to stop)")
    with open("logs/auth.log", "a") as f:
        while True:
            log_line = generate_log()
            f.write(log_line + "\n")
            f.flush()
            # Generate logs at a random interval between 0.1 and 1.5 seconds
            time.sleep(random.uniform(0.1, 1.5))
