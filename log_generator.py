import json
import random
import signal
import sys
import time
import uuid
from datetime import datetime, timezone

from prometheus_client import Counter, start_http_server

from src.config import Config
from src.emit import Emitter

# Metrics
LOGS_GENERATED = Counter('mock_logs_generated_total', 'Total number of logs generated', ['status', 'event_type'])
BRUTE_FORCE_SIMULATIONS = Counter('mock_bruteforce_simulations_total', 'Number of brute force events simulated')
COMPROMISE_SIMULATIONS = Counter('mock_compromise_simulations_total', 'Number of successful compromises simulated')
# Delivery failures are counted, not just logged: a producer that cannot reach
# the engine is a detection outage, and it must be visible on a dashboard.
SEND_FAILURES = Counter('mock_logs_send_failed_total', 'Log deliveries the generator could not complete', ['reason'])

USERS = ["admin", "alice", "bob", "testuser", "service_account"]
IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.50", "203.0.113.5", "198.51.100.22"]
ATTACKER_IP = "203.0.113.5"

running = True
brute_force_active = 0
compromise_next = False


def handle_sigterm(signum, frame):
    global running
    print("\nShutting down log generator...")
    running = False


signal.signal(signal.SIGINT, handle_sigterm)
signal.signal(signal.SIGTERM, handle_sigterm)


def generate_log():
    global brute_force_active, compromise_next

    timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    user = random.choice(USERS)
    ip = random.choice(IPS)
    status = "success" if random.random() < 0.80 else "failed"

    # Brute force burst, then the successful login that follows it.
    if brute_force_active > 0:
        user, ip, status = "admin", ATTACKER_IP, "failed"
        brute_force_active -= 1
        BRUTE_FORCE_SIMULATIONS.inc()
        if brute_force_active == 0:
            compromise_next = True
    elif compromise_next:
        user, ip, status = "admin", ATTACKER_IP, "success"
        compromise_next = False
        COMPROMISE_SIMULATIONS.inc()
    elif random.random() < 0.05:
        brute_force_active = 6

    LOGS_GENERATED.labels(status=status, event_type='authentication').inc()

    return json.dumps({
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "event_type": "authentication",
        "user": user,
        "source_ip": ip,
        "status": status,
        "message": f"User {user} authentication {status} from {ip}",
    })


if __name__ == "__main__":
    start_http_server(Config.GENERATOR_METRICS_PORT)
    print(f"Metrics endpoint on port {Config.GENERATOR_METRICS_PORT}")

    emitter = Emitter(on_failure=lambda reason: SEND_FAILURES.labels(reason=reason).inc())
    print(f"Generating auth logs via {emitter.mode} -> {emitter.target()}")

    while running:
        emitter.send(generate_log())
        time.sleep(random.uniform(0.1, 0.5))

    emitter.close()
    print("Log generator exited.")
    sys.exit(0)
