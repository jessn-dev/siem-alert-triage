"""Deterministic attack simulation.

Drives every rule in rules.yml plus the allowlist path, through whichever
transport the engine is running (webhook by default under docker-compose, file
when you run the engine directly).

    WEBHOOK_URL=http://localhost:8002 python3 simulate_attack.py
    python3 simulate_attack.py            # writes logs/auth.log instead
"""

import json
import time
import uuid
from datetime import datetime, timezone

from src.emit import Emitter

emitter = Emitter()


def emit(ip, user, status):
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "authentication",
        "status": status,
        "source_ip": ip,
        "user": user,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    emitter.send(json.dumps(event))
    print(f"    injected  ip={ip:<16} user={user:<14} status={status}")
    time.sleep(0.05)


print(f"=== SIEM Attack Simulation ({emitter.mode} -> {emitter.target()}) ===")

print("\n[1] R001 Brute Force - 6 failures, one IP, one account")
print("    expect: HIGH (base 40 + 20 high-risk geo + 10 critical account)")
for _ in range(6):
    emit("203.0.113.5", "admin", "failed")

time.sleep(1)

print("\n[2] R002 Compromise - 3 failures then a success on the same account")
print("    expect: CRITICAL (base 80, capped at 100)")
for _ in range(3):
    emit("100.20.30.40", "root", "failed")
emit("100.20.30.40", "root", "success")

time.sleep(1)

print("\n[3] R002 negative - success on a *different* account from the same IP")
print("    expect: no compromise alert (NAT gateway false-positive guard)")
for _ in range(3):
    emit("192.0.2.77", "alice", "failed")
emit("192.0.2.77", "unrelated_user", "success")

time.sleep(1)

print("\n[4] R003 Password Spray - 1 IP across 4 unique accounts")
print("    expect: CRITICAL (base 60 + 20 high-risk geo)")
for user in ["ceo", "hr_manager", "devops_lead", "finance_admin"]:
    emit("198.51.100.99", user, "failed")

time.sleep(1)

print("\n[5] Internal traffic - same volume, from the office LAN")
print("    expect: MEDIUM, not HIGH (identical attack, lower risk context)")
for _ in range(6):
    emit("192.168.1.50", "testuser", "failed")

time.sleep(1)

print("\n[6] Allowlisted scanner - should be ignored entirely")
for _ in range(6):
    emit("10.0.0.254", "admin", "failed")

emitter.close()
print("\n[+] Simulation complete. Check alerts/, the webhook receiver, or Grafana.")
