import json
import time
import uuid
import os
from datetime import datetime, timezone

LOG_FILE = "logs/auth.log"

def write_log(ip, user, status):
    # Ensure logs directory exists
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "authentication",
        "status": status,
        "source_ip": ip,
        "user": user,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }
    
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    print(f"[*] Injected log: IP={ip} USER={user} STATUS={status}")
    time.sleep(0.1) # slight delay to simulate network

print("=== SIEM Attack Simulation ===")

print("\n[1] Simulating Brute Force (R001) - 5 failures from one IP...")
for i in range(5):
    write_log("203.0.113.5", "admin", "failed")

time.sleep(2)

print("\n[2] Simulating Successful Compromise (R002) - 3 failures followed by 1 success...")
# We use a foreign IP to trigger a higher dynamic risk score
foreign_ip = "100.20.30.40" 
for i in range(3):
    write_log(foreign_ip, "root", "failed")
# The successful compromise
write_log(foreign_ip, "root", "success")

time.sleep(2)

print("\n[3] Simulating Password Spray Attack (R003) - 1 IP hitting 4 unique accounts...")
spray_ip = "198.51.100.99"
targets = ["ceo", "hr_manager", "devops_lead", "finance_admin"]
for user in targets:
    write_log(spray_ip, user, "failed")

print("\n[4] Simulating Allowlisted IP (Should be ignored)...")
write_log("10.0.0.254", "admin", "failed")
write_log("10.0.0.254", "admin", "failed")
write_log("10.0.0.254", "admin", "failed")

print("\n[+] Attack simulation complete! Check the /alerts directory or Grafana dashboard.")
