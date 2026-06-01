# Cloud-Agnostic SIEM Detection & Alerting Pipeline

A modular, containerized Security Information and Event Management (SIEM) pipeline. It normalizes disparate authentication logs into the Open Cybersecurity Schema Framework (OCSF), evaluates them against YAML-based detection rules in real-time, and routes critical events through a Prometheus and Alertmanager stack.

## What is this?
This project is an end-to-end event processing engine. It reads raw logs, translates them to a standardized schema (OCSF Class 3002), tracks state across sliding event-time windows, and triggers actionable alerts. 

The stack includes:
- A stateless Python detection engine.
- Detections-as-code (`rules.yml`) mapped to MITRE ATT&CK techniques.
- Prometheus for metric scraping and deadman-switch monitoring.
- Alertmanager for severity-based webhook routing and alert inhibition.
- Grafana for visual observability and MTTD (Mean Time to Detect) tracking.

## Why build this?
Alert monitoring dictates the actual effectiveness of a security posture. A Security Operations Center (SOC) fails if alerts are noisy or drop silently during infrastructure outages. 

This pipeline solves specific engineering problems inherent to threat detection:
- **Event-time vs. Wall-clock:** Cloud logs lag. This engine uses high-watermark event-time tracking to ensure delayed logs correctly trigger sliding-window thresholds without being prematurely swept from memory.
- **Idempotency:** Cloud queues guarantee at-least-once delivery. The engine deduplicates payloads via `event_id` to prevent false positives from message replays.
- **Self-Monitoring:** If the detection engine crashes, Prometheus catches the missing metrics and Alertmanager fires a "Blind SOC" critical alert.

## Where does this run?
Anywhere. The architecture is cloud-agnostic and follows 12-factor application principles. 
- All components are Dockerized.
- State is abstracted. The current implementation uses memory, but the `BaseState` interface allows dropping in a Redis backend for horizontal scaling across Kubernetes replica sets.
- Configuration is driven entirely by environment variables. There are no hardcoded host paths or local dependencies.

## When should you use this?
Deploy or adapt this architecture when you need vendor-agnostic detection engineering. It allows security teams to:
- Write complex correlation rules (e.g., successful login immediately following a brute-force burst) without relying on proprietary SIEM query languages.
- Prevent vendor lock-in by normalizing logs to OCSF before applying logic.
- Route alerts dynamically based on severity.

## How to adapt it for your environment
The code relies on dependency injection. You can adapt it to any cloud provider by implementing the provided abstract base classes:

1. **New Log Sources:** Write a class inheriting `BaseSource` to pull from AWS Kinesis or GCP Pub/Sub instead of local files.
2. **New Schemas:** Write a class inheriting `BaseParser` to map CloudTrail `ConsoleLogin` or Azure AD `SignInLogs` into the OCSF format. The detection rules will work immediately without modification.
3. **Distributed State:** Write a `RedisState` class inheriting `BaseState` to share sliding-window memory across multiple detection engine pods.

## How to run the local simulation

Start the entire environment (Engine, Generator, Prometheus, Grafana, Alertmanager, and Webhook Receiver):
```bash
docker-compose up -d --build
```

Watch the mock webhook receiver for triggered alerts:
```bash
docker logs -f siem_webhook_receiver
```

Open the observability dashboard:
1. Navigate to `http://localhost:3000`
2. Login with `admin` / `admin`
3. View the **SIEM Observability Overview** dashboard to watch real-time alert volumes and parsing metrics.

To test the deadman switch (Blind SOC fallback):
```bash
docker stop siem_engine
```
Within 15 seconds, the `SIEMComponentDown` alert will trigger and route to the webhook receiver.

## Architectural Pitfalls & Lessons Learned

Building a SIEM that survives the realities of cloud-native log ingestion, network latency, and distributed queues requires defensive engineering. Here are the core problems this architecture solves:

### 1. The Clock Domain Fallacy (Event-Time vs. Wall-Clock)
**The Trap:** Relying on the host's `time.time()` to measure sliding windows for alerts. Cloud logs (AWS CloudTrail, Azure AD, GCP Audit) routinely lag by minutes or hours. 
**The Fix:** The engine implements **high-watermark tracking**. The clock only advances based on the maximum timestamp extracted from the event stream itself, completely decoupled from the host's physical clock.

### 2. Watermark Poisoning (NTP Desyncs)
**The Trap:** A single rogue endpoint with a broken NTP clock sends a log timestamped 2 hours in the future. The watermark jumps forward, triggering a global sweep that silently wipes all state and kills active attack detections.
**The Fix:** **Max-Skew Bounding**. The engine rejects and metrics logs possessing future timestamps beyond a 1-hour clock-skew tolerance before they can poison the watermark.

### 3. Idempotency & The Wholesale Flush
**The Trap:** Handling duplicate deliveries from at-least-once queues (SQS / PubSub) using a basic set, and wiping the set when it hits a memory limit. Replays arriving immediately after the flush sail through as false positives.
**The Fix:** A **Bounded LRU Cache** (`OrderedDict`). When the cache hits 10,000 events, it safely drops only the oldest `event_id` rather than destroying the entire deduplication history.

### 4. Housekeeping Starvation
**The Trap:** Placing memory cleanup logic at the bottom of a log-processing loop. If a steady stream of malformed logs triggers `continue` statements, the sweep never executes and the engine OOMs.
**The Fix:** Housekeeping tasks are hoisted above conditional logic to guarantee execution every 10 seconds regardless of stream health.

### 5. False "Detections-as-Code"
**The Trap:** Moving thresholds to a YAML file but keeping rule IDs hardcoded in Python (`if rule_id == "R001":`). Adding a new rule does nothing.
**The Fix:** The engine dynamically dispatches based on rule `type` (`threshold` or `sequence`). Adding new detections requires zero code changes.

### 6. Sequence Rule False Positives (NAT Gateways)
**The Trap:** Triggering a "Successful Compromise" alert when an IP successfully logs in immediately after a brute-force burst. In enterprise environments, thousands of users route through the same NAT Gateway IP, leading to massive false positives.
**The Fix:** Sequence detections strictly correlate targets. The successful login must be evaluated against the specific `targeted_users` subset collected during the failure window.

### 7. The Password Spray vs. Brute Force Distinction
**The Trap:** Treating a Password Spray (T1110.003) as just another volume-based brute force threshold. A slow spray that tries one password across 50 different accounts often evades standard velocity thresholds.
**The Fix:** Engineered a distinct `spray` rule type in the engine that tracks and evaluates `unique_targets` per IP, detecting lateral credential testing regardless of failure volume.

### 8. Static Severity & Alert Fatigue
**The Trap:** Hardcoding a `CRITICAL` severity directly to a YAML rule. A brute force attack against a low-privilege guest account shouldn't page the on-call engineer, but the same attack against a root account should.
**The Fix:** Implemented a **Dynamic Risk Engine** that derives the final severity by enriching the log at runtime with mock GeoIP data and Asset Criticality context.

### 9. Prometheus Sparse Metric Oversensitivity
**The Trap:** Using `rate() > 0` to detect malformed logs. The `rate()` function extrapolates data; a single malformed log in a 5-minute window causes a mathematical spike that triggers false alerts.
**The Fix:** Transitioned sparse, event-driven rules to `increase(...[5m]) > 10`, ensuring only statistically significant anomalies are forwarded to Alertmanager.

### 10. The Deadman Switch Inhibition Failure
**The Trap:** When the SIEM container crashes, it stops generating metrics. The monitoring layer fires a "Component Down" alert, but often fires downstream alerts (like "High Alert Volume") based on stale metric extrapolation, causing a pager storm.
**The Fix:** Configured strict `inhibit_rules` in Alertmanager. The `SIEMComponentDown` alert acts as a master suppression switch, instantly muting all downstream metric-based alerts when the parent job dies.
