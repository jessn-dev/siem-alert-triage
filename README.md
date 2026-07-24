<div align="center">

  [![CI](https://github.com/jessn-dev/siem-alert-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/jessn-dev/siem-alert-triage/actions/workflows/ci.yml)
  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
  [![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/release/python-3130/)
  [![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
</div>

# Cloud-Agnostic SIEM Detection & Alerting Pipeline

A modular, containerized Security Information and Event Management (SIEM) pipeline built for modern cloud infrastructures. It normalizes disparate authentication logs into the Open Cybersecurity Schema Framework (OCSF), evaluates them against YAML-based detection rules in real-time, and securely routes critical events through a robust Prometheus and Alertmanager stack.

## ✨ Feature Highlights

- 🛡️ **OCSF Normalization**: Ingests raw AWS CloudTrail or mock JSON logs and normalizes them strictly to OCSF v1.1.0 (Class 3002).
- 🧩 **Detections-as-Code**: YAML-defined threshold and sequence rules mapped directly to MITRE ATT&CK techniques.
- ⚡ **Dynamic Risk Scoring**: Real-time log enrichment with mock GeoIP and asset criticality for adaptive alert severities.
- 📡 **Cloud-Agnostic I/O**: Driven by a factory pattern utilizing stateless HTTP Webhooks and Redis-ready memory, bypassing rigid file mounts.
- 🚨 **Blind SOC Protection**: Automated Prometheus deadman-switches and Alertmanager inhibit rules to prevent alert storms during container crashes.
- 📊 **Observability Ready**: Pre-configured Grafana dashboards for tracking MTTD (Mean Time To Detect) and real-time alert volumes.

## 🚀 Quick Start Guide

Deploy the entire mock infrastructure—including the SIEM engine, log generator, Prometheus, Grafana, and Alertmanager—in a single command.

```bash
# 1. Clone the repository
git clone https://github.com/jessn-dev/siem-alert-triage.git
cd siem-alert-triage

# 2. Start the containerized stack
docker-compose up -d --build

# 3. Watch the mock webhook receiver for triggered alerts
docker logs -f siem_webhook_receiver
```

**Access the Dashboards:**
- Navigate to `http://localhost:3000` (Login: `admin` / `admin`) to view the SIEM Observability Overview.

## 🛠️ Tech Stack

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?style=for-the-badge&logo=Prometheus&logoColor=white)
![Grafana](https://img.shields.io/badge/grafana-%23F46800.svg?style=for-the-badge&logo=grafana&logoColor=white)

---

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

### 11. The RWX Volume Trap (Host Coupling)
**The Trap:** Relying on shared disk mounts (`volumes: - ./logs:/app/logs`) to pass data between the generator and the engine. While this works beautifully in `docker-compose` on a laptop, it completely fails in Kubernetes unless you provision expensive `ReadWriteMany` (RWX) network filesystems.
**The Fix:** Abstracted I/O using a true Factory Pattern. The engine now seamlessly switches from a `FileSource` to an HTTP-based `WebhookSource`. The generator streams logs via HTTP POST over the container network, entirely eliminating the filesystem dependency.

### 12. "Half-OCSF" is Worse Than Custom
**The Trap:** Building a pipeline that claims OCSF compliance but uses invented string mappings (e.g. `activity_name: "Logon"`) instead of the rigid, integer-based enumerations demanded by the spec. Reviewers who know the spec instantly flag this.
**The Fix:** Engineered full compliance with the OCSF v1.1.0 Authentication schema (`class_uid: 3002`, `activity_id: 1`, `status_id: 1/2`). We proved the engine's agnosticism by implementing a secondary `CloudTrailParser` that normalizes raw AWS JSON directly into this exact integer schema alongside the local mock parser.

### 13. Docker Context Bloat & `.dockerignore`
**The Trap:** Running `COPY . .` in a Dockerfile without a `.dockerignore`. It copies local virtual environments (`venv/`), Git histories, and gigabytes of local test logs into the image, bloating deployment times and expanding the attack surface.
**The Fix:** Added a strict `.dockerignore` to ensure only source code is copied, keeping build contexts light and reproducible.

### 14. Root Containers & Production Hygiene
**The Trap:** Running container processes as the default `root` user. If a vulnerability exists in the Python runtime or a deserialization library, attackers gain root access to the container namespace.
**The Fix:** Enforced non-root execution by creating a dedicated `appuser` and running the engine via `USER appuser` in the Dockerfile.

### 15. The `latest` Tag Fallacy
**The Trap:** Pinning infrastructure (Prometheus, Grafana, Alertmanager) to `:latest` in Compose or Kubernetes. An upstream update silently breaks the monitoring stack in production without warning.
**The Fix:** Explicitly pinned all infrastructure images to stable, reproducible SHAs/tags (e.g., `prom/prometheus:v2.45.0`) and implemented explicit HTTP healthchecks to guarantee proper service startup ordering.


## 📝 License & Usage

This repository serves as an architectural showcase and portfolio project demonstrating production-grade SIEM engineering. While it is not actively seeking community contributions or pull requests, the code is open and available for educational review.

This project is licensed under the [MIT License](LICENSE).
