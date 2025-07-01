# Mock SIEM Alerting and Triage Pipeline

This project demonstrates the core concepts of a Security Information and Event Management (SIEM) system. It simulates log ingestion, applies stateful detection logic (rules), generates structured alerts, and exposes performance/security metrics via Prometheus and Grafana.

This is an excellent portfolio piece to demonstrate an understanding of:
- **Log Parsing & Normalization**: Handling structured JSON logs.
- **Detection Engineering**: Writing logic to detect suspicious patterns over time (e.g., brute-force attacks).
- **Incident Response & Triage**: Generating actionable alerts with context.
- **Security Observability**: Building dashboards with Prometheus and Grafana.

## Prerequisites
- Python 3.x
- Docker and Docker Compose (for Prometheus/Grafana)

## Setup

First, install the Python dependencies:
```bash
pip install -r requirements.txt
```

Next, spin up the monitoring stack (Prometheus & Grafana) using Docker:
```bash
docker-compose up -d
```

## Running the Simulation

You will need two terminal windows to see the Python application in action.

### Terminal 1: Start the Log Generator
This script writes mock logs to `logs/auth.log` and exposes metrics on `http://localhost:8001/metrics`.
```bash
python3 log_generator.py
```

### Terminal 2: Start the SIEM Engine
This script tails the `auth.log` file, detects attacks, generates alerts in the `alerts/` folder, and exposes metrics on `http://localhost:8002/metrics`.
```bash
python3 siem_engine.py
```

## Viewing the Dashboards (Grafana)

1. Open your browser and navigate to `http://localhost:3000`.
2. Login with the default credentials: username `admin`, password `admin`.
3. Grafana is already connected to Prometheus as a data source.
4. You can now build dashboards to visualize metrics such as:
   - `mock_logs_generated_total{status="failed"}`: Failed login rate.
   - `siem_alerts_generated_total`: Alerts firing over time.
   - `siem_active_tracked_ips`: IPs currently being tracked for suspicious behavior.

## Triage workflow
When the SIEM engine generates an alert, view it in the `alerts/` directory and follow the triage steps outlined in the JSON file.
