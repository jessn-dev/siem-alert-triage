# Mock SIEM Alerting and Triage Pipeline

A functional SIEM pipeline that covers log ingestion, stateful detection, alerting, and observability. It uses Prometheus, Grafana, and Alertmanager.

## Core Features
- **Log Parsing**: Parses and normalizes raw JSON authentication logs.
- **Detection Engine**: Detects brute-force attacks across sliding time windows using a Python backend.
- **Alert Routing**: Forwards critical events to a mock webhook receiver via Alertmanager.
- **Observability**: Exposes metrics to Prometheus and provides a Grafana dashboard for real-time traffic monitoring.
- **Testing**: Includes a pytest suite covering time boundaries, state cleanup, and log validation.

## Prerequisites
- Python 3
- Docker and Docker Compose

## Setup

Install the Python requirements:
```bash
pip install -r requirements.txt
```

Start the monitoring stack:
```bash
docker-compose up -d
```

## Running the Engine

You need two terminals.

Terminal 1 runs the log generator on port 8001:
```bash
python3 log_generator.py
```

Terminal 2 runs the SIEM engine on port 8002:
```bash
python3 siem_engine.py
```

## Viewing Dashboards

The project sets up a Grafana dashboard automatically.

1. Go to `http://localhost:3000`
2. Login with `admin` / `admin`
3. Click **Dashboards** > **Browse** and open the **SIEM Observability Overview** board.

## Alerting

When the SIEM engine triggers a rule, it drops a JSON file into the `alerts/` folder. Prometheus then evaluates the metric spikes against its rule file (`alert.rules.yml`) and passes the state to Alertmanager.

Alertmanager routes the payload to a local webhook receiver. Watch the alerts arrive in real time:
```bash
docker logs -f siem_webhook_receiver
```

## Running Tests

Run the test suite to verify the detection logic:
```bash
python3 -m pytest tests/
```
