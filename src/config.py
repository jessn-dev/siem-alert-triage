import os


class Config:
    """12-factor configuration. Every value is overridable by environment."""

    # Ingestion
    SOURCE_TYPE = os.getenv("SIEM_SOURCE_TYPE", "file")
    LOG_FILE = os.getenv("SIEM_LOG_FILE", "logs/auth.log")
    WEBHOOK_LISTEN_HOST = os.getenv("SIEM_WEBHOOK_LISTEN_HOST", "0.0.0.0")
    WEBHOOK_LISTEN_PORT = int(os.getenv("SIEM_WEBHOOK_LISTEN_PORT", "8002"))

    # Output
    SINK_TYPE = os.getenv("SIEM_SINK_TYPE", "file")
    ALERT_DIR = os.getenv("SIEM_ALERT_DIR", "alerts/")
    SINK_WEBHOOK_URL = os.getenv("SIEM_SINK_WEBHOOK_URL", "http://webhook-receiver:8080/alerts")

    # Normalization
    PARSER_TYPE = os.getenv("SIEM_PARSER_TYPE", "mock")

    # Detection
    RULES_FILE = os.getenv("SIEM_RULES_FILE", "rules.yml")
    MAX_CLOCK_SKEW_SECONDS = int(os.getenv("SIEM_MAX_CLOCK_SKEW_SECONDS", "3600"))
    SWEEP_INTERVAL_SECONDS = int(os.getenv("SIEM_SWEEP_INTERVAL_SECONDS", "10"))

    # State
    STATE_BACKEND = os.getenv("SIEM_STATE_BACKEND", "memory")
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
    INGEST_TOKEN = os.getenv("SIEM_INGEST_TOKEN")

    # Observability. Defaults deliberately do not collide with the webhook
    # listener, so `SOURCE_TYPE=webhook` works without any port overrides.
    METRICS_PORT = int(os.getenv("SIEM_METRICS_PORT", "8003"))
    GENERATOR_METRICS_PORT = int(os.getenv("SIEM_GENERATOR_METRICS_PORT", "8001"))
