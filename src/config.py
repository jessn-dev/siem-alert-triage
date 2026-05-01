import os

class Config:
    LOG_FILE = os.getenv("SIEM_LOG_FILE", "logs/auth.log")
    ALERT_DIR = os.getenv("SIEM_ALERT_DIR", "alerts/")
    METRICS_PORT = int(os.getenv("SIEM_METRICS_PORT", "8002"))
    RULES_FILE = os.getenv("SIEM_RULES_FILE", "rules.yml")
    STATE_BACKEND = os.getenv("SIEM_STATE_BACKEND", "memory")
    SOURCE_TYPE = os.getenv("SIEM_SOURCE_TYPE", "file")
    SINK_TYPE = os.getenv("SIEM_SINK_TYPE", "file")
