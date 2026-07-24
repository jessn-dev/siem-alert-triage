import os

class Config:
    LOG_FILE = os.getenv("SIEM_LOG_FILE", "logs/auth.log")
    ALERT_DIR = os.getenv("SIEM_ALERT_DIR", "alerts/")
    METRICS_PORT = int(os.getenv("SIEM_METRICS_PORT", "8002"))
    RULES_FILE = os.getenv("SIEM_RULES_FILE", "rules.yml")
    STATE_BACKEND = os.getenv("SIEM_STATE_BACKEND", "memory")
    SOURCE_TYPE = os.getenv("SIEM_SOURCE_TYPE", "file")
    SINK_TYPE = os.getenv("SIEM_SINK_TYPE", "file")
    PARSER_TYPE = os.getenv("SIEM_PARSER_TYPE", "mock")
    SINK_WEBHOOK_URL = os.getenv("SIEM_SINK_WEBHOOK_URL", "http://localhost:8080/alerts")
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
