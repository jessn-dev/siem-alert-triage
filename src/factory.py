"""Dependency injection for the pluggable I/O layer.

The engine imports nothing concrete. Swapping local files for a cloud
transport, or memory for shared state, is an environment-variable change.
Cloud SDKs are imported lazily so an unused backend never becomes a hard
dependency of the running process.
"""

from src.config import Config


def get_source():
    if Config.SOURCE_TYPE == "file":
        from src.sources.file_source import FileSource
        return FileSource(Config.LOG_FILE)
    if Config.SOURCE_TYPE == "webhook":
        if Config.WEBHOOK_LISTEN_PORT == Config.METRICS_PORT:
            raise ValueError(
                f"SIEM_WEBHOOK_LISTEN_PORT and SIEM_METRICS_PORT are both "
                f"{Config.METRICS_PORT}; the listener and metrics endpoint cannot share a port"
            )
        from src.sources.webhook import WebhookSource
        return WebhookSource(Config.WEBHOOK_LISTEN_HOST, Config.WEBHOOK_LISTEN_PORT, auth_token=Config.INGEST_TOKEN)
    raise ValueError(f"Unknown SIEM_SOURCE_TYPE: {Config.SOURCE_TYPE}")


def get_sink():
    if Config.SINK_TYPE == "file":
        from src.sinks.file_sink import FileSink
        return FileSink(Config.ALERT_DIR)
    if Config.SINK_TYPE == "webhook":
        from src.sinks.webhook import WebhookSink
        return WebhookSink(Config.SINK_WEBHOOK_URL)
    raise ValueError(f"Unknown SIEM_SINK_TYPE: {Config.SINK_TYPE}")


def get_state():
    if Config.STATE_BACKEND == "memory":
        from src.state.memory import MemoryState
        return MemoryState()
    if Config.STATE_BACKEND == "redis":
        from src.state.redis_state import RedisState
        return RedisState(host=Config.REDIS_HOST, port=Config.REDIS_PORT)
    raise ValueError(f"Unknown SIEM_STATE_BACKEND: {Config.STATE_BACKEND}")


def get_parser():
    if Config.PARSER_TYPE == "mock":
        from src.parsers.mock import MockParser
        return MockParser()
    if Config.PARSER_TYPE == "cloudtrail":
        from src.parsers.cloudtrail import CloudTrailParser
        return CloudTrailParser()
    raise ValueError(f"Unknown SIEM_PARSER_TYPE: {Config.PARSER_TYPE}")
