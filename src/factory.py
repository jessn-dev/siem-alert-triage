from src.config import Config
from src.sources.file_source import FileSource
from src.sinks.file_sink import FileSink
from src.state.memory import MemoryState
from src.parsers.mock import MockParser

def get_source():
    if Config.SOURCE_TYPE == "file":
        return FileSource(Config.LOG_FILE)
    elif Config.SOURCE_TYPE == "webhook":
        from src.sources.webhook import WebhookSource
        return WebhookSource(host="0.0.0.0", port=8002)
    raise ValueError(f"Unknown SOURCE_TYPE: {Config.SOURCE_TYPE}")

def get_sink():
    if Config.SINK_TYPE == "file":
        return FileSink(Config.ALERT_DIR)
    elif Config.SINK_TYPE == "webhook":
        from src.sinks.webhook import WebhookSink
        return WebhookSink(Config.SINK_WEBHOOK_URL)
    raise ValueError(f"Unknown SINK_TYPE: {Config.SINK_TYPE}")

def get_state():
    if Config.STATE_BACKEND == "memory":
        return MemoryState()
    elif Config.STATE_BACKEND == "redis":
        from src.state.redis_state import RedisState
        return RedisState(host=Config.REDIS_HOST, port=Config.REDIS_PORT)
    raise ValueError(f"Unknown STATE_BACKEND: {Config.STATE_BACKEND}")

def get_parser():
    if Config.PARSER_TYPE == "cloudtrail":
        from src.parsers.cloudtrail import CloudTrailParser
        return CloudTrailParser()
    return MockParser()
