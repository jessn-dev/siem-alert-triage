import json
from .base import BaseParser

class MockParser(BaseParser):
    def parse(self, raw_line: str) -> dict:
        try:
            raw = json.loads(raw_line)
        except (json.JSONDecodeError, TypeError):
            return None
            
        status_str = raw.get("status", "failed").lower()
        status_id = 1 if status_str == "success" else 2

        return {
            "class_uid": 3002,
            "activity_id": 1,
            "status_id": status_id,
            "status": "Success" if status_id == 1 else "Failure",
            "time": raw.get("timestamp"),
            "src_endpoint": {"ip": raw.get("source_ip", "0.0.0.0")},
            "user": {"name": raw.get("user", "unknown")},
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "MockSIEM"},
                "event_id": raw.get("event_id")
            },
            "raw_data": raw_line
        }
