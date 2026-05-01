import json
from .base import BaseParser

class MockParser(BaseParser):
    def parse(self, raw_line: str) -> dict:
        try:
            raw = json.loads(raw_line)
        except (json.JSONDecodeError, TypeError):
            return None
            
        return {
            "metadata": {
                "version": "1.0.0",
                "product": {"name": "MockSIEM"},
                "event_id": raw.get("event_id")
            },
            "time": raw.get("timestamp"),
            "activity_name": "Logon",
            "status": "Success" if raw.get("status") == "success" else "Failure",
            "src_endpoint": {"ip": raw.get("source_ip")},
            "user": {"name": raw.get("user")},
            "raw_data": raw_line
        }
