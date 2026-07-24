import json
from src.parsers.base import BaseParser

class CloudTrailParser(BaseParser):
    def parse(self, raw_log: str) -> dict:
        try:
            event = json.loads(raw_log)
        except json.JSONDecodeError:
            return {}
            
        # Only process ConsoleLogin events for authentication
        if event.get("eventName") != "ConsoleLogin":
            return {}
            
        # OCSF Mapping
        status_id = 1 if event.get("responseElements", {}).get("ConsoleLogin") == "Success" else 2
        user = event.get("userIdentity", {}).get("userName", "unknown")
        ip = event.get("sourceIPAddress", "0.0.0.0")
        
        return {
            "class_uid": 3002,
            "activity_id": 1,
            "status_id": status_id,
            "status": "Success" if status_id == 1 else "Failure",
            "time": event.get("eventTime"),
            "src_endpoint": {"ip": ip},
            "user": {"name": user},
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "AWS CloudTrail"},
                "event_id": event.get("eventID")
            },
            "raw_data": raw_log
        }
