import os
import json
from .base import BaseSink

class FileSink(BaseSink):
    def __init__(self, alert_dir):
        self.alert_dir = alert_dir
        if not os.path.exists(self.alert_dir):
            os.makedirs(self.alert_dir, exist_ok=True)
            
    def write_alert(self, alert: dict):
        filepath = os.path.join(self.alert_dir, f"{alert['alert_id']}.json")
        with open(filepath, "w") as f:
            json.dump(alert, f, indent=4)
        print(f"[!] {alert['severity']} ALERT WRITTEN TO FILE: {alert['alert_id']}")
