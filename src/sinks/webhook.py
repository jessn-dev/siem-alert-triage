import requests
import json
from src.sinks.base import BaseSink

class WebhookSink(BaseSink):
    def __init__(self, url):
        self.url = url
        
    def write_alert(self, alert_payload: dict):
        try:
            requests.post(self.url, json=alert_payload, timeout=5)
        except requests.RequestException as e:
            print(f"Webhook delivery failed: {e}")
