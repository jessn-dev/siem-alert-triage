import requests

from src.sinks.base import BaseSink


class WebhookSink(BaseSink):
    """Posts alerts to an HTTP endpoint (SOAR, ticketing, chat relay)."""

    def __init__(self, url, timeout=5, retries=2):
        self.url = url
        self.timeout = timeout
        self.retries = retries

    def write_alert(self, alert: dict):
        for attempt in range(self.retries + 1):
            try:
                response = requests.post(self.url, json=alert, timeout=self.timeout)
                response.raise_for_status()
                print(f"[!] {alert['severity']} ALERT POSTED: {alert['alert_id']}")
                return True
            except requests.RequestException as exc:
                if attempt == self.retries:
                    # Never raise: a dead sink must not take down detection.
                    print(f"[x] Webhook delivery failed for {alert['alert_id']}: {exc}")
                    return False
        return False
