"""Shared log emission for the generator and the attack simulator.

Both need to reach the engine whichever transport it is configured for, so the
demo tooling never assumes a shared filesystem.
"""

import os
import time

from src.config import Config


class Emitter:
    def __init__(self, webhook_url=None, log_file=None, max_bytes=5 * 1024 * 1024,
                 auth_token=None, on_failure=None):
        self.webhook_url = webhook_url or os.getenv("WEBHOOK_URL")
        # Same env var the engine reads, so producer and consumer cannot drift.
        self.auth_token = auth_token or Config.INGEST_TOKEN
        self.log_file = log_file or Config.LOG_FILE
        self.max_bytes = max_bytes
        # Called with a reason string on every failed delivery, so a producer
        # can surface send failures as metrics instead of only as log lines.
        self.on_failure = on_failure
        self._handle = None

        if self.webhook_url:
            import requests
            self._session = requests.Session()
        else:
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            self._handle = open(self.log_file, "a")

    @property
    def mode(self):
        return "webhook" if self.webhook_url else "file"

    def target(self):
        return self.webhook_url or self.log_file

    def _fail(self, reason: str, detail) -> bool:
        print(f"[x] POST to {self.webhook_url} failed ({reason}): {detail}")
        if self.on_failure:
            self.on_failure(reason)
        time.sleep(1)  # back off rather than hot-looping on a broken endpoint
        return False

    def send(self, line: str) -> bool:
        if self.webhook_url:
            headers = {"Content-Type": "application/json"}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"
            try:
                response = self._session.post(
                    self.webhook_url,
                    data=line.encode("utf-8"),
                    headers=headers,
                    timeout=2,
                )
            except Exception as exc:
                return self._fail("transport", exc)

            # requests does not raise on 4xx/5xx. An unchecked status here means
            # a token mismatch silently discards every event while reporting
            # success, so the status is classified explicitly.
            if response.status_code in (401, 403):
                return self._fail("auth", f"{response.status_code} - check SIEM_INGEST_TOKEN")
            if response.status_code >= 400:
                return self._fail("http", response.status_code)
            return True

        if self._handle.tell() > self.max_bytes:
            print("Log file hit size cap. Truncating to simulate rotation...")
            self._handle.truncate(0)
            self._handle.seek(0)

        self._handle.write(line + "\n")
        self._handle.flush()
        return True

    def close(self):
        if self._handle:
            self._handle.close()
