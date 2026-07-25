import json

from .base import (
    STATUS_ID_FAILURE,
    STATUS_ID_SUCCESS,
    BaseParser,
    build_authentication_event,
)


class MockParser(BaseParser):
    """Normalizes the local generator's JSON auth logs into OCSF 3002."""

    def parse(self, raw_line: str) -> dict:
        try:
            raw = json.loads(raw_line)
        except (json.JSONDecodeError, TypeError):
            return None

        if not isinstance(raw, dict):
            return None

        success = str(raw.get("status", "failed")).lower() == "success"

        return build_authentication_event(
            status_id=STATUS_ID_SUCCESS if success else STATUS_ID_FAILURE,
            raw_time=raw.get("timestamp"),
            ip=raw.get("source_ip", "0.0.0.0"),
            user=raw.get("user", "unknown"),
            event_id=raw.get("event_id"),
            product="MockSIEM",
            raw_data=raw_line.strip(),
        )
