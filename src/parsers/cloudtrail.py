import json

from .base import (
    STATUS_ID_FAILURE,
    STATUS_ID_SUCCESS,
    BaseParser,
    build_authentication_event,
)


class CloudTrailParser(BaseParser):
    """Normalizes AWS CloudTrail ConsoleLogin records into OCSF 3002.

    Same output shape as MockParser, which is the whole point: rules.yml never
    learns which cloud the event came from.
    """

    def parse(self, raw_log: str) -> dict:
        try:
            event = json.loads(raw_log)
        except (json.JSONDecodeError, TypeError):
            return None

        if not isinstance(event, dict) or event.get("eventName") != "ConsoleLogin":
            return None

        response = event.get("responseElements") or {}
        success = response.get("ConsoleLogin") == "Success"

        identity = event.get("userIdentity") or {}
        # Root logins carry no userName; fall back through the identity shape.
        user = identity.get("userName") or identity.get("type") or "unknown"

        return build_authentication_event(
            status_id=STATUS_ID_SUCCESS if success else STATUS_ID_FAILURE,
            raw_time=event.get("eventTime"),
            ip=event.get("sourceIPAddress", "0.0.0.0"),
            user=user,
            event_id=event.get("eventID"),
            product="AWS CloudTrail",
            raw_data=raw_log.strip(),
        )
