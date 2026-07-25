import json

import redis

from src.state.base import BaseState

# Keys outlive their window by this factor so a late-arriving event still lands
# inside a live sorted set instead of resurrecting an expired one.
TTL_SLACK = 4
DEDUP_TTL_SECONDS = 86400


class RedisState(BaseState):
    """Shared state backend. Lets multiple engine replicas observe one window.

    Every window operation is scored on the *event-time* watermark for that IP,
    mirroring MemoryState exactly, so detections do not change behaviour when
    you scale out.
    """

    def __init__(self, host="localhost", port=6379, max_window=300, client=None):
        self.client = client or redis.Redis(host=host, port=port, decode_responses=True)
        self.max_window = max_window

    # -- keys ------------------------------------------------------------
    def _events_key(self, ip: str, status: str) -> str:
        return f"siem:events:{ip}:{status}"

    @staticmethod
    def _ip_from_events_key(key: str) -> str:
        # Split off the fixed prefix and the trailing status, so IPv6 addresses
        # (which contain colons themselves) survive the round trip.
        return key.split(":", 2)[2].rsplit(":", 1)[0]

    def _watermark_key(self, key: str) -> str:
        return f"siem:watermark:{key}"

    # -- dedup -----------------------------------------------------------
    def is_duplicate(self, event_id: str) -> bool:
        # SET NX is atomic, so concurrent replicas cannot both claim the event.
        claimed = self.client.set(f"siem:dedup:{event_id}", "1", nx=True, ex=DEDUP_TTL_SECONDS)
        return not claimed

    # -- watermark -------------------------------------------------------
    def update_watermark(self, key: str, ts: float):
        current = self.client.get(self._watermark_key(key))
        if current is None or ts > float(current):
            self.client.set(self._watermark_key(key), ts, ex=self.max_window * TTL_SLACK)

    def get_watermark(self, key: str) -> float:
        return float(self.client.get(self._watermark_key(key)) or 0.0)

    # -- events ----------------------------------------------------------
    def add_event(self, ip: str, status: str, event_data: tuple):
        key = self._events_key(ip, status)
        self.client.zadd(key, {json.dumps(event_data): event_data[0]})
        self.client.expire(key, self.max_window * TTL_SLACK)

    def get_events(self, ip: str, status: str, time_window: float) -> list:
        watermark = self.get_watermark(ip)
        if not watermark:
            return []
        raw = self.client.zrangebyscore(self._events_key(ip, status), watermark - time_window, "+inf")
        return [tuple(json.loads(x)) for x in raw]

    # -- cooldown --------------------------------------------------------
    def check_and_set_cooldown(self, ip: str, rule_id: str, cooldown_window: float) -> bool:
        # Cooldown is expressed in event-time, but Redis TTLs run on wall-clock.
        # Store the firing watermark and compare explicitly so replay and lagged
        # streams suppress identically to MemoryState.
        key = f"siem:cooldown:{ip}:{rule_id}"
        watermark = self.get_watermark(ip)
        last = self.client.get(key)
        if last is not None and watermark - float(last) <= cooldown_window:
            return False
        self.client.set(key, watermark, ex=int(cooldown_window) * TTL_SLACK)
        return True

    # -- housekeeping ----------------------------------------------------
    def sweep(self, max_window: float, max_suppression: float):
        """Trim aged members. TTLs reclaim whole keys; this reclaims members."""
        for key in self.client.scan_iter(match="siem:events:*", count=500):
            ip = self._ip_from_events_key(key)
            watermark = self.get_watermark(ip)
            if watermark:
                self.client.zremrangebyscore(key, "-inf", watermark - max_window)
            if self.client.zcard(key) == 0:
                self.client.delete(key)

    def get_active_count(self) -> int:
        # SCAN, never KEYS: KEYS blocks the whole server on large keyspaces.
        return sum(
            1
            for key in self.client.scan_iter(match="siem:events:*:Failure", count=500)
            if self.client.zcard(key) > 0
        )
