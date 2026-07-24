import redis
import json
from src.state.base import BaseState

class RedisState(BaseState):
    def __init__(self, host='localhost', port=6379):
        self.client = redis.Redis(host=host, port=port, decode_responses=True)
        
    def add_event(self, ip: str, status: str, event_data: tuple):
        # event_data: (ts, user, event_id, raw)
        key = f"siem:events:{ip}:{status}"
        self.client.zadd(key, {json.dumps(event_data): event_data[0]})
        
    def get_events(self, ip: str, status: str, time_window: int) -> list:
        key = f"siem:events:{ip}:{status}"
        min_ts = self.get_watermark(ip) - time_window
        raw_events = self.client.zrangebyscore(key, min_ts, "+inf")
        return [tuple(json.loads(x)) for x in raw_events]
        
    def sweep(self, max_time_window: int, max_suppression_window: int):
        # Sweeps old events out of Redis
        pass
        
    def check_and_set_cooldown(self, ip: str, rule_id: str, suppression_window: int) -> bool:
        key = f"siem:cooldown:{ip}:{rule_id}"
        if self.client.get(key):
            return False
        self.client.setex(key, suppression_window, "1")
        return True
        
    def is_duplicate(self, event_id: str) -> bool:
        key = f"siem:dedup:{event_id}"
        if self.client.get(key):
            return True
        self.client.setex(key, 86400, "1") # 24h dedup window
        return False
        
    def update_watermark(self, ts: float):
        # Implement global or per-key watermark in redis if needed
        pass
        
    def get_watermark(self, ip: str = None) -> float:
        return float(self.client.get("siem:watermark") or 0)
        
    def get_active_count(self) -> int:
        return len(self.client.keys("siem:events:*:*"))
