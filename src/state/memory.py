import time
from collections import OrderedDict, defaultdict

from .base import BaseState

DEDUP_CAPACITY = 10000


class MemoryState(BaseState):
    """Single-process state backend. Correct, but bounded to one replica.

    Two clocks live here on purpose:

    * **Event time**, per IP, decides detection windows. Keeping it per key is
      what stops one desynced host from flushing everyone else's window.
    * **Arrival time**, wall clock, decides garbage collection only. An idle
      IP's own event clock never advances, so it could never age itself out -
      and using a *global* event clock for eviction would just reintroduce the
      cross-IP poisoning through the GC path.
    """

    def __init__(self, dedup_capacity: int = DEDUP_CAPACITY, time_source=time.time):
        self.state = defaultdict(lambda: {"Failure": [], "Success": []})
        self.last_alerted = {}
        self.watermarks = defaultdict(float)
        self.last_seen_wall = {}
        self.seen_events = OrderedDict()
        self.dedup_capacity = dedup_capacity
        self._now = time_source

    def is_duplicate(self, event_id: str) -> bool:
        if event_id in self.seen_events:
            return True
        self.seen_events[event_id] = True
        if len(self.seen_events) > self.dedup_capacity:
            self.seen_events.popitem(last=False)
        return False

    def update_watermark(self, key: str, ts: float):
        if ts > self.watermarks[key]:
            self.watermarks[key] = ts

    def get_watermark(self, key: str) -> float:
        return self.watermarks[key]

    def add_event(self, ip: str, status: str, event_data: tuple):
        self.state[ip][status].append(event_data)
        self.last_seen_wall[ip] = self._now()

    def get_events(self, ip: str, status: str, time_window: float) -> list:
        watermark = self.watermarks[ip]
        return [x for x in self.state[ip][status] if watermark - x[0] <= time_window]

    def check_and_set_cooldown(self, ip: str, rule_id: str, cooldown_window: float) -> bool:
        watermark = self.watermarks[ip]
        last_alert = self.last_alerted.get(ip, {}).get(rule_id)
        if last_alert is not None and watermark - last_alert <= cooldown_window:
            return False
        self.last_alerted.setdefault(ip, {})[rule_id] = watermark
        return True

    def sweep(self, max_window: float, max_suppression: float):
        idle_limit = max_window + max_suppression
        now = self._now()

        for ip in list(self.state.keys()):
            # Trim members that this IP's own event clock has already moved past.
            watermark = self.watermarks[ip]
            bucket = self.state[ip]
            bucket["Failure"] = [x for x in bucket["Failure"] if watermark - x[0] <= max_window]
            bucket["Success"] = [x for x in bucket["Success"] if watermark - x[0] <= max_window]

            # Evict the key entirely once nothing has arrived for it in a full
            # window plus suppression period. Anything retained at that point
            # would be pruned by watermark on the IP's next event anyway.
            if now - self.last_seen_wall.get(ip, now) > idle_limit:
                del self.state[ip]
                self.last_alerted.pop(ip, None)
                self.watermarks.pop(ip, None)
                self.last_seen_wall.pop(ip, None)

    def get_active_count(self) -> int:
        return len([ip for ip, data in self.state.items() if data["Failure"]])
