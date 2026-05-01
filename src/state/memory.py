from collections import defaultdict, OrderedDict
from .base import BaseState

class MemoryState(BaseState):
    def __init__(self):
        self.state = defaultdict(lambda: {"Failure": [], "Success": []})
        self.last_alerted = {}
        self.watermark = 0.0
        self.seen_events = OrderedDict()
        
    def is_duplicate(self, event_id: str) -> bool:
        if event_id in self.seen_events:
            return True
        self.seen_events[event_id] = True
        if len(self.seen_events) > 10000:
            self.seen_events.popitem(last=False)
        return False
        
    def update_watermark(self, ts: float):
        if ts > self.watermark:
            self.watermark = ts
            
    def get_watermark(self) -> float:
        return self.watermark
        
    def add_event(self, ip: str, status: str, event_data: tuple):
        self.state[ip][status].append(event_data)
            
    def get_events(self, ip: str, status: str, time_window: float) -> list:
        return [x for x in self.state[ip][status] if self.watermark - x[0] <= time_window]
        
    def check_and_set_cooldown(self, ip: str, rule_id: str, cooldown_window: float) -> bool:
        last_alert = self.last_alerted.get(ip, {}).get(rule_id, 0)
        if self.watermark - last_alert > cooldown_window:
            if ip not in self.last_alerted:
                self.last_alerted[ip] = {}
            self.last_alerted[ip][rule_id] = self.watermark
            return True
        return False
        
    def sweep(self, max_window: float, max_suppression: float):
        ips = list(self.state.keys())
        for ip in ips:
            valid_fails = [x for x in self.state[ip]["Failure"] if self.watermark - x[0] <= max_window]
            valid_success = [x for x in self.state[ip]["Success"] if self.watermark - x[0] <= max_window]
            
            self.state[ip]["Failure"] = valid_fails
            self.state[ip]["Success"] = valid_success
            
            if not valid_fails and not valid_success:
                safe = True
                if ip in self.last_alerted:
                    for r_id, last_ts in self.last_alerted[ip].items():
                        if self.watermark - last_ts <= max_suppression:
                            safe = False
                            break
                if safe:
                    del self.state[ip]
                    if ip in self.last_alerted:
                        del self.last_alerted[ip]
                        
    def get_active_count(self) -> int:
        return len([ip for ip, data in self.state.items() if len(data["Failure"]) > 0])
