from abc import ABC, abstractmethod

class BaseState(ABC):
    @abstractmethod
    def is_duplicate(self, event_id: str) -> bool: pass
    @abstractmethod
    def update_watermark(self, ts: float): pass
    @abstractmethod
    def get_watermark(self) -> float: pass
    @abstractmethod
    def add_event(self, ip: str, status: str, event_data: tuple): pass
    @abstractmethod
    def get_events(self, ip: str, status: str, time_window: float) -> list: pass
    @abstractmethod
    def check_and_set_cooldown(self, ip: str, rule_id: str, cooldown_window: float) -> bool: pass
    @abstractmethod
    def sweep(self, max_window: float, max_suppression: float): pass
    @abstractmethod
    def get_active_count(self) -> int: pass
