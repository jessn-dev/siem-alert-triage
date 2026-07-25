from abc import ABC, abstractmethod


class BaseState(ABC):
    """Sliding-window detection state.

    Watermarks are tracked *per key* (per source IP), not globally. A single
    host with a desynced clock must not be able to advance the clock for every
    other tracked entity and silently flush their windows.
    """

    @abstractmethod
    def is_duplicate(self, event_id: str) -> bool: ...

    @abstractmethod
    def update_watermark(self, key: str, ts: float): ...

    @abstractmethod
    def get_watermark(self, key: str) -> float: ...

    @abstractmethod
    def add_event(self, ip: str, status: str, event_data: tuple): ...

    @abstractmethod
    def get_events(self, ip: str, status: str, time_window: float) -> list: ...

    @abstractmethod
    def check_and_set_cooldown(self, ip: str, rule_id: str, cooldown_window: float) -> bool: ...

    @abstractmethod
    def sweep(self, max_window: float, max_suppression: float): ...

    @abstractmethod
    def get_active_count(self) -> int: ...
