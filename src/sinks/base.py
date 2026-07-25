from abc import ABC, abstractmethod


class BaseSink(ABC):
    @abstractmethod
    def write_alert(self, alert: dict):
        pass
