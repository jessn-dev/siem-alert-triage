from abc import ABC, abstractmethod

class BaseSource(ABC):
    @abstractmethod
    def read_events(self):
        pass
