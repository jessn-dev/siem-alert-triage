from abc import ABC, abstractmethod


class BaseSource(ABC):
    """An event source the engine can read from.

    `dropped` is part of the interface, not an optional extra. A source that
    sheds load without a place to report it sheds load silently, which is the
    failure mode this pipeline exists to make visible. Sources that cannot drop
    events simply leave it at zero.
    """

    #: Events discarded since the last drain. Incremented by the source,
    #: drained by the engine via `drain_dropped()`.
    dropped = 0

    @abstractmethod
    def read_events(self):
        pass

    def drain_dropped(self) -> int:
        """Returns the drop count and subtracts what was read.

        Subtracting rather than zeroing matters: a source may increment this
        from another thread (the webhook listener does), and assigning zero
        would discard any drop that landed between the read and the reset.
        """
        count = self.dropped
        if count:
            self.dropped -= count
        return count
