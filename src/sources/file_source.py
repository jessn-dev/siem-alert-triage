import os
import time

from .base import BaseSource


class FileSource(BaseSource):
    def __init__(self, filepath, backfill=False, poll_interval=0.5):
        self.filepath = filepath
        self.backfill = backfill
        self.poll_interval = poll_interval
        self.running = True

    def read_events(self):
        if not os.path.exists(self.filepath):
            os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
            open(self.filepath, 'a').close()

        with open(self.filepath) as f:
            if not self.backfill:
                f.seek(0, 2)

            last_inode = os.stat(self.filepath).st_ino
            last_size = os.stat(self.filepath).st_size

            while self.running:
                line = f.readline()
                if not line:
                    try:
                        stat = os.stat(self.filepath)
                        if stat.st_ino != last_inode or stat.st_size < last_size:
                            print(f"[*] Log rotation detected for {self.filepath}")
                            break
                        last_size = stat.st_size
                    except FileNotFoundError:
                        break
                    time.sleep(self.poll_interval)
                    yield None
                    continue
                yield line
