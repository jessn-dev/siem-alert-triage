import json
import os

from .base import BaseSink


class FileSink(BaseSink):
    """Writes alerts as JSON artifacts to a directory.

    Writability is proven at startup rather than on first alert. A read-only
    mount or a bad path is a misconfiguration, and a misconfiguration should
    stop the process immediately with an actionable message - not surface as a
    crash at the exact moment a detection fires.
    """

    def __init__(self, alert_dir="alerts/"):
        self.alert_dir = alert_dir
        try:
            os.makedirs(self.alert_dir, exist_ok=True)
            probe = os.path.join(self.alert_dir, ".write-probe")
            with open(probe, "w") as f:
                f.write("")
            os.remove(probe)
        except OSError as exc:
            raise RuntimeError(
                f"Alert directory {self.alert_dir!r} is not writable ({exc}). "
                f"Set SIEM_ALERT_DIR to a writable path, or use SIEM_SINK_TYPE=webhook "
                f"if this container runs with a read-only root filesystem."
            ) from exc

    def write_alert(self, alert: dict) -> bool:
        filepath = os.path.join(self.alert_dir, f"{alert['alert_id']}.json")
        try:
            with open(filepath, "w") as f:
                json.dump(alert, f, indent=4)
        except OSError as exc:
            # A failed sink must not take detection down with it.
            print(f"[x] Failed to write {alert['alert_id']}: {exc}")
            return False
        print(f"[!] {alert['severity']} ALERT WRITTEN TO FILE: {alert['alert_id']}")
        return True
