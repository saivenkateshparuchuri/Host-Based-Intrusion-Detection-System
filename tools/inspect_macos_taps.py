"""Read-only macOS keyboard event tap audit; prints metadata, NEVER typed text."""
import os
import sys
import psutil

# Allows running this standalone script from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sensors import macos_event_tap_sensor


def main():
    audit = macos_event_tap_sensor.audit_keyboard_taps()
    print(f"Sensor status: {audit.state} — {audit.message}")
    print(f"All event taps: {audit.total_taps}; enabled key-event taps: {audit.keyboard_taps}")
    for pid, tap_ids in sorted(audit.by_pid.items()):
        try:
            name = psutil.Process(pid).name()
        except psutil.Error:
            name = "(process metadata unavailable)"
        print(f"PID {pid:<7} process={name!r}  keyboard-tap IDs={tap_ids}")
    if audit.state == "ok" and not audit.by_pid:
        print("No enabled keyboard-event taps were reported. This does NOT rule out other keylogging methods.")
    print("No keystrokes, clipboard content, or window text were accessed.")
    return 0 if audit.state == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
