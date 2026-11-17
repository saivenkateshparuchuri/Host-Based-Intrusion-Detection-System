"""Collects process METADATA only. Never reads typed text or window contents."""
import os
import sys
import psutil
from models import ProcessObs
from sensors import macos_event_tap_sensor
import config


def _is_writable_file(pid, fd, target):
    """True for regular files opened for writing (reads /proc/<pid>/fdinfo flags; metadata only)."""
    try:
        if not os.path.isfile(target):
            return False
        with open(f"/proc/{pid}/fdinfo/{fd}") as fh:
            for line in fh:
                if line.startswith("flags:"):
                    return (int(line.split()[1], 8) & 0o3) in (1, 2)
    except (OSError, ValueError):
        pass
    return False


def _fd_scan(pid):
    """Return (input_devices, temp_files, readable). Needs root to see other users' processes."""
    devices, temps = [], []
    if not sys.platform.startswith("linux"):      # no /proc on macOS: input-device check unavailable
        return devices, temps, True
    fd_dir = f"/proc/{pid}/fd"
    try:
        for fd in os.listdir(fd_dir):
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target.startswith("/dev/input/"):
                devices.append(target)
            elif target.startswith(config.SUSPICIOUS_EXEC_PREFIXES) and _is_writable_file(pid, fd, target):
                temps.append(target)
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return devices, temps, False
    return devices, temps, True


_LAST_MACOS_AUDIT = macos_event_tap_sensor.TapAudit("unsupported", "Not yet scanned")

def get_macos_audit_status():
    """Safe, read-only health metadata for the dashboard (no keystrokes)."""
    a = _LAST_MACOS_AUDIT
    return {"state": a.state, "message": a.message,
            "total_taps": a.total_taps, "keyboard_taps": a.keyboard_taps,
            "processes_with_keyboard_taps": len(a.by_pid)}

def collect():
    """Return a list of ProcessObs. Inaccessible processes are skipped, never crash (TC-04)."""
    global _LAST_MACOS_AUDIT
    _LAST_MACOS_AUDIT = macos_event_tap_sensor.audit_keyboard_taps()
    observations = []
    for proc in psutil.process_iter():
        try:
            with proc.oneshot():
                pid = proc.pid
                name = proc.name()
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess, FileNotFoundError):
                    exe = ""
                try:
                    cmdline = proc.cmdline()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cmdline = []
                ppid = proc.ppid()
                parent_name = ""
                try:
                    parent_name = psutil.Process(ppid).name() if ppid else ""
                except psutil.Error:
                    pass
                try:
                    user = proc.username()
                except (psutil.AccessDenied, KeyError):
                    user = ""
                devices, temps, ok = _fd_scan(pid)
                observations.append(ProcessObs(
                    pid=pid, name=name, exe=exe, ppid=ppid, parent_name=parent_name,
                    username=user, create_time=proc.create_time(),
                    cpu_percent=proc.cpu_percent(None),
                    memory_mb=round(proc.memory_info().rss / 1048576, 1),
                    input_devices=devices,
                    macos_keyboard_tap_ids=_LAST_MACOS_AUDIT.by_pid.get(pid, []),
                    temp_files=temps, cmdline=cmdline, fd_readable=ok,
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue  # one bad process must not stop the scan
    return observations
