from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ProcessObs:
    pid: int
    name: str
    exe: str = ""
    ppid: int = 0
    parent_name: str = ""
    username: str = ""
    create_time: float = 0.0
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    input_devices: List[str] = field(default_factory=list)   # /dev/input/* held open
    macos_keyboard_tap_ids: List[int] = field(default_factory=list)  # existing keyboard event tap IDs; never keystrokes
    temp_files: List[str] = field(default_factory=list)      # writable files under /tmp etc.
    cmdline: List[str] = field(default_factory=list)
    fd_readable: bool = True                                  # False if /proc/<pid>/fd was denied


@dataclass
class PersistenceEntry:
    source: str            # autostart | systemd-user | cron
    name: str
    path: str              # the config file we read
    target: str = ""       # command/executable it launches
    mtime: float = 0.0
    is_new: bool = False   # first seen after baseline scan


@dataclass
class Alert:
    key: str
    severity: str          # Low | Medium | High
    score: int
    reasons: List[str]
    subject: str           # process name or persistence entry name
    pid: Optional[int] = None
    path: str = ""


INTERPRETERS = ("python", "bash", "sh", "dash", "perl", "ruby", "node")


def effective_path(p):
    """Path that really identifies the program: the script for interpreters, else the executable."""
    base = p.exe.rsplit("/", 1)[-1].lower() if p.exe else ""
    if base.startswith(INTERPRETERS) and len(p.cmdline) > 1:
        for arg in p.cmdline[1:]:
            if arg.startswith("/"):
                return arg
            if not arg.startswith("-"):
                break
    return p.exe
