"""Central configuration. Edit thresholds and lists here (slide 14: thresholds need calibration)."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("HIDS_DB", os.path.join(BASE_DIR, "hids.db"))
SCAN_INTERVAL_SECONDS = int(os.environ.get("HIDS_INTERVAL", "15"))
HOST = os.environ.get("HIDS_HOST", "127.0.0.1")
PORT = int(os.environ.get("HIDS_PORT", "5055"))   # single source of truth for run.py and tools/
RETENTION_DAYS = int(os.environ.get("HIDS_RETENTION_DAYS", "30"))   # old scans/events are pruned

# Paths where legitimate programs rarely run from.
SUSPICIOUS_EXEC_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/", "/private/var/tmp/")
# Hidden directory inside a home folder, e.g. /home/user/.cache/x
HOME_PREFIX = "/home/"          # macOS users live under /Users/ (handled in rules)

# Startup locations that are READ ONLY (metadata only, never modified).
HOME = os.path.expanduser("~")
AUTOSTART_DIRS = [
    os.path.join(HOME, ".config", "autostart"),
    "/etc/xdg/autostart",
]
SYSTEMD_USER_DIRS = [os.path.join(HOME, ".config", "systemd", "user")]
CRON_DIRS = ["/etc/cron.d"]
# macOS startup locations (read only). Empty on other systems.
import sys as _sys
LAUNCH_DIRS = ([os.path.join(HOME, "Library", "LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]
               if _sys.platform == "darwin" else [])
# Tests / demos can add extra directories without touching real ones.
EXTRA_AUTOSTART_DIRS = [d for d in os.environ.get("HIDS_EXTRA_AUTOSTART", "").split(":") if d]

# Known-good programs that legitimately read input devices
# (display server, input method editors, screen readers, remappers).
TRUSTED_INPUT_PROCESSES = {
    "Xorg", "Xwayland", "gnome-shell", "mutter", "kwin_x11", "kwin_wayland",
    "systemd-logind", "ibus-daemon", "ibus-engine-simple", "fcitx5", "fcitx",
    "orca", "libinput", "upowerd", "evtest", "kmscon", "weston", "sway", "Hyprland",
}

# OS-shipped programs (Siri, accessibility and input-method helpers legitimately use
# keyboard event taps). Only honoured on macOS, where the Apple system folders are protected by SIP.
TRUSTED_PATH_PREFIXES = ("/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/") \
    if _sys.platform == "darwin" else ()

# Score points per rule and severity thresholds.
RULE_POINTS = {
    "EXEC_IN_TEMP": 2,
    "EXEC_IN_HIDDEN_HOME_DIR": 2,
    "HIDDEN_PROCESS_NAME": 1,
    "ORPHAN_IN_HOME": 1,
    "OPENS_INPUT_DEVICE": 3,
    "WRITES_TEMP_FILE": 1,
    "PERSISTENCE_TARGET_SUSPICIOUS": 2,
    "NEW_STARTUP_ENTRY": 1,
    "PERSISTENCE_LINKED_TO_RUNNING_PROCESS": 2,
    "MACOS_KEYBOARD_EVENT_TAP": 2,  # weak alone; correlate with unexpected paths/persistence
}
MEDIUM_AT = 3
HIGH_AT = 4

# --- authentication
SECRET_PATH = os.environ.get("HIDS_SECRET", os.path.join(BASE_DIR, "hids_secret.key"))
ALLOW_REGISTRATION = os.environ.get("HIDS_ALLOW_REGISTER", "0") == "1"   # closed by default; the first account is always allowed
MIN_PASSWORD_LENGTH = 8
MAX_LOGIN_FAILURES = 5          # per username+IP within the window below
LOGIN_LOCK_SECONDS = 300

# macOS / LibreSSL compatibility: hashlib.scrypt is unavailable in Apple's Python build.
# Fallback to pbkdf2:sha256 for Werkzeug password hashing when scrypt is not supported.
import hashlib
try:
    import werkzeug.security
    if not hasattr(hashlib, "scrypt"):
        _orig_generate_password_hash = werkzeug.security.generate_password_hash

        def _compat_generate_password_hash(password: str, method: str = "scrypt", salt_length: int = 16) -> str:
            if method == "scrypt":
                method = "pbkdf2:sha256"
            return _orig_generate_password_hash(password, method=method, salt_length=salt_length)

        werkzeug.security.generate_password_hash = _compat_generate_password_hash
except ImportError:
    pass

