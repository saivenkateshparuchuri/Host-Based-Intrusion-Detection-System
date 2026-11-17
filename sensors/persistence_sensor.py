"""Reads Linux startup entries (read-only). Never deletes or disables anything."""
import os
import re
import glob
import plistlib
from models import PersistenceEntry
import config


def _first_token_path(cmd):
    cmd = re.sub(r"%[a-zA-Z]", "", cmd).strip()
    cmd = re.sub(r"^(env\s+\S+=\S+\s+|/usr/bin/env\s+)", "", cmd)
    for tok in cmd.split():
        tok = tok.strip("\"'")
        if tok.startswith(("/", "~")):
            return os.path.expanduser(tok)
    return cmd.split()[0] if cmd.split() else ""


def _read_key(path, key):
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                if line.strip().startswith(key + "="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


def _cron_target(path):
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" in line.split()[0]:
                    continue
                parts = line.split(None, 6)
                if len(parts) >= 7:
                    return _first_token_path(parts[6])
    except OSError:
        pass
    return ""


def _plist_target(path):
    """Program launched by a macOS LaunchAgent/LaunchDaemon plist."""
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return ""
    args = data.get("ProgramArguments") or []
    prog = data.get("Program") or (args[0] if args else "")
    # interpreter launches: report the script, as the process sensor does
    if os.path.basename(prog).lower().startswith(("python", "bash", "sh", "perl", "ruby", "node")) and len(args) > 1:
        for a in args[1:]:
            if a.startswith("/"):
                return a
    return prog


def collect():
    entries = []

    def add(source, path, target):
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = 0.0
        entries.append(PersistenceEntry(source=source, name=os.path.basename(path),
                                        path=path, target=target, mtime=mtime))

    for d in config.AUTOSTART_DIRS + config.EXTRA_AUTOSTART_DIRS:
        for f in glob.glob(os.path.join(d, "*.desktop")):
            add("autostart", f, _first_token_path(_read_key(f, "Exec")))
    for d in config.LAUNCH_DIRS:
        for f in glob.glob(os.path.join(d, "*.plist")):
            add("launchd", f, _plist_target(f))
    for d in config.SYSTEMD_USER_DIRS:
        for f in glob.glob(os.path.join(d, "*.service")):
            add("systemd-user", f, _first_token_path(_read_key(f, "ExecStart")))
    for d in config.CRON_DIRS:
        for f in glob.glob(os.path.join(d, "*")):
            if os.path.isfile(f):
                add("cron", f, _cron_target(f))
    return entries
