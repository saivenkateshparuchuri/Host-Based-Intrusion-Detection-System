"""Rule engine: each rule returns (rule_id, reason). Scores are summed per process (correlation)."""
import os
from models import Alert, effective_path
import config


def _in_temp(path):
    return bool(path) and path.startswith(config.SUSPICIOUS_EXEC_PREFIXES)


def _in_hidden_home_dir(path):
    for prefix in (config.HOME_PREFIX, "/Users/"):
        if path and path.startswith(prefix):
            break
    else:
        return False
    parts = path.split("/")[3:-1]            # directories below /home/<user>/
    return any(p.startswith(".") and p not in (".local", ".config") for p in parts)


REVERSE_SHELL_PATTERNS = (
    "/dev/tcp/",
    "/dev/udp/",
    "pty.spawn",
    "socket.socket",
    "nc -e ",
    "ncat -e ",
    "netcat -e ",
    "socat exec:",
    "mkfifo ",
)


def _check_reverse_shell(p):
    cmd = " ".join(p.cmdline) if p.cmdline else ""
    if not cmd:
        return False, ""
    for pat in REVERSE_SHELL_PATTERNS:
        if pat in cmd:
            return True, pat
    if ("bash -i" in cmd or "sh -i" in cmd or "zsh -i" in cmd) and (">&" in cmd or "2>&1" in cmd):
        return True, "interactive shell redirect"
    return False, ""


def _check_masquerading(p):
    if p.name in getattr(config, "CRITICAL_SYSTEM_NAMES", set()):
        path = effective_path(p) or p.exe
        if path and not path.startswith(getattr(config, "SYSTEM_PATH_PREFIXES", ())):
            return True, path
    return False, ""


def _check_deleted_binary(p):
    if p.exe and (p.exe.endswith(" (deleted)") or "(deleted)" in p.exe):
        return True, p.exe
    return False, ""


def _check_obfuscated_cmd(p):
    cmd = " ".join(p.cmdline) if p.cmdline else ""
    if not cmd:
        return False, ""
    lower = cmd.lower()
    pipe_shells = ("| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh", "| python", "|python")
    for tool in ("curl ", "wget ", "fetch "):
        if tool in lower and any(ps in lower for ps in pipe_shells):
            return True, "download piped to shell"
    if "base64" in lower and ("-d" in lower or "--decode" in lower) and any(ps in lower for ps in pipe_shells):
        return True, "base64 decoded pipeline"
    if "eval(base64." in lower or "eval(b64decode" in lower or "-encodedcommand" in lower:
        return True, "encoded eval payload"
    return False, ""


def _format_reason(rule_id, text):
    mitre_id = getattr(config, "RULE_MITRE", {}).get(rule_id)
    if mitre_id:
        return f"[{rule_id}] [MITRE {mitre_id}] {text}"
    return f"[{rule_id}] {text}"


def process_rules(p):
    hits = []
    path = effective_path(p)
    if _in_temp(path):
        hits.append(("EXEC_IN_TEMP", f"Program runs from a temporary folder: {path}"))
    if _in_hidden_home_dir(path):
        hits.append(("EXEC_IN_HIDDEN_HOME_DIR", f"Program lives in a hidden home directory: {path}"))
    if p.name.startswith(".") or path.rsplit("/", 1)[-1].startswith("."):
        hits.append(("HIDDEN_PROCESS_NAME", f"Process or program name starts with a dot: {path or p.name}"))
    if p.ppid == 1 and path.startswith((config.HOME_PREFIX, "/Users/")):
        hits.append(("ORPHAN_IN_HOME", "User-space program detached from its launcher (parent is init)"))
    if p.input_devices and p.name not in config.TRUSTED_INPUT_PROCESSES:
        hits.append(("OPENS_INPUT_DEVICE",
                     f"Holds raw input device open ({', '.join(sorted(set(p.input_devices)))}); "
                     "not on the trusted-input allowlist"))
    trusted_path = bool(path) and path.startswith(config.TRUSTED_PATH_PREFIXES) if config.TRUSTED_PATH_PREFIXES else False
    if p.macos_keyboard_tap_ids and p.name not in config.TRUSTED_INPUT_PROCESSES and not trusted_path:
        hits.append(("MACOS_KEYBOARD_EVENT_TAP",
                     "macOS reports an enabled keyboard-event tap owned by this process "
                     f"(tap IDs: {p.macos_keyboard_tap_ids}); a tap is not proof of malware"))
    if p.temp_files:
        hits.append(("WRITES_TEMP_FILE", f"Has a file open in a temp location: {p.temp_files[0]}"))

    is_rev, rev_pat = _check_reverse_shell(p)
    if is_rev:
        hits.append(("REVERSE_SHELL_PATTERN", f"Reverse shell syntax detected in command line ({rev_pat})"))

    is_masq, masq_path = _check_masquerading(p)
    if is_masq:
        hits.append(("PROCESS_MASQUERADING", f"Process name matches system daemon ({p.name}) but executes from: {masq_path}"))

    is_del, del_exe = _check_deleted_binary(p)
    if is_del:
        hits.append(("DELETED_EXECUTABLE_RUNNING", f"Process is executing from an unlinked or deleted binary: {del_exe}"))

    is_obf, obf_detail = _check_obfuscated_cmd(p)
    if is_obf:
        hits.append(("OBFUSCATED_COMMAND_EXECUTION", f"Obfuscated or pipe-to-shell command execution detected ({obf_detail})"))

    return hits


def persistence_rules(e):
    hits = []
    if _in_temp(e.target) or _in_hidden_home_dir(e.target):
        hits.append(("PERSISTENCE_TARGET_SUSPICIOUS",
                     f"Startup entry launches a program from an untrusted location: {e.target}"))
    if e.is_new:
        hits.append(("NEW_STARTUP_ENTRY", "Startup entry appeared after the baseline scan"))
    return hits


def severity(score):
    if score >= config.HIGH_AT:
        return "High"
    if score >= config.MEDIUM_AT:
        return "Medium"
    return "Low"


def evaluate(processes, entries):
    """Return a list of Alert. Processes/entries with no hits produce nothing (TC-01 baseline)."""
    alerts = []
    running_exes = {}
    for p in processes:
        if effective_path(p):
            running_exes.setdefault(effective_path(p), []).append(p)

    proc_hits = {}
    for p in processes:
        hits = process_rules(p)
        if hits:
            proc_hits[p.pid] = (p, hits)

    for e in entries:
        hits = persistence_rules(e)
        linked = running_exes.get(e.target, [])
        if hits and linked:                 # correlation: startup entry + same program is running
            for lp in linked:
                if lp.pid not in proc_hits:
                    proc_hits[lp.pid] = (lp, [])
                proc_hits[lp.pid][1].append(("PERSISTENCE_LINKED_TO_RUNNING_PROCESS",
                    f"Its program is registered for startup in {e.path}"))
        if hits:
            score = sum(config.RULE_POINTS[r] for r, _ in hits)
            alerts.append(Alert(key=f"persist:{e.path}", severity=severity(score), score=score,
                                reasons=[_format_reason(r, t) for r, t in hits], subject=e.name, path=e.path))

    for pid, (p, hits) in proc_hits.items():
        score = sum(config.RULE_POINTS[r] for r, _ in hits)
        alerts.append(Alert(key=f"proc:{effective_path(p) or p.name}", severity=severity(score), score=score,
                            reasons=[_format_reason(r, t) for r, t in hits], subject=p.name,
                            pid=pid, path=effective_path(p)))
    return alerts
