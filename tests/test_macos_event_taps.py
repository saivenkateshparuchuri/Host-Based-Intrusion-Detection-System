"""Tests that use synthetic METADATA ONLY; never create event taps or read keys."""
import ctypes
from models import ProcessObs
from engine import rules
from sensors import macos_event_tap_sensor as sensor
from sensors import process_sensor


def _tap(pid, id, mask, enabled=True):
    tap = sensor._CGEventTapInformation()
    tap.eventTapID = id
    tap.tappingProcess = pid
    tap.eventsOfInterest = mask
    tap.enabled = enabled
    return tap


def test_macos_struct_layout():
    # Field alignment for macOS arm64/x86_64, from CoreGraphics public header.
    assert ctypes.sizeof(sensor._CGEventTapInformation) == 48
    assert sensor._CGEventTapInformation.eventsOfInterest.offset == 16
    assert sensor._CGEventTapInformation.tappingProcess.offset == 24


def test_keyboard_tap_classification_without_reading_keystrokes():
    taps = [_tap(123, 7, sensor.KEYBOARD_MASK),
            _tap(124, 8, (1 << 22)),     # mouse only
            _tap(125, 9, sensor.KEYBOARD_MASK, False),
            _tap(123, 10, 1 << sensor.KEY_UP)]
    assert sensor.classify_taps(taps) == {123: [7, 10]}


def test_macos_keyboard_tap_is_weak_indicator_not_malware_verdict():
    p = ProcessObs(pid=123, name="AccessibilityHelper", exe="/Applications/Helper.app/Contents/MacOS/Helper",
                   macos_keyboard_tap_ids=[7])
    alerts = rules.evaluate([p], [])
    assert len(alerts) == 1
    assert alerts[0].severity == "Low"
    assert "MACOS_KEYBOARD_EVENT_TAP" in alerts[0].reasons[0]


def test_keyboard_tap_correlated_with_temp_path_escalates():
    p = ProcessObs(pid=123, name="Helper", exe="/tmp/suspicious/Helper", macos_keyboard_tap_ids=[7])
    alerts = rules.evaluate([p], [])
    assert len(alerts) == 1 and alerts[0].severity == "High"


def test_collector_does_not_crash_when_audit_is_unavailable(monkeypatch):
    monkeypatch.setattr(process_sensor.macos_event_tap_sensor, "audit_keyboard_taps",
                        lambda: sensor.TapAudit("error", "Access not available"))
    procs = process_sensor.collect()
    assert isinstance(procs, list)
    assert process_sensor.get_macos_audit_status()["state"] == "error"


def test_apple_system_process_with_tap_is_not_flagged(monkeypatch):
    import config
    monkeypatch.setattr(config, "TRUSTED_PATH_PREFIXES", ("/System/",))
    p = ProcessObs(pid=1, name="Siri", exe="/System/Library/CoreServices/Siri.app/Contents/MacOS/Siri",
                   macos_keyboard_tap_ids=[3])
    assert rules.evaluate([p], []) == []
    q = ProcessObs(pid=2, name="Siri", exe="/tmp/Siri", macos_keyboard_tap_ids=[3])   # impostor in temp
    assert rules.evaluate([q], [])[0].severity == "High"
