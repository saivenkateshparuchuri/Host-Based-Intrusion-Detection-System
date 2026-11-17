#!/usr/bin/env python3
"""Validate keyboard-tap inventory and simulated risk correlation; NEVER read key data.

This is a safe functional validation, NOT a real-malware detection benchmark.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine import rules
from models import ProcessObs
from sensors import macos_event_tap_sensor as mac


def main():
    print('HIDS safe input-monitoring detection verification')
    print('------------------------------------------------')
    scan = mac.audit_keyboard_taps()
    print(f'Native macOS event-tap audit: {scan.state} — {scan.message}')
    if scan.state == 'ok':
        print(f'Observed: {scan.total_taps} total taps, {scan.keyboard_taps} enabled keyboard taps')
        print('These taps might be installed by legitimate apps. No malware verdict is made.')
    elif sys.platform == 'darwin':
        print('Note: macOS native enumeration is unavailable. Inspect tools/inspect_macos_taps.py output.')

    # Inject synthetic metadata directly into the *existing rule engine*.
    # No new event tap, keylogger process, keystroke, or OS permission is used.
    plain = ProcessObs(pid=987001, name='DemoAccessibility',
                       exe='/Applications/DemoAccessibility.app/Contents/MacOS/DemoAccessibility',
                       macos_keyboard_tap_ids=[12345])
    suspicious = ProcessObs(pid=987002, name='HIDS-Lab-Simulation',
                            exe='/private/tmp/hids_lab_sim/HIDS-Lab-Simulation',
                            macos_keyboard_tap_ids=[12346])
    baseline = ProcessObs(pid=987003, name='BenignProcess',
                          exe='/Applications/BenignProcess.app/Contents/MacOS/BenignProcess',
                          macos_keyboard_tap_ids=[])
    expected = [(plain, 'Low'), (suspicious, 'High'), (baseline, None)]
    good = True
    for p, severity in expected:
        result = rules.evaluate([p], [])
        actual = result[0].severity if result else None
        check = actual == severity
        good &= check
        print(f'{"PASS" if check else "FAIL"}: {p.name}: expected={severity or "none"}, actual={actual or "none"}')
        if result:
            print('  Rules: ' + ' | '.join(result[0].reasons))
    print('No keyboard content, clipboard data, or window text was accessed.')
    if not good:
        print('Rule tests failed. Confirm the macOS upgrade was applied to this same project directory.')
        return 1
    print('Synthetic correlation tests PASSED.')
    print('LIMITATION: Real malicious keylogger detection, false-positive rate, and accuracy are NOT established by this test.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
