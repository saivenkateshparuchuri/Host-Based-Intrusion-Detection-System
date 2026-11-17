"""SAFE test helper (TC-02 / TC-03). Creates a HARMLESS dummy program that only looks suspicious:
it sits in /tmp, has a hidden name, holds a temp file open and sleeps. It does NOT read input.
Also creates a benign autostart entry in a private demo folder (not your real autostart).

  python3 tools/simulate_threat.py start     # create + launch dummy
  python3 tools/simulate_threat.py stop      # stop and clean up everything
Run the HIDS with:  HIDS_EXTRA_AUTOSTART=/tmp/hids_demo/autostart python3 run.py
"""
import os, shutil, signal, subprocess, sys

DEMO = "/tmp/hids_demo"
DUMMY = os.path.join(DEMO, ".helper_demo")
AUTO = os.path.join(DEMO, "autostart")
PIDFILE = os.path.join(DEMO, "pid")

DUMMY_SRC = """#!/usr/bin/env python3
import time
f = open('/tmp/hids_demo/demo.log', 'a')
while True:
    f.write('tick\\n'); f.flush(); time.sleep(5)
"""


def start():
    os.makedirs(AUTO, exist_ok=True)
    with open(DUMMY, "w") as fh:
        fh.write(DUMMY_SRC)
    os.chmod(DUMMY, 0o755)
    with open(os.path.join(AUTO, "hids-demo.desktop"), "w") as fh:
        fh.write(f"[Desktop Entry]\nType=Application\nName=HIDS demo\nExec={DUMMY}\n")
    proc = subprocess.Popen([DUMMY], start_new_session=True)
    open(PIDFILE, "w").write(str(proc.pid))
    print(f"Dummy started (pid {proc.pid}). Press 'Scan now' in the dashboard.")


def stop():
    if os.path.exists(PIDFILE):
        try:
            os.kill(int(open(PIDFILE).read()), signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass
    shutil.rmtree(DEMO, ignore_errors=True)
    print("Cleaned up.")


if __name__ == "__main__":
    {"start": start, "stop": stop}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: print(__doc__))()
