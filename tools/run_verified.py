#!/usr/bin/env python3
"""Start the local HIDS server and open Safari only after HTTP is responding.

Does not change the database, process rules, or existing credentials.  Keeps the
server in the foreground; Control-C stops only the child server it launches.
"""
from pathlib import Path
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import config
HOST = config.HOST
PORT = config.PORT
URL = f'http://{HOST}:{PORT}'


def already_listening():
    try:
        with socket.create_connection((HOST, PORT), timeout=1):
            return True
    except OSError:
        return False


def page_responds():
    try:
        with urllib.request.urlopen(f'{URL}/login', timeout=2) as response:
            body = response.read(30000)
            return response.status == 200 and b'Host-Based Intrusion Detection' in body
    except (OSError, urllib.error.URLError, ValueError):
        return False


def main():
    if already_listening():
        if page_responds():
            print(f'HIDS already responds at {URL}. Do not start a second copy.', flush=True)
        else:
            print('Port 5055 is occupied by a service that does not answer as HIDS.', flush=True)
            print('On Mac: lsof -nP -iTCP:5055 -sTCP:LISTEN', flush=True)
        return 1
    print('Starting HIDS and checking web readiness...', flush=True)
    child = subprocess.Popen([sys.executable, '-u', str(ROOT / 'run.py')], cwd=str(ROOT), env=os.environ.copy())
    try:
        for _ in range(40):
            if child.poll() is not None:
                print(f'HIDS exited during startup with code {child.returncode}. Check the error above.', flush=True)
                return 1
            if page_responds():
                print(f'READY: HIDS login page responds at {URL}', flush=True)
                print('Dashboard requires login; previous alerts remain in the same database.', flush=True)
                webbrowser.open(URL)
                break
            time.sleep(0.5)
        else:
            print('STARTUP TIMEOUT: HIDS did not answer within 20 seconds.', flush=True)
            print('Check errors above, then run: lsof -nP -iTCP:5055 -sTCP:LISTEN', flush=True)
            return 1
        return child.wait()
    except KeyboardInterrupt:
        print('\nStopping HIDS...', flush=True)
        return 0
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()

if __name__ == '__main__':
    raise SystemExit(main())
