"""Register and run a metadata-only HIDS agent for the shared dashboard."""
import argparse
import getpass
import json
import platform
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

CONFIG_PATH = Path.home() / ".hids-agent.json"


def device_id():
    return uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname()).hex


def request_json(url, payload, token=None):
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"server returned HTTP {exc.code}: {detail}") from exc


def register(args):
    name = args.name or socket.gethostname()
    current_id = device_id()
    username = args.username
    password = getpass.getpass("Dashboard password: ")
    result = request_json(args.server.rstrip("/") + "/api/agent/register", {
        "username": username, "password": password, "device_id": current_id,
        "name": name, "platform": platform.platform(),
    })
    CONFIG_PATH.write_text(json.dumps({
        "server": args.server.rstrip("/"), "device_id": current_id,
        "name": name, "token": result["token"],
    }) + "\n")
    CONFIG_PATH.chmod(0o600)
    print(f"Registered {name} as {current_id}. Configuration saved to {CONFIG_PATH}.")


def scan_once(settings):
    import scanner
    from storage import db

    started = time.time()
    conn = db.connect()
    try:
        processes, alerts = scanner.run_scan(conn)
    finally:
        conn.close()
    payload = {
        "device_id": settings["device_id"], "name": settings["name"],
        "platform": platform.platform(), "processes": len(processes),
        "unreadable": sum(1 for process in processes if not process.fd_readable),
        "alert_count": len(alerts), "seconds": round(time.time() - started, 3),
        "alerts": [{
            "key": alert.key, "severity": alert.severity, "score": alert.score,
            "subject": alert.subject, "pid": alert.pid, "path": alert.path,
            "reasons": alert.reasons,
        } for alert in alerts],
    }
    request_json(settings["server"] + "/api/agent/scan", payload, settings["token"])


def run(args):
    settings = json.loads(CONFIG_PATH.read_text())
    if args.server:
        settings["server"] = args.server.rstrip("/")
    while True:
        try:
            scan_once(settings)
            print(f"Scan sent for {settings['name']}.", flush=True)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"Agent scan failed: {exc}", flush=True)
        if args.once:
            return
        time.sleep(args.interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    register_parser = subparsers.add_parser("register")
    register_parser.add_argument("--server", required=True, help="Dashboard URL")
    register_parser.add_argument("--username", required=True)
    register_parser.add_argument("--name", help="Friendly device name")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--server", help="Override the registered dashboard URL")
    run_parser.add_argument("--interval", type=int, default=30)
    run_parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.command == "register":
        register(args)
    else:
        run(args)


if __name__ == "__main__":
    main()
