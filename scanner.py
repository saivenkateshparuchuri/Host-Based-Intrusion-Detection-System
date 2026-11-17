import threading
import time
from sensors import process_sensor, persistence_sensor
from engine import rules
from storage import db


_lock = threading.Lock()   # background loop and the "Scan now" button must not scan at the same time
_scans_done = 0


def run_scan(conn):
    """One full cycle: collect -> normalize -> evaluate -> store. Returns (processes, alerts)."""
    with _lock:
        return _run_scan(conn)


def _run_scan(conn):
    global _scans_done
    t0 = time.time()
    procs = process_sensor.collect()
    entries = persistence_sensor.collect()
    db.mark_persistence(conn, entries)
    alerts = rules.evaluate(procs, entries)
    db.save_alerts(conn, alerts)
    unreadable = sum(1 for p in procs if not p.fd_readable)
    db.save_scan(conn, len(procs), unreadable, len(alerts), round(time.time() - t0, 3))
    _scans_done += 1
    if _scans_done % 240 == 1:          # roughly hourly at the default interval
        db.prune(conn)
    conn.commit()
    return procs, alerts
