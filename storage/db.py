import json
import sqlite3
import time
import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, ts REAL, kind TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY, key TEXT, severity TEXT, score INTEGER, subject TEXT,
  pid INTEGER, path TEXT, reasons TEXT, first_seen REAL, last_seen REAL,
  count INTEGER DEFAULT 1, status TEXT DEFAULT 'New', note TEXT DEFAULT '',
  device_id TEXT DEFAULT 'local');
CREATE TABLE IF NOT EXISTS persistence_seen(path TEXT PRIMARY KEY, first_seen REAL);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, pw_hash TEXT, role TEXT DEFAULT 'analyst',
  created REAL);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, ts REAL, processes INTEGER,
  unreadable INTEGER, alerts INTEGER, seconds REAL, device_id TEXT DEFAULT 'local');
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY, device_id TEXT UNIQUE, name TEXT, platform TEXT,
  token_hash TEXT, user_id INTEGER, created REAL, last_seen REAL);
"""


def connect(path=None):
    conn = sqlite3.connect(path or config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    for table, column in (("alerts", "device_id"), ("scans", "device_id")):
        columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT DEFAULT 'local'")
    conn.commit()
    return conn


def log_event(conn, kind, detail):
    conn.execute("INSERT INTO events(ts,kind,detail) VALUES(?,?,?)", (time.time(), kind, detail))


def mark_persistence(conn, entries):
    """Entries first seen after the first (baseline) scan stay flagged as new on every scan."""
    base = conn.execute("SELECT MIN(ts) FROM scans").fetchone()[0]   # None until first scan is saved
    for e in entries:
        row = conn.execute("SELECT first_seen FROM persistence_seen WHERE path=?", (e.path,)).fetchone()
        if not row:
            conn.execute("INSERT INTO persistence_seen VALUES(?,?)", (e.path, time.time()))
            if base is not None:
                log_event(conn, "new_startup_entry", e.path)
            e.is_new = base is not None
        else:
            e.is_new = base is not None and row["first_seen"] > base


def save_alerts(conn, alerts, device_id="local"):
    now = time.time()
    for a in alerts:
        row = conn.execute("SELECT id,severity FROM alerts WHERE key=? AND device_id=? "
                           "ORDER BY id DESC LIMIT 1", (a.key, device_id)).fetchone()
        if row and row["severity"] == a.severity:
            conn.execute("UPDATE alerts SET last_seen=?, count=count+1, pid=?, reasons=? "
                         "WHERE id=?", (now, a.pid, json.dumps(a.reasons), row["id"]))
        else:
            conn.execute("""INSERT INTO alerts(key,severity,score,subject,pid,path,reasons,first_seen,last_seen,device_id)
                            VALUES(?,?,?,?,?,?,?,?,?,?)""",
                         (a.key, a.severity, a.score, a.subject, a.pid, a.path,
                          json.dumps(a.reasons), now, now, device_id))
            log_event(conn, "alert", f"{a.severity}: {a.subject} ({a.key})")


def save_scan(conn, n_proc, unreadable, n_alerts, seconds, device_id="local"):
    conn.execute("INSERT INTO scans(ts,processes,unreadable,alerts,seconds,device_id) VALUES(?,?,?,?,?,?)",
                 (time.time(), n_proc, unreadable, n_alerts, seconds, device_id))


def save_remote_scan(conn, device_id, alerts, n_proc, unreadable, n_alerts, seconds):
    """Persist metadata-only results submitted by a registered local agent."""
    now = time.time()
    for alert in alerts:
        key = str(alert.get("key", ""))[:200]
        if not key:
            continue
        row = conn.execute("SELECT id,severity FROM alerts WHERE key=? AND device_id=? "
                           "ORDER BY id DESC LIMIT 1", (key, device_id)).fetchone()
        severity = str(alert.get("severity", "Low"))
        reasons = alert.get("reasons", [])
        if not isinstance(reasons, list):
            reasons = []
        if row and row["severity"] == severity:
            conn.execute("UPDATE alerts SET last_seen=?, count=count+1, pid=?, reasons=? WHERE id=?",
                         (now, alert.get("pid"), json.dumps(reasons), row["id"]))
        else:
            conn.execute("""INSERT INTO alerts(key,severity,score,subject,pid,path,reasons,first_seen,last_seen,device_id)
                            VALUES(?,?,?,?,?,?,?,?,?,?)""",
                         (key, severity, int(alert.get("score", 0)), str(alert.get("subject", ""))[:300],
                          alert.get("pid"), str(alert.get("path", ""))[:1000], json.dumps(reasons), now, now, device_id))
    save_scan(conn, int(n_proc), int(unreadable), int(n_alerts), float(seconds), device_id)


def upsert_device(conn, device_id, name, platform, token_hash, user_id):
    now = time.time()
    conn.execute("""INSERT INTO devices(device_id,name,platform,token_hash,user_id,created,last_seen)
                    VALUES(?,?,?,?,?,?,?)
                    ON CONFLICT(device_id) DO UPDATE SET name=excluded.name, platform=excluded.platform,
                    token_hash=excluded.token_hash, user_id=excluded.user_id, last_seen=excluded.last_seen""",
                 (device_id, name, platform, token_hash, user_id, now, now))
    conn.commit()


def get_device_by_token(conn, token_hash):
    return conn.execute("SELECT * FROM devices WHERE token_hash=?", (token_hash,)).fetchone()


def list_devices(conn, user_id):
    return conn.execute("SELECT device_id,name,platform,last_seen FROM devices WHERE user_id=? "
                        "ORDER BY name COLLATE NOCASE", (user_id,)).fetchall()


def prune(conn, days=None):
    """Delete scan/event history older than the retention window (alerts are kept as evidence)."""
    cutoff = time.time() - 86400 * (days or config.RETENTION_DAYS)
    conn.execute("DELETE FROM scans WHERE ts<?", (cutoff,))
    conn.execute("DELETE FROM events WHERE ts<?", (cutoff,))


def user_count(conn):
    return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create_user(conn, username, pw_hash):
    """First account becomes admin. Returns False if the username is taken."""
    role = "admin" if user_count(conn) == 0 else "analyst"
    try:
        conn.execute("INSERT INTO users(username,pw_hash,role,created) VALUES(?,?,?,?)",
                     (username, pw_hash, role, time.time()))
        log_event(conn, "user_created", f"{username} ({role})")
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def get_user(conn, username):
    return conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
