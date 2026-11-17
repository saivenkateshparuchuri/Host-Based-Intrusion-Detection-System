import config
from storage import db
import scanner
from web.app import create_app


def make_client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "SECRET_PATH", str(tmp_path / "k"))
    monkeypatch.setattr(config, "ALLOW_REGISTRATION", True)   # default is closed; tests open it explicitly
    app = create_app(start_scanner=False)
    return app.test_client()


def register(client, user="alice", pw="s3cretpass", confirm=None):
    with client.session_transaction() as s:
        s["csrf"] = "tok"
    return client.post("/register", data={"username": user, "password": pw,
                                          "confirm": confirm or pw, "csrf_token": "tok"})


def test_scan_and_dashboard(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    conn = db.connect()
    procs, _ = scanner.run_scan(conn)
    assert len(procs) > 0                                   # process inventory loads
    conn.close()
    assert register(client).status_code == 302               # first account, auto sign-in
    for url in ("/", "/alerts", "/processes", "/export.csv", "/api/overview"):
        assert client.get(url).status_code == 200
    assert client.get("/alert/99999").status_code == 404    # invalid input handled


def test_updating_missing_alert_returns_404(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    register(client)
    with client.session_transaction() as s:
        tok = s["csrf"]
    r = client.post("/alert/99999", data={"status": "Confirmed", "csrf_token": tok})
    assert r.status_code == 404


def test_registration_closed_by_default(tmp_path, monkeypatch):
    import config
    client = make_client(tmp_path, monkeypatch)
    register(client)                                         # first account always allowed
    monkeypatch.setattr(config, "ALLOW_REGISTRATION", False)
    with client.session_transaction() as s:
        s.clear(); s["csrf"] = "t"
    assert client.post("/register", data={"username": "eve", "password": "s3cretpass",
                                          "confirm": "s3cretpass", "csrf_token": "t"}).status_code == 403


def test_history_pruning_keeps_alerts(tmp_path, monkeypatch):
    import time, config
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "p.db"))
    conn = db.connect()
    old = time.time() - 90 * 86400
    conn.execute("INSERT INTO scans(ts,processes,unreadable,alerts,seconds) VALUES(?,?,?,?,?)", (old, 1, 0, 0, 0.1))
    conn.execute("INSERT INTO events(ts,kind,detail) VALUES(?,?,?)", (old, "x", "y"))
    conn.execute("INSERT INTO alerts(key,severity,score,subject,reasons,first_seen,last_seen) VALUES('k','Low',1,'s','[]',?,?)", (old, old))
    db.prune(conn)
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
