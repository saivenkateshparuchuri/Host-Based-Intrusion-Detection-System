"""Regression checks for the new user interface and time-scoped analytics."""
import json
import time
import config
from storage import db
from web.app import create_app
from werkzeug.security import generate_password_hash


def test_time_scoped_dashboard_has_real_counts_and_assets(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "dashboard.db"))
    monkeypatch.setattr(config, "SECRET_PATH", str(tmp_path / "secret"))
    app = create_app(start_scanner=False)
    client = app.test_client()
    connection = db.connect()
    assert db.create_user(connection, "tester", generate_password_hash("safepass123"))
    now = time.time()
    connection.execute("""INSERT INTO alerts(key,severity,score,subject,pid,path,reasons,first_seen,last_seen,status)
                          VALUES (?,?,?,?,?,?,?,?,?,?)""",
                       ("test-one", "High", 5, "Safe-test", 100, "/tmp/safe-test",
                        json.dumps(["[EXEC_IN_TEMP] harmless test activity",
                                    "[MACOS_KEYBOARD_EVENT_TAP] event-tap metadata"]), now, now, "New"))
    connection.execute("""INSERT INTO alerts(key,severity,score,subject,pid,path,reasons,first_seen,last_seen,status)
                          VALUES (?,?,?,?,?,?,?,?,?,?)""",
                       ("test-two", "Medium", 3, "Startup-test", None, "/tmp/safe-startup",
                        json.dumps(["[PERSISTENCE_TARGET_SUSPICIOUS] test startup"]), now, now,
                        "Investigating"))
    connection.execute("INSERT INTO scans(ts,processes,unreadable,alerts,seconds) VALUES(?,?,?,?,?)",
                       (now, 100, 5, 2, 0.1))
    connection.commit()
    connection.close()

    with client.session_transaction() as sess:
        sess["user"] = "tester"
        sess["role"] = "admin"
        sess["csrf"] = "testcsrf"
    page = client.get("/")
    assert page.status_code == 200
    assert b"HIDS Guard" in page.data
    assert b"Top 5 Detection Rules" in page.data
    assert client.get("/static/dashboard_v2.css").status_code == 200
    assert client.get("/static/dashboard_v2.js").status_code == 200
    out = client.get("/api/dashboard/analytics?range=3d")
    assert out.status_code == 200
    data = out.get_json()
    assert data["stats"]["total"] == 2
    assert data["stats"]["high"] == 1
    assert data["stats"]["medium"] == 1
    assert data["stats"]["open"] == 2
    assert data["stats"]["input_taps"] == 1
    assert data["stats"]["persistence"] == 1
    assert data["stats"]["scans"] >= 1
    assert data["stats"]["visibility"] == 95.0
    assert len(data["buckets"]) == 3
    assert sum(data["series"]["Total"]) == 2
    assert client.get("/alerts").status_code == 200
    assert client.get("/processes").status_code == 200
    assert client.get("/export.csv").status_code == 200
    assert len(client.get("/api/dashboard/analytics?range=24h").get_json()["buckets"]) == 24
