from tests.test_app import make_client, register
from storage import db


def test_pages_require_login(tmp_path, monkeypatch):
    c = make_client(tmp_path, monkeypatch)
    for url in ("/", "/alerts", "/processes", "/export.csv"):
        r = c.get(url)
        assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert c.get("/api/overview").status_code == 401
    assert c.get("/login").status_code == 200


def test_register_login_logout_flow(tmp_path, monkeypatch):
    c = make_client(tmp_path, monkeypatch)
    assert register(c, "alice", "s3cretpass").status_code == 302
    conn = db.connect()
    assert db.get_user(conn, "alice")["role"] == "admin"        # first user is admin
    assert db.get_user(conn, "alice")["pw_hash"] != "s3cretpass"  # stored hashed
    conn.close()
    with c.session_transaction() as s:
        tok = s["csrf"]
    assert c.post("/logout", data={"csrf_token": tok}).status_code == 302
    assert c.get("/").status_code == 302                         # signed out
    c.get("/login")                                              # page load issues a fresh CSRF token
    with c.session_transaction() as s:
        tok = s["csrf"]
    r = c.post("/login", data={"username": "ALICE", "password": "s3cretpass", "csrf_token": tok})
    assert r.status_code == 302                                  # case-insensitive username


def test_bad_password_and_validation(tmp_path, monkeypatch):
    c = make_client(tmp_path, monkeypatch)
    assert register(c, "alice", "short").status_code == 400
    assert register(c, "alice", "s3cretpass", "different").status_code == 400
    assert register(c, "a b", "s3cretpass").status_code == 400
    register(c, "alice", "s3cretpass")
    with c.session_transaction() as s:
        s.clear(); s["csrf"] = "t"
    assert c.post("/login", data={"username": "alice", "password": "wrong", "csrf_token": "t"}).status_code == 401
    assert register(c, "alice", "s3cretpass").status_code == 400  # duplicate username


def test_csrf_required(tmp_path, monkeypatch):
    c = make_client(tmp_path, monkeypatch)
    assert c.post("/register", data={"username": "bob", "password": "s3cretpass",
                                     "confirm": "s3cretpass"}).status_code == 400


def test_lockout_after_repeated_failures(tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "MAX_LOGIN_FAILURES", 3)
    c = make_client(tmp_path, monkeypatch)
    register(c, "alice", "s3cretpass")
    with c.session_transaction() as s:
        s.clear(); s["csrf"] = "t"
    for _ in range(3):
        c.post("/login", data={"username": "alice", "password": "bad", "csrf_token": "t"})
    r = c.post("/login", data={"username": "alice", "password": "s3cretpass", "csrf_token": "t"})
    assert r.status_code == 401 and b"Too many" in r.data


def test_open_redirect_blocked(tmp_path, monkeypatch):
    c = make_client(tmp_path, monkeypatch)
    register(c, "alice", "s3cretpass")
    with c.session_transaction() as s:
        s.clear(); s["csrf"] = "t"
    r = c.post("/login?next=//evil.com", data={"username": "alice", "password": "s3cretpass", "csrf_token": "t"})
    assert r.status_code == 302 and "evil.com" not in r.headers["Location"]


def test_registration_can_be_disabled(tmp_path, monkeypatch):
    import config
    c = make_client(tmp_path, monkeypatch)
    register(c, "alice", "s3cretpass")                           # first account always allowed
    monkeypatch.setattr(config, "ALLOW_REGISTRATION", False)
    with c.session_transaction() as s:
        s.clear(); s["csrf"] = "t"
    assert c.get("/register").status_code == 403
