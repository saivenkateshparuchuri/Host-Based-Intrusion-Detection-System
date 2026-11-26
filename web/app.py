import csv
import io
import json
import re
import os
import sys
import psutil
import secrets
import hashlib
from collections import Counter
import threading
from urllib.parse import urlsplit
import time
from flask import Flask, render_template, request, redirect, url_for, Response, session, flash, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
import config
import scanner
from storage import db
from sensors import process_sensor, persistence_sensor

_state = {"procs": [], "last_scan": 0.0}
_failures = {}      # (username, ip) -> [timestamps of recent failed logins]
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PUBLIC_ENDPOINTS = {"login", "register", "static", "agent_register", "agent_ingest"}


def _secret_key():
    """Persistent random key so sessions survive restarts. File is private (0600)."""
    if not os.path.exists(config.SECRET_PATH):
        fd = os.open(config.SECRET_PATH, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secrets.token_hex(32))
    return open(config.SECRET_PATH).read().strip()


def _locked(username, ip):
    now = time.time()
    hits = [t for t in _failures.get((username.lower(), ip), []) if now - t < config.LOGIN_LOCK_SECONDS]
    _failures[(username.lower(), ip)] = hits
    return len(hits) >= config.MAX_LOGIN_FAILURES


def _safe_next(target):
    return target if target and target.startswith("/") and not target.startswith("//") else url_for("index")


def _scan_loop(stop):
    conn = db.connect()
    while not stop.is_set():
        try:
            procs, _ = scanner.run_scan(conn)
            _state["procs"], _state["last_scan"] = procs, time.time()
        except Exception as exc:                      # keep monitoring alive
            db.log_event(conn, "scan_error", str(exc)); conn.commit()
        stop.wait(config.SCAN_INTERVAL_SECONDS)


def create_app(start_scanner=True):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=_secret_key(), SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=8 * 3600)
    db.connect().close()
    if start_scanner:
        stop = threading.Event()
        threading.Thread(target=_scan_loop, args=(stop,), daemon=True).start()

    def q(sql, args=()):
        conn = db.connect()
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    def current_user_id():
        if "user" not in session:
            return None
        rows = q("SELECT id FROM users WHERE username=?", (session["user"],))
        return rows[0]["id"] if rows else None

    def owned_device_ids():
        conn = db.connect()
        try:
            return {row["device_id"] for row in db.list_devices(conn, current_user_id())}
        finally:
            conn.close()

    @app.template_filter("ts")
    def fmt_ts(v):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(v)) if v else "-"

    app.jinja_env.filters["fromjson"] = json.loads

    # ---------- authentication ----------
    @app.before_request
    def require_login():
        if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
            pass
        elif "user" not in session:
            if request.path.startswith("/api/"):
                return jsonify(error="login required"), 401
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        if request.method == "POST" and request.endpoint not in {"agent_register", "agent_ingest"}:
                                                                            # CSRF check on browser POSTs
            sent = request.form.get("csrf_token", "")
            if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
                return "Invalid or missing CSRF token. Go back, refresh the page and try again.", 400

    @app.context_processor
    def inject_user():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return {"csrf_token": session["csrf"], "current_user": session.get("user"),
                "role": session.get("role"), "can_register": config.ALLOW_REGISTRATION}

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def _start_session(user):
        session.clear()
        session.permanent = True
        session["user"], session["role"] = user["username"], user["role"]
        session["csrf"] = secrets.token_hex(16)

    @app.route("/api/agent/register", methods=["POST"])
    def agent_register():
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", "")).strip()
        password = payload.get("password", "")
        device_id = str(payload.get("device_id", "")).strip()
        name = str(payload.get("name", "")).strip()[:100]
        platform = str(payload.get("platform", "unknown")).strip()[:40]
        if not username or not isinstance(password, str) or not re.fullmatch(
                r"[A-Za-z0-9_.:-]{1,100}", device_id) or not name:
            return jsonify(error="username, password, device_id, and name are required"), 400
        conn = db.connect()
        try:
            user = db.get_user(conn, username)
            if not user or not check_password_hash(user["pw_hash"], password):
                return jsonify(error="invalid credentials"), 401
            token = secrets.token_urlsafe(32)
            db.upsert_device(conn, device_id, name, platform,
                             hashlib.sha256(token.encode()).hexdigest(), user["id"])
            return jsonify(device_id=device_id, token=token)
        finally:
            conn.close()

    @app.route("/api/agent/scan", methods=["POST"])
    def agent_ingest():
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify(error="bearer token required"), 401
        token = auth[7:].strip()
        payload = request.get_json(silent=True) or {}
        device_id = str(payload.get("device_id", "")).strip()
        conn = db.connect()
        try:
            device = db.get_device_by_token(conn, hashlib.sha256(token.encode()).hexdigest())
            if not device or device["device_id"] != device_id:
                return jsonify(error="invalid device token"), 401
            alerts = payload.get("alerts", [])
            if not isinstance(alerts, list) or len(alerts) > 500:
                return jsonify(error="alerts must be a list of at most 500 items"), 400
            db.save_remote_scan(conn, device_id, alerts, payload.get("processes", 0),
                                payload.get("unreadable", 0), payload.get("alert_count", len(alerts)),
                                payload.get("seconds", 0))
            conn.execute("UPDATE devices SET last_seen=?, name=?, platform=? WHERE device_id=?",
                         (time.time(), str(payload.get("name", device["name"]))[:100],
                          str(payload.get("platform", device["platform"]))[:40], device_id))
            conn.commit()
            return jsonify(ok=True)
        except (TypeError, ValueError):
            return jsonify(error="invalid scan values"), 400
        finally:
            conn.close()

    @app.route("/api/devices")
    def devices():
        conn = db.connect()
        try:
            rows = db.list_devices(conn, current_user_id())
            return jsonify(devices=[dict(row) for row in rows])
        finally:
            conn.close()

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            ip = request.remote_addr or "?"
            conn = db.connect()
            try:
                if _locked(username, ip):
                    error = "Too many failed attempts. Try again in a few minutes."
                else:
                    user = db.get_user(conn, username)
                    if user and check_password_hash(user["pw_hash"], password):
                        _failures.pop((username.lower(), ip), None)
                        db.log_event(conn, "login", username); conn.commit()
                        _start_session(user)
                        return redirect(_safe_next(request.args.get("next")))
                    _failures.setdefault((username.lower(), ip), []).append(time.time())
                    db.log_event(conn, "login_failed", f"{username} from {ip}"); conn.commit()
                    error = "Invalid username or password."
            finally:
                conn.close()
        conn = db.connect(); n = db.user_count(conn); conn.close()
        return render_template("login.html", error=error, first_run=(n == 0),
                               username=request.form.get("username", "")), (401 if error else 200)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        conn = db.connect()
        try:
            first = db.user_count(conn) == 0
            if not config.ALLOW_REGISTRATION and not first:
                return render_template("register.html", error="Registration is disabled.", disabled=True), 403
            error = None
            if request.method == "POST":
                username = request.form.get("username", "").strip()
                pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
                if not USERNAME_RE.match(username):
                    error = "Username must be 3-32 characters: letters, numbers, dot, dash or underscore."
                elif len(pw) < config.MIN_PASSWORD_LENGTH:
                    error = f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters."
                elif pw != pw2:
                    error = "Passwords do not match."
                elif not db.create_user(conn, username, generate_password_hash(pw)):
                    error = "That username is already taken."
                else:
                    _start_session(db.get_user(conn, username))
                    return redirect(url_for("index"))
            return render_template("register.html", error=error, first_run=first,
                                   username=request.form.get("username", "")), (400 if error else 200)
        finally:
            conn.close()

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/api/overview")
    def api_overview():
        rng = request.args.get("range", "24h")
        now = time.time()
        sev = {r["severity"]: r["n"] for r in q(
            "SELECT severity, COUNT(*) n FROM alerts WHERE status!='Dismissed' GROUP BY severity")}
        hi, me, lo = sev.get("High", 0), sev.get("Medium", 0), sev.get("Low", 0)
        scans = list(reversed(q("SELECT * FROM scans ORDER BY id DESC LIMIT 30")))
        last = scans[-1] if scans else None
        # security posture: simple, explainable score out of 100
        posture = max(0, 100 - 15 * hi - 6 * me - 2 * lo)
        label = "Strong" if posture >= 80 else ("Fair" if posture >= 50 else "At risk")
        visibility = 100.0
        if last and last["processes"]:
            visibility = round(100 * (1 - last["unreadable"] / last["processes"]), 1)
        # alerts per rule (parse "[RULE_ID]" tags from stored reasons)
        rules = Counter()
        for r in q("SELECT reasons FROM alerts WHERE status!='Dismissed'"):
            for reason in json.loads(r["reasons"]):
                m = re.match(r"\[([A-Z_]+)\]", reason)
                if m:
                    rules[m.group(1)] += 1
        # timeline buckets by severity
        buckets, span = (24, 3600) if rng == "24h" else (7, 86400)
        start = now - buckets * span
        tl = {k: [0] * buckets for k in ("High", "Medium", "Low")}
        for r in q("SELECT severity, first_seen FROM alerts WHERE first_seen>=?", (start,)):
            i = min(buckets - 1, int((r["first_seen"] - start) // span))
            tl[r["severity"]][i] += 1
        recent = [{"id": r["id"], "subject": r["subject"], "severity": r["severity"], "pid": r["pid"],
                   "ts": r["last_seen"], "status": r["status"]}
                  for r in q("SELECT * FROM alerts ORDER BY last_seen DESC LIMIT 5")]
        avg_scan = round(sum(s_["seconds"] for s_ in scans) / len(scans), 3) if scans else 0
        open_n = q("SELECT COUNT(*) n FROM alerts WHERE status IN ('New','Investigating')")[0]["n"]
        return {
            "counts": {"High": hi, "Medium": me, "Low": lo, "All": hi + me + lo},
            "posture": posture, "posture_label": label, "visibility": visibility,
            "scans": [{"alerts": s_["alerts"], "processes": s_["processes"],
                       "unreadable": s_["unreadable"], "seconds": s_["seconds"]} for s_ in scans],
            "last_scan": last["ts"] if last else None, "processes": last["processes"] if last else 0,
            "unreadable": last["unreadable"] if last else 0,
            "rules": dict(rules), "timeline": tl, "range": rng, "recent": recent,
            "events": q("SELECT COUNT(*) n FROM events")[0]["n"], "avg_scan": avg_scan,
            "open_alerts": open_n, "platform": sys.platform, "interval": config.SCAN_INTERVAL_SECONDS,
            "trusted": len(config.TRUSTED_INPUT_PROCESSES), "rule_count": len(config.RULE_POINTS),
            "macos_event_taps": process_sensor.get_macos_audit_status(),
        }

    @app.route("/api/dashboard/analytics")
    def dashboard_analytics():
        """Time-scoped dashboard analytics from real SQLite alert and scan records.

        Counts represent distinct alert records first observed in the selected
        period, not repeated detections or unverified malware infections.
        """
        periods = {"24h": (24, 3600), "3d": (3, 86400),
                   "7d": (7, 86400), "30d": (30, 86400)}
        selected = request.args.get("range", "3d")
        if selected not in periods:
            selected = "3d"
        n_buckets, step = periods[selected]
        now = time.time()
        start = now - n_buckets * step
        device_id = request.args.get("device_id", "").strip()
        if device_id:
            if device_id not in owned_device_ids():
                return jsonify(error="unknown device"), 404
        device_sql = " AND device_id=?" if device_id else ""
        device_args = (device_id,) if device_id else ()
        series = {name: [0] * n_buckets for name in
                  ("Total", "High", "Medium", "Low", "Open", "InputTap", "Persistence", "Scans")}
        severity = {name: 0 for name in ("High", "Medium", "Low")}
        rule_counts = Counter()
        subjects = Counter()
        recent = []
        rows = q("""SELECT id, severity, subject, pid, reasons, status, first_seen, last_seen
                    FROM alerts WHERE (last_seen>=? OR first_seen>=?)""" + device_sql + " ORDER BY last_seen DESC",
                    (start, start) + device_args)
        open_statuses = {"New", "Investigating", "Confirmed"}
        input_taps = 0
        persistence = 0
        open_count = 0
        for row in rows:
            t = row["last_seen"] if row["last_seen"] >= start else row["first_seen"]
            index = max(0, min(n_buckets - 1, int((t - start) // step)))
            series["Total"][index] += 1
            sev = row["severity"]
            if sev in severity:
                severity[sev] += 1
                series[sev][index] += 1
            if row["status"] in open_statuses:
                open_count += 1
                series["Open"][index] += 1
            try:
                reasons = json.loads(row["reasons"] or "[]")
                if not isinstance(reasons, list):
                    reasons = []
            except (ValueError, TypeError):
                reasons = []
            rule_ids = set()
            for reason in reasons:
                if not isinstance(reason, str):
                    continue
                match = re.match(r"\[([A-Z0-9_]+)\]", reason)
                if match:
                    rule_ids.add(match.group(1))
            for rule_id in rule_ids:  # one count per rule per alert
                rule_counts[rule_id] += 1
            if "MACOS_KEYBOARD_EVENT_TAP" in rule_ids or "OPENS_INPUT_DEVICE" in rule_ids:
                input_taps += 1
                series["InputTap"][index] += 1
            if any(rule.startswith("PERSISTENCE_") or rule == "NEW_STARTUP_ENTRY"
                   for rule in rule_ids):
                persistence += 1
                series["Persistence"][index] += 1
            subjects[row["subject"] or "Unknown"] += 1
            if len(recent) < 6:
                recent.append({"id": row["id"], "severity": sev,
                               "subject": row["subject"], "pid": row["pid"],
                               "status": row["status"], "last_seen": row["last_seen"]})

        # Aggregate scans inside SQLite, rather than transferring a large scan log.
        scan_counts = q("""SELECT CAST((ts - ?) / ? AS INTEGER) AS bucket, COUNT(*) AS n
                           FROM scans WHERE ts>=? AND ts<=?""" + device_sql + """
                           GROUP BY bucket""", (start, step, start, now) + device_args)
        scan_count = 0
        for r in scan_counts:
            i = r["bucket"]
            if i is not None and 0 <= i < n_buckets:
                series["Scans"][i] = r["n"]
                scan_count += r["n"]
        last = q("SELECT ts, processes, unreadable FROM scans WHERE 1=1" + device_sql +
                 " ORDER BY id DESC LIMIT 1", device_args)
        last = last[0] if last else None
        visibility = (round(100 * (1 - last["unreadable"] / last["processes"]), 1)
                      if last and last["processes"] else None)
        return jsonify({
            "range": selected, "generated_at": now,
            "buckets": [start + i * step for i in range(n_buckets)],
            "series": series,
            "stats": {"total": len(rows), "high": severity["High"],
                      "medium": severity["Medium"], "low": severity["Low"],
                      "open": open_count, "input_taps": input_taps,
                      "persistence": persistence, "scans": scan_count,
                      "visibility": visibility},
            "rules": [{"name": rule, "count": n} for rule, n in rule_counts.most_common(5)],
            "top_subjects": [{"name": name, "count": n} for name, n in subjects.most_common(5)],
            "recent": recent, "last_scan": last["ts"] if last else None, "device_id": device_id,
            "sensors": {"process": bool(last), "persistence": bool(last),
                        "input": process_sensor.get_macos_audit_status() if sys.platform == "darwin" else None,
                        "rule_count": len(config.RULE_POINTS), "platform": sys.platform}
        })

    @app.route("/")
    def index():
        counts = {r["severity"]: r["n"] for r in q(
            "SELECT severity, COUNT(*) n FROM alerts WHERE status!='Dismissed' GROUP BY severity")}
        scan = q("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
        events = q("SELECT * FROM events ORDER BY id DESC LIMIT 10")
        return render_template("index.html", counts=counts, scan=scan[0] if scan else None,
                               events=events)

    @app.route("/alerts")
    def alerts():
        sev = request.args.get("severity", "")
        mode = request.args.get("mode", "active")
        now = time.time()

        sql = "SELECT * FROM alerts"
        conditions = []
        args = []
        if sev in ("Low", "Medium", "High"):
            conditions.append("severity=?")
            args.append(sev)
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY last_seen DESC LIMIT 300"

        raw_rows = q(sql, tuple(args))
        rows = []
        active_count = 0
        total_count = len(raw_rows)

        for r in raw_rows:
            r_dict = dict(r)
            pid = r_dict.get("pid")
            is_alive = False
            if pid:
                try:
                    p = psutil.Process(pid)
                    is_alive = p.is_running() and p.status() != psutil.STATUS_ZOMBIE
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    is_alive = False

            recently_seen = (now - r_dict["last_seen"]) < 600
            is_active = (is_alive or recently_seen) and r_dict.get("status") != "Dismissed"
            r_dict["is_running"] = is_alive
            r_dict["is_active"] = is_active

            if is_active:
                active_count += 1

            if mode == "active":
                if is_active:
                    rows.append(r_dict)
            else:
                rows.append(r_dict)

        return render_template("alerts.html", rows=rows, sev=sev, mode=mode,
                               active_count=active_count, total_count=total_count)

    @app.route("/alerts/cleanup-inactive", methods=["POST"])
    def cleanup_inactive_alerts():
        now = time.time()
        conn = db.connect()
        try:
            alerts = conn.execute("SELECT id, pid, last_seen, status FROM alerts WHERE status != 'Dismissed'").fetchall()
            dismissed_n = 0
            for a in alerts:
                pid = a["pid"]
                is_alive = False
                if pid:
                    try:
                        p = psutil.Process(pid)
                        is_alive = p.is_running() and p.status() != psutil.STATUS_ZOMBIE
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        is_alive = False
                recently_seen = (now - a["last_seen"]) < 600
                if not is_alive and not recently_seen:
                    conn.execute("UPDATE alerts SET status='Dismissed', note='Auto-dismissed: Process no longer active on host.' WHERE id=?", (a["id"],))
                    dismissed_n += 1
            conn.commit()
            flash(f"Cleaned up {dismissed_n} inactive/older alerts.")
        finally:
            conn.close()
        return redirect(url_for("alerts", mode="active"))

    @app.route("/alert/<int:aid>", methods=["GET", "POST"])
    def alert(aid):
        if request.method == "POST":
            status = request.form.get("status", "New")
            if status not in ("New", "Investigating", "False positive", "Confirmed", "Dismissed"):
                status = "New"
            conn = db.connect()
            try:
                cur = conn.execute("UPDATE alerts SET status=?, note=? WHERE id=?",
                                   (status, request.form.get("note", "")[:1000], aid))
                conn.commit()
            finally:
                conn.close()
            if cur.rowcount == 0:
                return "Alert not found", 404
            return redirect(url_for("alert", aid=aid))
        rows = q("SELECT * FROM alerts WHERE id=?", (aid,))
        if not rows:
            return "Alert not found", 404
        r = rows[0]
        return render_template("alert.html", a=r, reasons=json.loads(r["reasons"]))

    @app.route("/processes")
    def processes():
        procs = sorted(_state["procs"], key=lambda p: p.name.lower())
        return render_template("processes.html", procs=procs, last=_state["last_scan"])

    @app.route("/scan", methods=["POST"])
    def scan_now():
        conn = db.connect()
        try:
            procs, _ = scanner.run_scan(conn)
            _state["procs"], _state["last_scan"] = procs, time.time()
        except Exception as exc:
            db.log_event(conn, "scan_error", str(exc)); conn.commit()
            flash("Scan failed; see the event log.")
        finally:
            conn.close()
        return redirect(_safe_next(urlsplit(request.referrer or "").path or None))

    @app.route("/alert/<int:aid>/kill", methods=["POST"])
    def alert_kill(aid):
        conn = db.connect()
        try:
            row = conn.execute("SELECT pid, subject FROM alerts WHERE id=?", (aid,)).fetchone()
            if not row:
                return "Alert not found", 404
            pid = row["pid"]
            force_dismiss = request.form.get("force_dismiss", "0") == "1"
            if force_dismiss:
                conn.execute("UPDATE alerts SET status='Dismissed', note=? WHERE id=?",
                             (f"Alert dismissed by analyst (PID {pid or 'N/A'}).", aid))
                conn.commit()
                flash(f"Alert #{aid} marked as Dismissed.")
                return redirect(url_for("alerts"))
            if not pid:
                flash("No process ID associated with this alert.")
                return redirect(url_for("alert", aid=aid))
            try:
                p = psutil.Process(pid)
                p.terminate()
                try:
                    p.wait(timeout=2)
                except psutil.TimeoutExpired:
                    p.kill()
                msg = f"Terminated process {row['subject']} (PID {pid}) and dismissed alert."
                conn.execute("UPDATE alerts SET status='Dismissed', note=? WHERE id=?",
                             (f"Process PID {pid} terminated via Incident Response action.", aid))
                db.log_event(conn, "process_kill", f"PID {pid} ({row['subject']}) killed for alert #{aid}")
                conn.commit()
                flash(msg)
            except psutil.NoSuchProcess:
                conn.execute("UPDATE alerts SET status='Dismissed', note=? WHERE id=?",
                             (f"Process PID {pid} was already stopped.", aid))
                conn.commit()
                flash(f"Process PID {pid} was already stopped. Alert marked Dismissed.")
            except psutil.AccessDenied:
                import subprocess
                try:
                    res = subprocess.run(["kill", "-9", str(pid)], capture_output=True, text=True)
                    if res.returncode == 0:
                        conn.execute("UPDATE alerts SET status='Dismissed', note=? WHERE id=?",
                                     (f"Process PID {pid} terminated via SIGKILL.", aid))
                        db.log_event(conn, "process_kill", f"PID {pid} ({row['subject']}) killed with SIGKILL for alert #{aid}")
                        conn.commit()
                        flash(f"Terminated process {row['subject']} (PID {pid}) via SIGKILL.")
                        return redirect(url_for("alert", aid=aid))
                except Exception:
                    pass
                flash(f"Permission denied for PID {pid}. This occurs for system-protected processes or when HIDS runs with standard user rights. You can click 'Dismiss Alert (Keep Process)' or run 'kill -9 {pid}' in Terminal.")
            except Exception as e:
                flash(f"Failed to terminate PID {pid}: {e}")
        finally:
            conn.close()
        return redirect(url_for("alert", aid=aid))

    @app.route("/rules")
    def detection_rules():
        rule_list = []
        for rid, pts in config.RULE_POINTS.items():
            mitre = config.RULE_MITRE.get(rid, "-")
            desc = config.RULE_DESCRIPTIONS.get(rid, "")
            sev = "High" if pts >= config.HIGH_AT else ("Medium" if pts >= config.MEDIUM_AT else "Low")
            rule_list.append({
                "id": rid,
                "points": pts,
                "severity": sev,
                "mitre": mitre,
                "description": desc,
            })
        return render_template("rules.html", rules=rule_list)

    @app.route("/persistence")
    def persistence():
        try:
            raw_entries = persistence_sensor.collect()
        except Exception:
            raw_entries = []
        entries = []
        for e in raw_entries:
            target = e.target or ""
            target_lower = target.lower()
            is_suspicious = any(target_lower.startswith(prefix) for prefix in config.SUSPICIOUS_EXEC_PREFIXES)
            entries.append({
                "source": e.source,
                "name": e.name,
                "path": e.path,
                "target": target,
                "mtime": e.mtime,
                "is_suspicious": is_suspicious,
            })
        return render_template("persistence.html", entries=entries, count=len(entries))

    @app.route("/export.csv")
    def export():
        rows = q("SELECT * FROM alerts ORDER BY id")
        out = io.StringIO(); w = csv.writer(out)
        w.writerow(["id", "severity", "score", "subject", "pid", "path", "reasons",
                    "first_seen", "last_seen", "count", "status", "note"])
        for r in rows:
            w.writerow([r["id"], r["severity"], r["score"], r["subject"], r["pid"], r["path"],
                        " | ".join(json.loads(r["reasons"])), fmt_ts(r["first_seen"]),
                        fmt_ts(r["last_seen"]), r["count"], r["status"], r["note"]])
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=hids_alerts.csv"})

    return app
