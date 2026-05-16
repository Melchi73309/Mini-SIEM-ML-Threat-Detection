"""
app.py — Mini SIEM + ML Hybrid System (FINAL)

Integrations:
  - Rule-Based Detection (detection/rule_engine.py)
  - ML Detection using RandomForest model (model.pkl) via detection/ml_detector.py
  - Combined risk scoring (detection/risk_scoring.py)

Features:
  1. User registration and login with bcrypt hashing
  2. PIN-based two-factor authentication
  3. Per-user data isolation (all alerts scoped to user_id)
  4. Max 3 accounts per email address
  5. Login lockout after 5 failed attempts (15 min)
  6. Manual event input with ML + rule-based risk prediction
  7. Log file upload (.txt) with ML analysis on each entry
  8. Real-time file monitoring (logs/sample.log)
  9. Simulated event API for dashboard live feed
  10. Geo IP map visualization
  11. Chart data API for dashboard charts

Run: python app.py
"""

from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
import bcrypt
import time
import os
import random
import json
import threading
from datetime import datetime

from detection.log_parser   import parse_line, parse_log_content
from detection.risk_scoring import calculate_risk

app = Flask(__name__)
app.secret_key = "mini_siem_hybrid_ml_secret_2024"

app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = "Lax",
    PERMANENT_SESSION_LIFETIME = 3600,
)

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "database", "users.db")
LOGS_DIR   = os.path.join(BASE_DIR, "logs")
SAMPLE_LOG = os.path.join(LOGS_DIR, "sample.log")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")


# ===========================================================================
# STARTUP: Verify ML model is available
# ===========================================================================

def check_ml_model():
    if os.path.exists(MODEL_PATH):
        try:
            import joblib
            m = joblib.load(MODEL_PATH)
            feats = getattr(m, "n_features_in_", "?")
            print(f"[ML] model.pkl loaded OK — {feats} features")
        except Exception as e:
            print(f"[ML] WARNING: model.pkl found but failed to load: {e}")
    else:
        print(f"[ML] WARNING: model.pkl not found at {MODEL_PATH} — rule-based fallback active")


# ===========================================================================
# DATABASE
# ===========================================================================

def init_db():
    os.makedirs(os.path.join(BASE_DIR, "database"), exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    UNIQUE NOT NULL,
            email      TEXT    NOT NULL,
            phone      TEXT,
            password   TEXT    NOT NULL,
            pin        TEXT    NOT NULL,
            created_at TEXT    DEFAULT (datetime('now'))
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            time        TEXT    DEFAULT (datetime('now')),
            ip          TEXT,
            event       TEXT,
            attack_type TEXT,
            risk        TEXT,
            score       INTEGER DEFAULT 0,
            attempts    INTEGER DEFAULT 0,
            failed      INTEGER DEFAULT 0,
            ml_used     INTEGER DEFAULT 0,
            ml_label    INTEGER,
            source      TEXT    DEFAULT 'manual'
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            username      TEXT    PRIMARY KEY,
            attempt_count INTEGER DEFAULT 0,
            last_attempt  REAL
        )
    """)

    conn.commit()
    conn.close()

    if not os.path.exists(SAMPLE_LOG):
        sample_content = """[2024-01-15 08:01:00] 192.168.1.100 Failed SSH login attempt from unknown host
[2024-01-15 08:01:10] 192.168.1.100 Failed SSH login attempt from unknown host
[2024-01-15 08:02:00] 45.33.32.156 Brute force attack detected - multiple retries
[2024-01-15 08:02:30] 10.0.0.55 Normal web request GET /index.html 200
[2024-01-15 08:03:00] 203.0.113.42 Unauthorized API access token rejected
[2024-01-15 08:03:15] 198.51.100.7 SQL injection attempt detected in form field
[2024-01-15 08:04:00] 8.8.8.8 DNS lookup successful normal activity
"""
        with open(SAMPLE_LOG, "w") as f:
            f.write(sample_content)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_ip_fail_count(conn, ip: str, user_id: int) -> int:
    """Count failed events for a given IP belonging to this user."""
    if not ip or ip in ("0.0.0.0", "N/A"):
        return 0
    row = conn.execute(
        """SELECT COUNT(*) as cnt FROM alerts
           WHERE user_id=? AND ip=?
             AND (event LIKE '%fail%' OR event LIKE '%denied%'
                  OR event LIKE '%invalid%' OR event LIKE '%unauthorized%'
                  OR failed > 0)""",
        (user_id, ip)
    ).fetchone()
    return row["cnt"] if row else 0


def get_current_user_id():
    return session.get("user_id")


# ===========================================================================
# HOME / LANDING
# ===========================================================================

@app.route("/")
def index():
    return render_template("home.html")


# ===========================================================================
# CHECK USERNAME
# ===========================================================================

@app.route("/check_username")
def check_username():
    username = request.args.get("username", "")
    conn = get_db()
    user = conn.execute(
        "SELECT id FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    return "Username already taken" if user else "Username available"


# ===========================================================================
# REGISTER
# ===========================================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect("/dashboard")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email",    "").strip()
        phone    = request.form.get("phone",    "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        pin      = request.form.get("pin", "")

        if not username or not email or not password or not pin:
            return render_template("register.html", message="All fields are required")
        if password != confirm:
            return render_template("register.html", message="Passwords do not match")
        if len(pin) < 4:
            return render_template("register.html", message="PIN must be at least 4 digits")

        conn = get_db()

        email_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM users WHERE email=?", (email,)
        ).fetchone()["cnt"]
        if email_count >= 3:
            conn.close()
            return render_template(
                "register.html",
                message="Maximum 3 accounts per email address already reached"
            )

        hashed_pw  = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        hashed_pin = bcrypt.hashpw(pin.encode(),      bcrypt.gensalt()).decode()

        try:
            conn.execute(
                "INSERT INTO users(username,email,phone,password,pin) VALUES(?,?,?,?,?)",
                (username, email, phone, hashed_pw, hashed_pin)
            )
            conn.commit()
            conn.close()
            return redirect("/login?registered=1")
        except Exception:
            conn.close()
            return render_template("register.html", message="Username already exists")

    return render_template("register.html")


# ===========================================================================
# LOGIN
# ===========================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect("/dashboard")

    message    = None
    registered = request.args.get("registered")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        pin      = request.form.get("pin", "")

        if not username or not password or not pin:
            return render_template("login.html", message="All fields are required")

        conn = get_db()
        now  = time.time()

        attempt = conn.execute(
            "SELECT * FROM login_attempts WHERE username=?", (username,)
        ).fetchone()

        if attempt and attempt["attempt_count"] >= 5 and (now - attempt["last_attempt"]) < 900:
            remaining = int((900 - (now - attempt["last_attempt"])) / 60) + 1
            conn.close()
            return render_template(
                "login.html",
                message=f"Account locked for {remaining} more minute(s) due to too many failed attempts"
            )

        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()

        if user and \
           bcrypt.checkpw(password.encode(), user["password"].encode()) and \
           bcrypt.checkpw(pin.encode(),      user["pin"].encode()):
            conn.execute("DELETE FROM login_attempts WHERE username=?", (username,))
            conn.commit()
            conn.close()
            session.permanent = False
            session["user_id"] = user["id"]
            session["user"]    = username
            return redirect("/welcome")

        if attempt:
            conn.execute(
                "UPDATE login_attempts SET attempt_count=attempt_count+1, last_attempt=? "
                "WHERE username=?",
                (now, username)
            )
        else:
            conn.execute(
                "INSERT INTO login_attempts(username,attempt_count,last_attempt) VALUES(?,1,?)",
                (username, now)
            )
        conn.commit()
        conn.close()

        if not user:
            message = "User not found"
        else:
            message = "Invalid credentials"

    return render_template("login.html", message=message, registered=registered)


# ===========================================================================
# WELCOME
# ===========================================================================

@app.route("/welcome")
def welcome():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("welcome.html", username=session["user"])


# ===========================================================================
# LOGOUT
# ===========================================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ===========================================================================
# DASHBOARD — USER-ISOLATED
# ===========================================================================

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    uid  = session["user_id"]
    conn = get_db()

    alerts = conn.execute(
        "SELECT * FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT 100", (uid,)
    ).fetchall()

    total    = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE user_id=?",                      (uid,)).fetchone()["c"]
    critical = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE user_id=? AND risk='CRITICAL'",  (uid,)).fetchone()["c"]
    high     = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE user_id=? AND risk='HIGH'",      (uid,)).fetchone()["c"]
    medium   = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE user_id=? AND risk='MEDIUM'",    (uid,)).fetchone()["c"]
    low      = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE user_id=? AND risk='LOW'",       (uid,)).fetchone()["c"]

    top_ip_row = conn.execute(
        "SELECT ip, COUNT(*) as cnt FROM alerts "
        "WHERE user_id=? AND ip IS NOT NULL AND ip != '' AND ip != 'N/A' "
        "GROUP BY ip ORDER BY cnt DESC LIMIT 1",
        (uid,)
    ).fetchone()

    top_attacker = {"ip": top_ip_row["ip"], "count": top_ip_row["cnt"]} if top_ip_row else None

    conn.close()

    return render_template(
        "dashboard.html",
        alerts=      [dict(a) for a in alerts],
        total=total, critical=critical,
        high=high,   medium=medium, low=low,
        top_attacker=top_attacker,
        username=session["user"]
    )


# ===========================================================================
# MANUAL DETECTION — ML + RULE BASED
# ===========================================================================

@app.route("/manual", methods=["GET", "POST"])
def manual():
    if "user_id" not in session:
        return redirect("/login")

    uid    = session["user_id"]
    result = None

    if request.method == "POST":
        ip        = (request.form.get("ip_address") or "").strip()
        raw_att   = request.form.get("attempts")  or "0"
        raw_fail  = request.form.get("failed")    or "0"
        ip_change = (request.form.get("ip_change") or "unknown").strip().lower()
        raw_hours = (request.form.get("hours")     or "").strip()

        # Step 4: Validation
        try:
            attempts = max(0, int(raw_att))
        except ValueError:
            attempts = 0

        try:
            failed = max(0, int(raw_fail))
        except ValueError:
            failed = 0

        if failed > attempts:
            failed = attempts

        if ip_change not in ("yes", "no", "unknown"):
            ip_change = "unknown"

        hours = None
        if raw_hours:
            try:
                hours = float(raw_hours)
                if hours < 0:
                    hours = None
            except ValueError:
                hours = None

        # Auto-generate a readable event summary (no free-text field)
        ip_change_label = ip_change.capitalize()
        event_parts = []
        if attempts:
            event_parts.append(f"{attempts} attempts ({failed} failed)")
        if ip_change == "yes":
            event_parts.append("IP change detected")
        if hours is not None:
            event_parts.append(f"window {hours}h")
        event = "Manual detection: " + (", ".join(event_parts) if event_parts else "no anomaly inputs")

        conn = get_db()
        repeated_ip   = bool(ip and conn.execute(
            "SELECT 1 FROM alerts WHERE user_id=? AND ip=? LIMIT 1", (uid, ip)
        ).fetchone())
        ip_fail_count = get_ip_fail_count(conn, ip, uid) if ip else 0

        detection = calculate_risk(
            attempts=attempts,
            failed=failed,
            event=event,
            repeated_ip=repeated_ip,
            ip_fail_count=ip_fail_count,
            ip_change=ip_change,
            hours=hours,
        )

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO alerts(user_id,time,ip,event,risk,attack_type,score,attempts,failed,ml_used,ml_label,source) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,'manual')",
            (uid, ts, ip or "N/A", event, detection["risk"],
             detection["attack_type"], detection["score"],
             attempts, failed,
             1 if detection.get("ml_used") else 0,
             detection.get("ml_label"))
        )
        conn.commit()
        conn.close()

        result = {
            "ip":          ip or "N/A",
            "event":       event,
            "attempts":    attempts,
            "failed":      failed,
            "ip_change":   ip_change_label,
            "hours":       hours,
            "risk":        detection["risk"],
            "attack_type": detection["attack_type"],
            "score":       detection["score"],
            "ml_used":     detection.get("ml_used", False),
            "ml_label":    detection.get("ml_label"),
            "timestamp":   ts,
        }

    return render_template("manual.html", result=result, username=session["user"])


# ===========================================================================
# LOG FILE UPLOAD — ML ON EACH ENTRY
# ===========================================================================

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect("/login")

    uid          = session["user_id"]
    message      = None
    parsed_count = 0
    errors       = []
    results      = []

    if request.method == "POST":
        if "logfile" not in request.files:
            return render_template("upload.html", error="No file selected", username=session["user"])

        f = request.files["logfile"]

        if not f or f.filename == "":
            return render_template("upload.html", error="No file selected", username=session["user"])

        if not f.filename.lower().endswith(".txt"):
            return render_template(
                "upload.html",
                error="Only .txt files are allowed. Please upload a valid text log file.",
                username=session["user"]
            )

        try:
            content = f.read().decode("utf-8", errors="ignore")
            events  = parse_log_content(content)

            conn = get_db()
            for ev in events:
                ip       = ev["ip"]
                event    = ev["event"]
                attempts = max(0, int(ev.get("attempts") or 0))
                failed_c = max(0, int(ev.get("failed")   or 0))
                if failed_c > attempts:
                    failed_c = attempts

                repeated_ip   = bool(conn.execute(
                    "SELECT 1 FROM alerts WHERE user_id=? AND ip=? LIMIT 1", (uid, ip)
                ).fetchone())
                ip_fail_count = get_ip_fail_count(conn, ip, uid)

                detection = calculate_risk(
                    attempts=attempts,
                    failed=failed_c,
                    event=event,
                    repeated_ip=repeated_ip,
                    ip_fail_count=ip_fail_count,
                )

                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                conn.execute(
                    "INSERT INTO alerts(user_id,time,ip,event,risk,attack_type,score,attempts,failed,ml_used,ml_label,source) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,'upload')",
                    (uid, ts, ip, event, detection["risk"],
                     detection["attack_type"], detection["score"],
                     attempts, failed_c,
                     1 if detection.get("ml_used") else 0,
                     detection.get("ml_label"))
                )
                parsed_count += 1
                results.append({
                    "ip":          ip,
                    "event":       event[:60],
                    "risk":        detection["risk"],
                    "attack_type": detection["attack_type"],
                    "score":       detection["score"],
                    "ml_used":     detection.get("ml_used", False),
                })

            conn.commit()
            conn.close()
            message = f"Successfully parsed and stored {parsed_count} log entries (ML analysis applied)."

        except Exception as e:
            errors.append(str(e))

    return render_template(
        "upload.html", message=message,
        parsed_count=parsed_count, errors=errors,
        results=results,
        username=session["user"]
    )


# ===========================================================================
# MONITORING — FILE-BASED (logs/sample.log)
# ===========================================================================

@app.route("/monitoring")
def monitoring():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("monitoring.html", username=session["user"])


@app.route("/api/monitor_file", methods=["POST"])
def monitor_file():
    """Read logs/sample.log and process all lines with ML for the current user."""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    uid = session["user_id"]

    if not os.path.exists(SAMPLE_LOG):
        return jsonify({"error": "logs/sample.log not found", "processed": 0}), 404

    try:
        with open(SAMPLE_LOG, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        events = parse_log_content(content)
        conn = get_db()
        processed = 0

        for ev in events:
            ip       = ev["ip"]
            event    = ev["event"]
            attempts = max(0, int(ev.get("attempts") or 0))
            failed_c = max(0, int(ev.get("failed")   or 0))
            if failed_c > attempts:
                failed_c = attempts

            repeated_ip   = bool(conn.execute(
                "SELECT 1 FROM alerts WHERE user_id=? AND ip=? LIMIT 1", (uid, ip)
            ).fetchone())
            ip_fail_count = get_ip_fail_count(conn, ip, uid)

            detection = calculate_risk(
                attempts=attempts, failed=failed_c,
                event=event,
                repeated_ip=repeated_ip,
                ip_fail_count=ip_fail_count,
            )

            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "INSERT INTO alerts(user_id,time,ip,event,risk,attack_type,score,attempts,failed,ml_used,ml_label,source) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,'monitor')",
                (uid, ts, ip, event, detection["risk"],
                 detection["attack_type"], detection["score"],
                 attempts, failed_c,
                 1 if detection.get("ml_used") else 0,
                 detection.get("ml_label"))
            )
            processed += 1

        conn.commit()
        conn.close()

        return jsonify({
            "success":   True,
            "processed": processed,
            "message":   f"Processed {processed} log entries from sample.log (ML applied)"
        })

    except Exception as e:
        return jsonify({"error": str(e), "processed": 0}), 500


# ===========================================================================
# GEO MAP — USER-ISOLATED
# ===========================================================================

@app.route("/map")
def geo_map():
    if "user_id" not in session:
        return redirect("/login")

    uid  = session["user_id"]
    conn = get_db()
    ips  = conn.execute(
        "SELECT ip, risk, COUNT(*) as cnt FROM alerts "
        "WHERE user_id=? AND ip IS NOT NULL AND ip != '0.0.0.0' AND ip != 'N/A' "
        "GROUP BY ip",
        (uid,)
    ).fetchall()
    conn.close()

    ip_data = [{"ip": r["ip"], "risk": r["risk"], "count": r["cnt"]} for r in ips]
    return render_template("map.html", ip_data=json.dumps(ip_data), username=session["user"])


# ===========================================================================
# API — REAL-TIME SIMULATION — ML APPLIED
# ===========================================================================

_SAMPLE_IPS = [
    "192.168.1.100", "10.0.0.55",    "172.16.0.200",
    "45.33.32.156",  "8.8.8.8",      "104.16.100.25",
    "203.0.113.42",  "198.51.100.7", "192.0.2.88",
]
_SAMPLE_EVENTS = [
    ("Failed SSH login attempt",          5, 3),
    ("Unauthorized API access rejected",  2, 2),
    ("SQL injection pattern detected",    1, 1),
    ("Port scan from external IP",        30, 15),
    ("Normal web request GET /index.html",0, 0),
    ("Brute force login detected",        25, 12),
    ("Invalid authentication token",      3, 3),
    ("Normal database query",             0, 0),
    ("DDoS pattern detected",             50, 20),
    ("File upload attempt blocked",       1, 1),
]


@app.route("/api/simulate")
def simulate():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    uid              = session["user_id"]
    ip               = random.choice(_SAMPLE_IPS)
    event, att, fail = random.choice(_SAMPLE_EVENTS)

    conn          = get_db()
    repeated_ip   = bool(conn.execute(
        "SELECT 1 FROM alerts WHERE user_id=? AND ip=? LIMIT 1", (uid, ip)
    ).fetchone())
    ip_fail_count = get_ip_fail_count(conn, ip, uid)

    detection = calculate_risk(
        attempts=att, failed=fail,
        event=event,
        repeated_ip=repeated_ip,
        ip_fail_count=ip_fail_count,
    )

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO alerts(user_id,time,ip,event,risk,attack_type,score,attempts,failed,ml_used,ml_label,source) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,'simulated')",
        (uid, ts, ip, event, detection["risk"],
         detection["attack_type"], detection["score"],
         att, fail,
         1 if detection.get("ml_used") else 0,
         detection.get("ml_label"))
    )
    conn.commit()
    conn.close()

    return jsonify({
        "time":        ts,
        "ip":          ip,
        "event":       event,
        "risk":        detection["risk"],
        "attack_type": detection["attack_type"],
        "score":       detection["score"],
        "ml_used":     detection.get("ml_used", False),
    })


# ===========================================================================
# API — CHART DATA — USER-ISOLATED
# ===========================================================================

@app.route("/api/chart_data")
def chart_data():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    uid  = session["user_id"]
    conn = get_db()

    risk_counts = conn.execute(
        "SELECT risk, COUNT(*) as cnt FROM alerts WHERE user_id=? GROUP BY risk", (uid,)
    ).fetchall()

    daily_counts = conn.execute(
        "SELECT date(time) as day, COUNT(*) as cnt FROM alerts WHERE user_id=? "
        "GROUP BY date(time) ORDER BY day DESC LIMIT 7",
        (uid,)
    ).fetchall()

    top_ips = conn.execute(
        "SELECT ip, COUNT(*) as cnt FROM alerts WHERE user_id=? "
        "GROUP BY ip ORDER BY cnt DESC LIMIT 5",
        (uid,)
    ).fetchall()

    conn.close()

    return jsonify({
        "risk_levels": {r["risk"]: r["cnt"] for r in risk_counts},
        "daily":       [{"day": r["day"], "count": r["cnt"]} for r in daily_counts],
        "top_ips":     [{"ip": r["ip"],   "count": r["cnt"]} for r in top_ips],
    })


# ===========================================================================
# API — RECENT ALERTS — USER-ISOLATED
# ===========================================================================

@app.route("/api/recent_alerts")
def recent_alerts():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    uid    = session["user_id"]
    conn   = get_db()
    alerts = conn.execute(
        "SELECT * FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT 10", (uid,)
    ).fetchall()
    conn.close()
    return jsonify([dict(a) for a in alerts])


# ===========================================================================
# API — ML STATUS
# ===========================================================================

@app.route("/api/ml_status")
def ml_status():
    """Return information about the ML model status."""
    model_exists = os.path.exists(MODEL_PATH)
    model_ok     = False
    features     = None

    if model_exists:
        try:
            import joblib
            m        = joblib.load(MODEL_PATH)
            features = getattr(m, "n_features_in_", None)
            model_ok = True
        except Exception:
            model_ok = False

    return jsonify({
        "model_loaded": model_ok,
        "model_path":   "model.pkl",
        "features":     features,
        "status":       "active" if model_ok else "fallback (rule-based only)"
    })


# ===========================================================================
# RUN
# ===========================================================================

if __name__ == "__main__":
    init_db()
    check_ml_model()
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port, debug=False)
