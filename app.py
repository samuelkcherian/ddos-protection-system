from flask import Flask, render_template, jsonify, request, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
import threading
import time
import json
import os
import socket

app = Flask(__name__)
app.secret_key = "your_secret_key"

USERS_FILE = "users.json"
DASHBOARD_FILE = "dashboard_data.json"

# ---------- File Handling ----------
def load_json_safely(DASHBOARD_FILE):
    try:
        with open(DASHBOARD_FILE, "r") as f:
            data = json.load(f)
            if not isinstance(data, list):
                print(f"[ERROR] {DASHBOARD_FILE} does not contain a list. Resetting.")
                return []
            return data
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to load {DASHBOARD_FILE}: {e}")
        return []
    except Exception as e:
        print(f"[ERROR] Unexpected error loading {DASHBOARD_FILE}: {e}")
        return []


def save_json_safely(DASHBOARD_FILE, data):
    try:
        with open(DASHBOARD_FILE, "w") as f:
            json.dump(data, f, indent=4)
            f.truncate()
    except Exception as e:
        print(f"[ERROR] Failed to save {DASHBOARD_FILE}: {e}")

# ---------- Authentication ----------
def load_users():
    if not os.path.exists(USERS_FILE) or os.stat(USERS_FILE).st_size == 0:
        return {}
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = load_users()
        if username in users and check_password_hash(users[username], password):
            session["user"] = username
            return redirect("/dashboard")
        return "❌ Invalid credentials!"
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = load_users()
        if username in users:
            return "⚠️ Username already exists."
        users[username] = generate_password_hash(password)
        save_users(users)
        return redirect("/")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html")

# ---------- Main API Logic ----------
@app.route("/data")
def data():
    dashboard = load_json_safely(DASHBOARD_FILE)
    now = datetime.now(timezone.utc)
    for entry in dashboard:
        if entry.get("status") == "Blocked" and entry.get("blocked_at"):
            entry["blocked_duration"] = get_block_duration(entry["blocked_at"])
        else:
            entry["blocked_duration"] = "-"
    return jsonify(dashboard)
    print(f"[DEBUG] Returning {len(dashboard)} entries from /data")

@app.route("/api/log", methods=["POST"])
def log_data():
    if not request.is_json:
        return abort(400, description="Invalid data format")

    try:
        data = request.get_json()
        ip = data["ip"]
        count = data["packet_count"]
        last_seen = data.get("last_seen", datetime.utcnow().isoformat())
        status = data.get("status", "Safe")
        blocked_at = data.get("blocked_at")
        now = data.get("timestamp", datetime.now(timezone.utc).isoformat())
    except Exception as e:
        return abort(400, description=f"Malformed data: {e}")

    dashboard = load_json_safely(DASHBOARD_FILE)
    updated = False

    for entry in dashboard:
        if isinstance(entry, dict) and entry.get("ip") == ip:
            entry["packet_count"] = count
            entry["last_seen"] = last_seen
            entry["status"] = status
            if status == "Blocked" and not entry.get("blocked_at"):
                entry["blocked_at"] = now
            entry.setdefault("timestamps", []).append(now)
            entry["timestamps"] = entry["timestamps"][-20:]
            updated = True
            break

    if not updated:
        dashboard.append({
            "ip": ip,
            "packet_count": count,
            "last_seen": last_seen,
            "status": status,
            "timestamps": [now],
            "blocked_at": blocked_at if status == "Blocked" else None
        })

    save_json_safely(DASHBOARD_FILE, dashboard)
    return "", 204

@app.route("/monitor", methods=["POST"])
def monitor_domain():
    data = request.get_json()
    domain = data.get("domain")
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    try:
        resolved_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return jsonify({"error": "Failed to resolve domain"}), 400

    dashboard = load_json_safely(DASHBOARD_FILE)
    for entry in dashboard:
        if entry["ip"] == resolved_ip:
            return jsonify({"message": "Already monitoring", "ip": resolved_ip})

    dashboard.append({
        "ip": resolved_ip,
        "packet_count": 0,
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "status": "Monitoring"
    })
    save_json_safely(DASHBOARD_FILE, dashboard)
    return jsonify({"message": f"Monitoring {domain}", "ip": resolved_ip})

# ---------- Smart Analytics + Background ----------
def calculate_suspicion_score(entry):
    timestamps = entry.get("timestamps", [])
    if len(timestamps) < 2:
        return 0
    parsed = [datetime.fromisoformat(t) for t in timestamps]
    recent = [t for t in parsed if datetime.now(timezone.utc) - t <= timedelta(seconds=10)]
    score = min(100, len(recent) * 10)
    if entry.get("status") == "Blocked":
        score = max(score, 70)
    elif entry.get("status") == "Suspicious":
        score = max(score, 50)
    return score

def analyze_traffic():
    while True:
        dashboard = load_json_safely(DASHBOARD_FILE)
        now = datetime.now(timezone.utc)
        updated = False

        for entry in dashboard:
            timestamps = entry.get("timestamps", [])
            recent = [datetime.fromisoformat(ts) for ts in timestamps if now - datetime.fromisoformat(ts) <= timedelta(seconds=5)]
            score = calculate_suspicion_score(entry)
            if entry.get("suspicion_score") != score:
                entry["suspicion_score"] = score
                updated = True
            if len(recent) >= 10 and entry["status"] != "Blocked":
                entry["status"] = "Blocked"
                entry["blocked_at"] = now.isoformat()
                updated = True

        if updated:
            save_json_safely(DASHBOARD_FILE, dashboard)

        time.sleep(5)

def auto_unblock():
    while True:
        dashboard = load_json_safely(DASHBOARD_FILE)
        now = datetime.now(timezone.utc)
        updated = False
        for entry in dashboard:
            if entry.get("status") == "Blocked" and entry.get("blocked_at"):
                blocked_time = datetime.fromisoformat(entry["blocked_at"])
                if (now - blocked_time).total_seconds() > 600:
                    entry["status"] = "Safe"
                    entry["blocked_at"] = None
                    updated = True
        if updated:
            save_json_safely(DASHBOARD_FILE, dashboard)
        time.sleep(30)

def get_block_duration(blocked_at_str):
    try:
        blocked_at = datetime.fromisoformat(blocked_at_str)
        now = datetime.now(timezone.utc)
        delta = now - blocked_at
        minutes, seconds = divmod(int(delta.total_seconds()), 60)
        return f"{minutes}m {seconds}s"
    except:
        return "?"

# ---------- Start Background Tasks ----------
threading.Thread(target=analyze_traffic, daemon=True).start()
threading.Thread(target=auto_unblock, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
