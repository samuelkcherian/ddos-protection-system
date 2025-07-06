from flask import Flask, render_template, jsonify, request, redirect, url_for, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
import threading
import time
import json
import os
import socket
#from sniffer import start_sniffing
from ip_blocker import unblock_expired_ips

app = Flask(__name__)
app.secret_key = "your_secret_key"
USERS_FILE = "users.json"

# Load users
def load_users():
    if not os.path.exists(USERS_FILE) or os.stat(USERS_FILE).st_size == 0:
        print("users.json is missing or empty.")
        return {}
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print("users.json is corrupted or has invalid JSON.")
        return {}
# Save users
def save_users(users):
    with open(USERS_FILE,"w") as f:
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
        else:
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

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

@app.route("/data")
def data():
    try:
        with open("dashboard_data.json", "r") as f:
            dashboard=json.load(f)
        
        for entry in dashboard:
            blocked_at = entry.get("blocked_at")
            print(f"[DEBUG] {entry['ip']} | status: {entry['status']} | blocked_at: {blocked_at}")

            if entry.get("status") == "Blocked" and blocked_at:
                entry["block_duration"] = get_block_duration(blocked_at)
            else:
                entry["block_duration"] = "-"


        return jsonify(dashboard)

    except Exception as e:
        print(f"[ERROR] /data: {e}")
        return jsonify([])
    
    
@app.route("/api/log", methods=["POST"])
def log_data():
    if not request.is_json:
        return abort(400, description="Invalid data format.")
    data = request.get_json()
    print(f"📥 Incoming log data: {data}")

    try:
        ip = data["ip"]
        count = data["packet_count"]
        last_seen = data.get("last_seen", datetime.utcnow().isoformat())
        status = data.get("status", "Blocked")
    except KeyError as e:
        return abort(400, description=f"Missing key: {str(e)}")
    
    try:
        with open("dashboard_data.json", "r") as f:
            dashboard = json.load(f)
    except FileNotFoundError:
        dashboard = []

    now = data.get("timestamp", datetime.now(timezone.utc).isoformat())
    updated = False
    path = os.path.abspath("dashboard_data.json")
    print(f"[DEBUG] Writing to: {path}")

    for entry in dashboard:
        if entry["ip"] == ip:
            entry["packet_count"] = count
            entry["last_seen"] = last_seen
            entry["status"] = status
            if status == "Blocked":
                if not entry.get("blocked_at"):
                    entry["blocked_at"] = now
            else:
                entry["blocked_at"] = None

            if "timestamps" not in entry:
                entry["timestamps"] = []
            entry["timestamps"].append(now)
            entry["timestamps"] = entry["timestamps"][-20:]

            updated = True
            break
            

    if not updated:
        new_entry = {
            "ip": ip,
            "packet_count": count,
            "last_seen": last_seen,
            "status": status,
            "timestamps": [now],
            "blocked_at": now if status == "Blocked" else None
        }



        if status == "Blocked":
            print(f"🆕 New blocked IP {ip} with blocked_at = {now}")

        dashboard.append(new_entry)

    print(f"[DEBUG] Received log for IP {ip} with timestamp: {now}")    

    with open("dashboard_data.json", "w") as f:
        json.dump(dashboard, f, indent=4)

    return "", 204
    
@app.route("/unblock", methods=["POST"])
def unblock():
    from ip_blocker import unblock_ip
    ip = request.json.get("ip")
    unblock_ip(ip)

    try:
        with open("dashboard_data.json", "r") as f:
            dashboard = json.load(f)
    except FileNotFoundError:
        dashboard = []

    for entry in dashboard:
        if entry["ip"] == ip:
            entry["status"] = "Safe"
            entry["blocked_at"] = None
            break
    with open("dashboard_data.json", "w") as f:
        json.dump(dashboard, f, indent=4)
    return "", 204

@app.route("/monitor", methods=["POST"])
def monitor_domain():
    data = request.get_json()
    domain = data.get("domain")
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    try:
        resolved_ip = socket.gethostbyname(domain)
        print(f"🌐 Domain {domain} resolved to IP {resolved_ip}")
    except socket.gaierror:
        return jsonify({"error": "Failed to resolve domain"}), 400
    
    try:
        with open("dashboard_data.json", "r") as f:
            dashboard = json.load(f)
    except FileNotFoundError:
        dashboard = []

    for entry in dashboard:
        if entry["ip"] == resolved_ip:
            return jsonify({
                "message": "Already monitoring this domain's IP",
                "ip": resolved_ip
            }), 200
        
    dashboard.append({
        "ip": resolved_ip,
        "packet_count": 0,
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "status": "Monitoring"
    })

    with open("dashboard_data.json", "w") as f:
        json.dump(dashboard, f, indent=4)

    print(f"[INFO] Domain '{domain}' resolved to '{resolved_ip}' and added to dashboard.")
    return jsonify({
        "message": f"Monitoring domain {domain} at IP {resolved_ip}",
        "ip": resolved_ip
    }),200

def calculate_suspicion_score(entry):
    timestamps = entry.get("timestamps", [])
    if len(timestamps) < 2:
        return 0
    
    parsed_times = [datetime.fromisoformat(ts) for ts in timestamps]
    now = datetime.now(timezone.utc)

    recent = [ts for ts in parsed_times if now - ts <= timedelta(seconds=10)]
    count = len(recent)

    score = min(100, count * 10)
    if entry.get("status") == "Blocked":
        score = max(score, 70)
    elif entry.get("status") == "Suspicious":
        score = max(score, 50)

    return score

def analyze_traffic():
    while True:
        try:
            with open("dashboard_data.json", "r") as f:
                dashboard = json.load(f)
        except FileNotFoundError:
            dashboard = []

        updated = False
        now = datetime.now(timezone.utc)

        for entry in dashboard:
            timestamps = entry.get("timestamps", [])
            parsed_times = [datetime.fromisoformat(ts) for ts in timestamps]
            recent = [ts for ts in parsed_times if now - ts <= timedelta(seconds=5)]
 
            new_score = calculate_suspicion_score(entry)
            if entry.get("suspicion_score") != new_score:
                entry["suspicion_score"] = new_score
                updated = True
                           
            print(f"🧠 Score for {entry['ip']}: {entry['suspicion_score']}")

            if len(recent) >= 10:
                if entry["status"] != "Suspicious":
                    entry["status"] = "Suspicious"
                    print(f"⚠️ Suspicious activity detected from {entry['ip']}")
                    updated = True
            
           

        if updated:
            with open("dashboard_data.json", "w") as f:
                json.dump(dashboard, f, indent=4)

        time.sleep(5)

def auto_unblock():
    while True:
        try:
            with open("dashboard_data.json", "r") as f:
                dashboard = json.load(f)
        except FileNotFoundError:
            dashboard = []

        now = datetime.now(timezone.utc)
        updated = False

        for entry in dashboard:
            if entry.get("status") == "Blocked" and entry.get("blocked_at"):
                blocked_time = datetime.fromisoformat(entry["blocked_at"])
                if (now - blocked_time).total_seconds() > 600:
                    print(f"🔓 Auto-unblocking {entry['ip']}")
                    entry["status"] = "Safe"
                    entry["blocked_at"] = None
                    updated = True

        if updated:
            with open("dashboard_data.json", "w") as f:
                json.dump(dashboard, f, indent=4)

        time.sleep(30)

def get_block_duration(blocked_at_str):
    try:
        blocked_at = datetime.fromisoformat(blocked_at_str)
        now = datetime.now(timezone.utc)
        duration = now - blocked_at
        seconds = int(duration.total_seconds())

        minutes, seconds = divmod(seconds, 60)
        return f"{minutes}m {seconds}s"
    except Exception as e:
        print(f"[ERROR] Block duration parse failed: {e}")
        return "Unknown"
#def run_sniffer():
#    while True:
 #       unblock_expired_ips()
 #       start_sniffing()

threading.Thread(target=analyze_traffic, daemon=True).start()
threading.Thread(target=auto_unblock, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)