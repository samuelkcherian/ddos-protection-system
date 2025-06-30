from flask import Flask, render_template, jsonify, request, redirect, url_for, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import threading
import json
import os
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
            return jsonify(json.load(f))
    except:
        return jsonify([])
    
@app.route("/api/log", methods=["POST"])
def log_data():
    if not request.is_json:
        return abort(400, description="Invalid data format.")
    data = request.get_json()
    try:
        ip = data["ip"]
        count = data["packet_count"]
        last_seen = data.get("last_seen", datetime.utcnow().isoformat())
        status = data.get("status", "Blocked")
    except KeyError as e:
        return abort(400, description="Missing keys: {str(e)}")
    
    try:
        with open("dashboard_data.json", "r") as f:
            dashboard = json.load(f)
    except FileNotFoundError:
        dashboard = []

    for entry in dashboard:
        if entry["ip"] == ip:
            entry["packet_count"] = count
            entry["last_seen"] = last_seen
            entry["status"] = status
            break

    else:
        dashboard.append({
            "ip": ip,
            "packet_count": count,
            "last_seen": last_seen,
            "status": status
        })

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
            entry["status"] = "Unblocked"
            break
    with open("dashboard_data.json", "w") as f:
        json.dump(dashboard, f, indent=4)
    return "", 204

#def run_sniffer():
#    while True:
 #       unblock_expired_ips()
 #       start_sniffing()

#threading.Thread(target=run_sniffer, daemon=True).start()
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)