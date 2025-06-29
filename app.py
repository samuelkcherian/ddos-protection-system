from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import json
import os
from sniffer import start_sniffing
from ip_blocker import unblock_expired_ips

app = Flask(__name__)
app.secret_key = "your_secret_key"
USERS_FILE = "users.json"

# Load users
def load_users():
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
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
    
@app.route("/unblock", methods=["POST"])
def unblock():
    from ip_blocker import unblock_ip
    ip = request.json.get("ip")
    unblock_ip(ip)
    return "", 204

def run_sniffer():
    while True:
        unblock_expired_ips()
        start_sniffing()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)