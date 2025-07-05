import subprocess, json, time, os

BLOCK_DURATION = 60
BLOCKED_FILE = "blocked_ips.json"

def block_ip(ip):
    blocked_ips = load_blocked_ips()
    if ip not in blocked_ips:
        os.system(f"iptables -A INPUT -s {ip} -j DROP")
        blocked_ips[ip] = {"blocked_at": "manual"}
        save_blocked_ips(blocked_ips)
        print(f"⛔ Blocked IP: {ip}")
    else:
        print(f"ℹ️ IP {ip} already blocked")


def unblock_ip(ip):
    blocked_ips = load_blocked_ips()
    if ip in blocked_ips:
        os.system(f"iptables -D INPUT -s {ip} -j DROP")
        del blocked_ips[ip]
        save_blocked_ips(blocked_ips)
        print(f"🔓 Unblocked IP: {ip}")
    else:
        print(f"⚠️ IP {ip} is not currently blocked")
        

def _record(ip):
    blocked = _load_raw()
    blocked[ip] = time.time()
    with open(BLOCKED_FILE, "w") as f:
        json.dump(blocked, f, indent=4)

def _remove(ip):
    blocked = _load_raw()
    if ip in blocked:
        del blocked[ip]
        with open(BLOCKED_FILE, "w") as f:
            json.dump(blocked, f, indent=4)

def _load_raw():
    try:
        with open(BLOCKED_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def load_blocked_ips():
    try:
        with open(BLOCKED_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_blocked_ips(data):
    with open(BLOCKED_FILE, "w") as f:
        json.dump(data, f, indent=4) 

def unblock_expired_ips():
    blocked = _load_raw()
    now = time.time()
    for ip, ts in list(blocked.items()):
        if now - ts >= BLOCK_DURATION:
            unblock_ip(ip)
