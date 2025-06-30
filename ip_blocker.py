import subprocess, json, time, os

BLOCK_DURATION = 60
BLOCKED_FILE = "blocked_ips.json"

def block_ip(ip):
    subprocess.call(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    _record(ip)

def unblock_ip(ip):
    blocked_ips = load_blocked_ips()
    if ip in blocked_ips:
        del blocked_ips[ip]
        save_blocked_ips(blocked_ips)
        os.system(f"iptables -D INPUT -s {ip} -j DROP")


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
    return list(_load_raw().keys())

def unblock_expired_ips():
    blocked = _load_raw()
    now = time.time()
    for ip, ts in list(blocked.items()):
        if now - ts >= BLOCK_DURATION:
            unblock_ip(ip)
