# sniffer.py
from scapy.all import sniff, IP
from ip_blocker import block_ip, load_blocked_ips
import requests
from datetime import datetime, timezone
import time

packet_threshold = 2
time_window = 5

ip_packet_count = {}
start_time = time.time()

def report_to_dashboard(ip, packet_count, status="Safe", blocked_at=None):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {
        "ip": ip,
        "packet_count": packet_count,
        "last_seen": timestamp,
        "status": status,
        "timestamp": timestamp
    }
    if status == "Blocked" and blocked_at:
        payload["blocked_at"] = blocked_at

    print(f"[DEBUG] Sending data: {payload}")
    try:
        response = requests.post("https://ddos-protection-system-6qob.onrender.com/api/log", json=payload)
        print(f"[DEBUG] Response: {response.status_code} - {response.text.strip()}")
    except Exception as e:
        print(f"❌ Exception during reporting: {e}")

def packet_handler(pkt):
    global ip_packet_count, start_time
    if IP in pkt:
        src_ip = pkt[IP].src
        print(f"📦 Packet from {src_ip}")

        current_time = time.time()

        if current_time - start_time > time_window:
            ip_packet_count = {}
            start_time = current_time

        ip_packet_count[src_ip] = ip_packet_count.get(src_ip, 0) + 1

        if ip_packet_count[src_ip] > packet_threshold:
            print(f"🚨 Blocking {src_ip}")
            blocked = load_blocked_ips()
            if src_ip not in blocked:
                block_ip(src_ip)
                report_to_dashboard(src_ip, ip_packet_count[src_ip], "Blocked", blocked_at=datetime.now(timezone.utc).isoformat())
        else:
            report_to_dashboard(src_ip, ip_packet_count[src_ip], "Safe")

def start_sniffing():
    print("🔍 Monitoring all IP traffic...")
    sniff(iface="eth0", prn=packet_handler, store=0)

if __name__ == "__main__":
    start_sniffing()
