#sniffer.py
from scapy.all import sniff, IP
from ip_blocker import block_ip, load_blocked_ips
import requests
from datetime import datetime, timezone
import time

packet_threshold = 1
time_window = 5

ip_packet_count = {}
start_time = time.time()

def report_to_dashboard(ip, packet_count, status="Safe"):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {
        "ip": ip,
        "packet_count": packet_count,
        "last_seen": timestamp,
        "status": status,
        "timestamp": timestamp
    }

    if status == "Blocked":
        payload["blocked_at"] = timestamp

    print(f"📤 Sending data for {ip}: {payload}")
    try:
        response = requests.post("https://ddos-protection-system-6qob.onrender.com/api/log", json=payload)
        print(f"✅ Response status: {response.status_code}")
        if response.status_code != 204:
            print(f"⚠️ Unexpected response: {response.text}")
    except Exception as e:
        print(f"❌ Exception in report_to_dashboard: {e}")


def packet_handler(pkt):
    global ip_packet_count, start_time
    try:
        if IP in pkt:
            src_ip = pkt[IP].src
            print(f"📦 Packet from {src_ip}")
            
            current_time = time.time()

            if current_time - start_time > time_window:
                ip_packet_count = {}
                start_time = current_time

            ip_packet_count[src_ip] = ip_packet_count.get(src_ip, 0) + 1
            blocked = load_blocked_ips()

            if ip_packet_count[src_ip] > packet_threshold:
                if src_ip not in blocked:
                    block_ip(src_ip)
                    report_to_dashboard(src_ip, ip_packet_count[src_ip], status="Blocked")
                else:
                    report_to_dashboard(src_ip, ip_packet_count[src_ip], status="Blocked")
            else:
                report_to_dashboard(src_ip, ip_packet_count[src_ip], status="Safe")

    except Exception as e:
        print(f"❌ Error in packet_handler: {e}")

def start_sniffing():
    print("🔍 Monitoring All IP traffic....")
    sniff(iface="eth0", prn=packet_handler, store=0)

if __name__ == "__main__":
    start_sniffing()
