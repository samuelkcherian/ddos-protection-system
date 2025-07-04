# sniffer.py
from scapy.all import sniff, IP, conf
from ip_blocker import block_ip, load_blocked_ips
import requests
from datetime import datetime, timezone
import time
import json

packet_threshold = 10  # Number of packets from a single IP to consider suspicious
time_window = 5        # Time window in seconds to check the threshold

ip_packet_count = {}
start_time = time.time()

def report_to_dashboard(ip, packet_count, status="Blocked"):
    timestamp = datetime.now(timezone.utc).isoformat()
    print(f"[DEBUG] Sending data: ip={ip}, count={packet_count}, time={timestamp}")
    try:
        response = requests.post("https://ddos-protection-system-6qob.onrender.com/api/log", json={
            "ip": ip,
            "packet_count": packet_count,
            "last_seen": timestamp,
            "status": status,
            "timestamp": timestamp
        })
        if response.text.strip():
            print(f"[DEBUG] Response: {response.status_code} - {response.text}")
        else:
            print(f"[DEBUG] Response: {response.status_code}")

        if response.status_code == 204:
            print(f"✅ Reported {ip} to live dashboard")
        else:
            print(f"⚠️ Failed to report {ip} - {response.status_code}")
    except Exception as e:
        print(f"❌ Exception during reporting for IP {ip}: {e}")

def packet_handler(pkt):
    global ip_packet_count, start_time

    try:
        if IP in pkt:
            src_ip = pkt[IP].src
            print(f"📦 Packet detected from {src_ip}")  # Debug output

            current_time = time.time()

        # Reset counts if time window has passed
            if current_time - start_time > time_window:
                ip_packet_count = {}
                start_time = current_time

            ip_packet_count[src_ip] = ip_packet_count.get(src_ip, 0) + 1

            if ip_packet_count[src_ip] > packet_threshold:
                blocked = load_blocked_ips()
                if src_ip not in blocked:
                    block_ip(src_ip)
                    report_to_dashboard(src_ip, ip_packet_count[src_ip], "Blocked")
            else:
                report_to_dashboard(src_ip, ip_packet_count[src_ip], "Safe")
    except Exception as e:
        print(f"⚠️ Error processing packet: {e}")


def start_sniffing():
    print("🔍 Monitoring all IP traffic... ")

    try:
        sniff(
            iface="eth0",
            prn=packet_handler,
            store=0,
            stop_filter=lambda x: False  # Run forever unless interrupted
        )
    except KeyboardInterrupt:
        print("\n🛑 Sniffer stopped by user.")
    except Exception as e:
        print(f"❌ Sniffer crashed: {e}")

if __name__ == "__main__":
    start_sniffing()
