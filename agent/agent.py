import socket
import time
import threading
from datetime import datetime, timezone

import psutil
import requests
from scapy.all import sniff, IP, TCP

from config import SERVER_URL, AGENT_ID, INTERVAL_SECONDS

# globals updated by the packet sniffer
syn_count = 0
dst_ports = set()


def handle_packet(pkt):
    global syn_count, dst_ports
    if IP in pkt and TCP in pkt:
        tcp = pkt[TCP]
        # SYN flag (0x02)
        if tcp.flags & 0x02:
            syn_count += 1
        dst_ports.add(int(tcp.dport))


def start_sniffer():
    t = threading.Thread(
        target=lambda: sniff(prn=handle_packet, store=False),
        daemon=True
    )
    t.start()


def get_hostname():
    return socket.gethostname()


def collect_metrics():
    global syn_count, dst_ports

    counters = psutil.net_io_counters()

    current_syn = syn_count
    current_unique_ports = len(dst_ports)
    syn_count = 0
    dst_ports = set()

    return {
        "agent_id": AGENT_ID,
        "hostname": get_hostname(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "bytes_sent": counters.bytes_sent,
        "bytes_recv": counters.bytes_recv,
        "packets_sent": counters.packets_sent,
        "packets_recv": counters.packets_recv,
        "syn_count": current_syn,
        "unique_dst_ports": current_unique_ports,
    }


def main():
    print(f"Starting agent {AGENT_ID}, sending to {SERVER_URL}")
    while True:
        payload = collect_metrics()
        try:
            r = requests.post(SERVER_URL, json=payload, timeout=2)
            print("Sent metrics, server responded:", r.status_code, r.text)
        except Exception as e:
            print("Error sending metrics:", e)
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    start_sniffer()
    main()
