# SentinelFlow

SentinelFlow is a lightweight, behavior-based network traffic monitor and anomaly detection tool.

It has:
- A Python agent that runs on a node, collects network stats (psutil) and sniffs packets (scapy).
- A FastAPI server that receives metrics, computes a per-node risk score, and shows a live dashboard.

The goal is to detect unusual or potentially malicious traffic patterns (traffic spikes, SYN floods, port scans) in real time.

---

## Features

- Agent ↔ server communication over HTTP (JSON)
- System metrics per node:
  - bytes sent / received
  - packets sent / received
- Packet-level signals:
  - syn_count (TCP SYN packets per interval)
  - unique_dst_ports (unique destination ports per interval)
- Risk scoring engine:
  - sliding-window baseline of bytes/sec
  - traffic spike detection
  - "idle → noisy" detection
  - SYN-flood-like and port-scan-like behavior
- Live dashboard at /dashboard:
  - agent ID, hostname, last seen
  - risk score (color coded)
  - last alert message

---

## How to Run

```bash
# 1. Clone and enter the project
git clone https://github.com/geekrarmiessler/sentineflow.git
cd sentineflow

# 2. Create virtualenv and install deps
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Start the server
uvicorn server.main:app --reload
