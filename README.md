
# D06 Sentinel IDS

D06 Sentinel is a terminal-based IDS/IPS system designed for Kali Linux and other Linux distributions. It monitors network traffic in real time using Scapy, detects suspicious behavior, assigns threat scores per IP, logs alerts, and can automatically block malicious IPs using iptables.

---

## Features

- Real-time packet sniffing using Scapy  
- Detection of port scans, traffic floods, and repeated connections  
- Configurable threat scoring system (default threshold: 10)  
- Automatic IP blocking using Linux iptables  
- Live terminal dashboard with Rich (real-time stats and alerts)  
- JSON alert logging (~/.sentinelx/alerts.jsonl)  
- Safe handling of malformed packets  
- IDS-only mode (no blocking)

---

## Installation

bash git clone https://github.com/YOUR-USERNAME/D06-IDS.git cd D06-IDS python3 -m venv venv source venv/bin/activate pip install -r requirements.txt 

---

## Usage

Start monitoring:

bash sudo python3 main.py start --interface eth0 

Custom threshold:

bash sudo python3 main.py start --interface eth0 --threshold 15 

IDS-only mode:

bash sudo python3 main.py start --interface wlan0 --no-block 

Check status:

bash python3 main.py status 

Stop system:

bash sudo python3 main.py stop 

---

## CLI Options

- --interface (-i) → network interface  
- --threshold (-t) → threat score limit  
- --no-block → disable IPS  
- --log-file → custom log path  

---

## Alert Example

json {"behavior":"port_scan","blocked_now":true,"source_ip":"10.0.0.50","score":12,"severity":"high"} 

---

## Project Structure

main.py        CLI controller detector.py    Packet analysis (Scapy) scorer.py      Threat scoring logic blocker.py     IP blocking (iptables) ui.py          Terminal dashboard (Rich) logger.py      Alert logging banner.py      Custom D06 ASCII logo

---

## Requirements

- Python 3.10+
- Linux (Kali recommended)
- root privileges (for packet capture)
- iptables (for blocking)

---

## Author

**Domoa Alfatla
