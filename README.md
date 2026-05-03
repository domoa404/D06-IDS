# DO6

 v1.0 is a terminal-based IDS/IPS for Kali Linux and other Linux systems. It monitors network packets in real time with Scapy, detects suspicious behavior, assigns per-IP threat scores, logs alerts as JSON, and can automatically block malicious IPs with `iptables`.

## Features

- Real-time packet sniffing with Scapy
- Detection for port scanning, high-rate traffic floods, and repeated connections
- Configurable threat scoring with a default block threshold of `10`
- Optional IPS blocking through Linux `iptables`
- Rich terminal dashboard with live IP scores, packet totals, active threats, and blocked IP count
- JSON Lines alert log at `~/.sentinelx/alerts.jsonl`
- Safe packet handling for malformed or unsupported traffic
- Graceful IDS-only mode when blocking is disabled or unavailable

## Installation

```bash
git clone <your-repo-url> sentinelx
cd sentinelx
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Kali Linux, make sure `iptables` is installed:

```bash
sudo apt update
sudo apt install iptables
```

## Usage

Start monitoring an interface:

```bash
sudo python main.py start --interface eth0
```

Use a custom threshold:

```bash
sudo python main.py start --interface eth0 --threshold 15
```

Run in IDS-only mode without automatic blocking:

```bash
sudo python main.py start --interface wlan0 --no-block
```

Check status from another terminal:

```bash
python main.py status
```

Stop a running SentinelX process:

```bash
sudo python main.py stop
```

Show the help menu:

```bash
python main.py --help
python main.py start --help
```

## CLI Commands

- `sentinelx start`: start packet monitoring and threat scoring
- `sentinelx stop`: send a stop signal to the running process
- `sentinelx status`: show whether SentinelX is running

Common options for `start`:

- `--interface`, `-i`: network interface to monitor, such as `eth0`
- `--threshold`, `-t`: threat score limit before blocking, default `10`
- `--no-block`: disable IPS blocking
- `--log-file`: custom alert log path

## Alert Log Format

Alerts are written as JSON Lines, one JSON object per alert. Example:

```json
{"behavior":"port_scan","blocked_now":true,"destination_ip":"192.168.1.10","message":"Possible port scan: 16 unique destination ports.","metadata":{"unique_ports":16,"window_seconds":20},"points":5,"score":12,"severity":"high","source_ip":"10.0.0.50","status":"BLOCKED","threshold":10,"timestamp":"2026-05-03T12:00:00+00:00"}
```

## Cross-Platform Notes

SentinelX is primarily designed for Kali Linux. Packet capture usually requires root privileges. Automatic blocking uses `iptables`, so it is Linux-only. On non-Linux systems, or when `--no-block` is used, SentinelX continues to detect, score, display, and log threats without blocking.

## Project Structure

```text
main.py          CLI entry point and process state handling
detector.py      Scapy packet parsing and behavior detection
scorer.py        Threat score accumulation and status tracking
blocker.py       Linux iptables blocking integration
ui.py            Rich live terminal interface
logger.py        JSON Lines alert logging
requirements.txt Python dependencies
README.md        Setup and usage documentation
```

## Development

Run a syntax check:

```bash
python -m py_compile main.py detector.py scorer.py blocker.py ui.py logger.py
```

Run help locally:

```bash
python main.py --help
```
