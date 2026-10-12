# AuthSentry

[![Test Suite](https://github.com/Saburov077/authsentry/actions/workflows/tests.yml/badge.svg)](https://github.com/Saburov077/authsentry/actions/workflows/tests.yml)

AuthSentry is a lightweight, host-based intrusion detection and prevention system (HIDS/IPS) written in Python. It analyzes OpenSSH authentication logs (`auth.log`), detects brute-force and password spraying attacks using sliding time windows, enriches indicators of compromise (IoCs) with Threat Intelligence, delivers real-time Telegram alerts, and generates automated firewall countermeasures.

Directly aligned with MITRE ATT&CK technique: **[T1110 (Brute Force)](https://attack.mitre.org/techniques/T1110/)**.

---

## Key features

- **Sliding time window detection:** Tracks authentication attempts using stateful double-ended queues (`collections.deque`), flagging burst patterns within a specified time frame to eliminate false positives.
- **Threat Intelligence & GeoIP:** Resolves geographic location, country, city, and ISP/Organization metadata for external attacker IPs while filtering internal private networks (RFC 1918).
- **Continuous monitoring (`--watch`):** Implements an asynchronous file stream generator (`tail -f` behavior) to monitor incoming log records in real time.
- **Automated mitigation & IPS (`--block`):** Generates host-level firewall drop rules (`iptables` on Linux, `netsh advfirewall` on Windows) with an integrated safe `--dry-run` simulation mode.
- **Multi-channel export & alerts:** Renders formatted terminal tables via `rich`, exports findings to `JSON` and `CSV` for SIEM ingestion, and dispatches incident summaries via the Telegram Bot API.

---

## Installation and environment setup

Clone the repository to your local machine and navigate into the project directory:

```bash
[https://github.com/Saburov077/authsentry.git](https://github.com/Saburov077/authsentry.git) && cd authsentry
```

Create an isolated virtual environment under `.venv`:

```bash
python -m venv .venv
```

Activate the virtual environment:

```bash
source .venv/Scripts/activate       # Linux / Git Bash
```

For Windows PowerShell users:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

## Running detection

### Standard batch analysis
Run the detection pipeline against the bundled sample log (`sample_logs/auth.log`):

```bash
python main.py
```

By default, AuthSentry inspects the log using a threshold of `4` failed attempts within a `120`-second sliding window.

### Custom logs and threshold configuration
Target a custom log file and adjust threshold parameters:

```bash
python main.py --file /var/log/auth.log --threshold 5 --window 60
```

---

## Continuous real-time monitoring

To run AuthSentry as a continuous monitoring daemon against active log streams:

```bash
python main.py --file /var/log/auth.log --watch
```

New log entries are processed on the fly, immediately displaying incident cards upon threshold breaches.

---

## Automated incident response (Firewall mitigation)

AuthSentry can automatically mitigate active threats by isolating attacker IPs at the firewall layer.

### Simulated mitigation (Dry-run mode)
Preview generated firewall rules without altering system policies:

```bash
python main.py --block --dry-run
```

### Live active defense
Apply immediate firewall drop rules to the host system:

```bash
python main.py --block --no-dry-run
```

* Linux environments generate `iptables -I INPUT -s <IP> -j DROP`.
* Windows environments generate `netsh advfirewall firewall add rule ... action=block`.

---

## Incident reporting and SIEM export

Export detected incidents into structured machine-readable formats for SIEM ingestion or audit logging:

```bash
python main.py --json reports/incidents.json --csv reports/incidents.csv
```

### Running with Docker

Deploy AuthSentry as an isolated background daemon using Docker Compose:

```bash
docker compose up -d --build
```

View live detection logs in the container stream:

```bash
docker logs -f authsentry
```

## Telegram alert notifications

Dispatch high-priority incident notifications directly to SOC channels or administrators:

```bash
python main.py --telegram "YOUR_BOT_TOKEN" "YOUR_CHAT_ID"
```

---

## Project layout

```text
authsentry/
├── sample_logs/
│   └── auth.log          # Bundled sample logs for testing
├── src/
│   ├── detector.py       # Sliding time window state engine
│   ├── enricher.py       # GeoIP and Threat Intelligence resolver
│   ├── notifier.py       # Telegram Bot API notification engine
│   ├── parser.py         # Regex parsing for OpenSSH logs
│   ├── reporter.py       # JSON and CSV report export handlers
│   ├── responder.py      # Automated firewall mitigation module
│   └── watcher.py        # Real-time log file stream follower
├── main.py               # CLI interface and pipeline orchestrator
├── requirements.txt      # Project dependencies
└── README.md
```