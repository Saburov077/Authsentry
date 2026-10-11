# AuthSentry

AuthSentry is a lightweight Python security utility designed to inspect OpenSSH authentication logs (`auth.log`), identify brute-force patterns and password spraying attempts, and deliver structured alerts to security teams.

The tool directly aligns with MITRE ATT&CK technique **[T1110 (Brute Force)](https://attack.mitre.org/techniques/T1110/)**.

---

## Installation and environment setup

Clone the repository to your local machine and navigate into the project directory:

```bash
git clone [https://github.com/Saburov077/authsentry.git](https://github.com/Saburov077/authsentry.git)
cd authsentry
```

Create an isolated virtual environment under `.venv` to prevent dependency conflicts:

```bash
python -m venv .venv
```

Activate the environment based on your current terminal:

```bash
source .venv/Scripts/activate
```

For Windows PowerShell users, activate using:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install all required third-party libraries listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## Running detection

To run the analyzer against the bundled sample log (`sample_logs\auth.log`):

```bash
python main.py
```

By default, the script reads `sample_logs\auth.log` and flags any source IP address that reaches `4` or more failed authentication attempts.

### Custom log files and detection thresholds

If your logs live on a different path or you want to inspect live system logs on Linux, pass `--file` directly:

```bash
python main.py --file /var/log/auth.log --threshold 5
```

The `--threshold` flag defines the minimum number of failed password attempts required to generate an alert. Any IP with attempts exceeding `10` is automatically escalated to `CRITICAL` risk level.

---

## Incident reporting and SIEM export

You can export detected anomalies into structured formats for SIEM ingestion, triage tickets, or forensic analysis.

Generate both JSON and CSV reports in a single run:

```bash
python main.py --json incidents.json --csv incidents.csv
```

The exported `JSON` file contains full structured incident metadata (source IP, attempt counter, targeted user accounts, initial attempt timestamp, and last seen timestamp). The `CSV` file provides a tabular summary suitable for spreadsheets.

---

## Telegram alert integration

AuthSentry can forward high-priority alerts directly to security analysts or on-call administrators via the Telegram Bot API.

Trigger analysis with immediate Telegram dispatch:

```bash
python main.py --telegram "YOUR_BOT_TOKEN" "YOUR_CHAT_ID"
```

The alert message includes the offending source IP, total failed attempts, enumerated usernames, and time window.

---

## Project layout

The project structure is organized into modular components:

```text
authsentry/
├── sample_logs/
│   └── auth.log          # Bundled sample logs for immediate testing
├── src/
│   ├── detector.py       # Core state tracker and threshold evaluation
│   ├── notifier.py       # Telegram Bot API notification client
│   ├── parser.py         # Regular expression parsing for OpenSSH logs
│   └── reporter.py       # Structured JSON and CSV export handlers
├── main.py               # CLI interface and pipeline orchestrator
├── requirements.txt      # Project dependencies
└── README.md
```