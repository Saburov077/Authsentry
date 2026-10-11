# AuthSentry

**AuthSentry** is a lightweight command-line interface (CLI) security tool designed to parse Linux authentication logs (`auth.log`), detect SSH brute-force attacks, and deliver real-time incident alerts.

Aligned with MITRE ATT&CK framework: **[T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)**.

---

##  Features

- **OpenSSH Log Parsing:** Extracts source IP addresses, targeted usernames, timestamps, and authentication statuses using optimized regular expressions.
- **Anomaly Detection:** Tracks failed authentication attempts per IP address with configurable threshold limits.
- **Threat Severity Assessment:** Automatically tags detected incidents (`HIGH`, `CRITICAL`) based on attack volume.
- **Rich Terminal UI:** Formats incident data into clear, color-coded tables in the console.
- **Incident Reporting:** Exports structured findings to `JSON` and `CSV` for SIEM/SOAR ingestion.
- **Telegram Bot Integration:** Dispatches instant incident notifications directly to SOC analysts or system administrators.

---

## 📁 Project Structure

```text
authsentry/
├── sample_logs/
│   └── auth.log           # Sample OpenSSH authentication logs
├── src/
│   ├── detector.py        # Attack detection and threshold evaluation
│   ├── notifier.py        # Telegram Bot API notification engine
│   ├── parser.py          # Regex-based log parser
│   └── reporter.py        # JSON and CSV report export handlers
├── main.py                # Application entry point (CLI)
├── requirements.txt       # Project dependencies
└── README.md

## Installation & Setup

### 1. Clone the repository
Clone the remote repository from GitHub to your local workstation:

```bash
git clone [https://github.com/Saburov077/authsentry.git](https://github.com/Saburov077/authsentry.git)
cd authsentry
```

### 2. Configure Virtual Environment
Create an isolated environment inside the `.venv` directory:

```bash
python -m venv .venv
```

Activate the environment depending on your operating system:

```bash
source .venv/Scripts/activate       # Linux / Git Bash
.\.venv\Scripts\Activate.ps1        # Windows PowerShell
```

### 3. Install dependencies
Install required packages specified in `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## Usage Examples

### Basic log analysis
Runs the parser on the bundled `sample_logs/auth.log` file:

```bash
python main.py
```

### Custom threshold and target file
Set a custom attempt threshold and analyze a system log:

```bash
python main.py --file /var/log/auth.log --threshold 5
```

### Export reports
Generate machine-readable exports in `JSON` and `CSV` format:

```bash
python main.py --json incidents.json --csv incidents.csv
```

### Dispatch Telegram alerts
Send notifications through the Telegram Bot API:

```bash
python main.py --telegram "YOUR_BOT_TOKEN" "YOUR_CHAT_ID"
```