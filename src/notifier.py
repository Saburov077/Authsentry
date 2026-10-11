import requests
from typing import List, Dict, Any

def send_telegram_alert(token: str, chat_id: str, alerts: List[Dict[str, Any]]) -> bool:
    """Dispatches structured incident notifications to Telegram."""
    if not alerts:
        return True

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    message_lines = ["🚨 *[AuthSentry] SSH Brute-Force Incident Alert!* 🚨\n"]

    for alert in alerts:
        users = ", ".join(alert["targeted_users"])
        message_lines.append(
            f"• *Attacker IP:* `{alert['ip']}`\n"
            f"  *Attempts:* {alert['attempts']} (window: {alert.get('window_seconds', 120)}s)\n"
            f"  *Targeted Accounts:* {users}\n"
            f"  *Time Frame:* {alert['first_seen']} — {alert['last_seen']}\n"
            f"  *Severity:* {alert['severity']}\n"
        )

    payload = {
        "chat_id": chat_id,
        "text": "\n".join(message_lines),
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        return response.status_code == 200
    except requests.RequestException:
        return False