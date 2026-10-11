import requests
from typing import List, Dict, Any

def send_telegram_alert(token: str, chat_id: str, alerts: List[Dict[str, Any]]) -> bool:
    """Отправляет структурированное уведомление об атаках в Telegram."""
    if not alerts:
        return True

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    # Формируем текст сообщения в Markdown-разметке
    message_lines = ["🚨 *[AuthSentry] Обнаружена атака Brute-Force!* 🚨\n"]

    for alert in alerts:
        users = ", ".join(alert["targeted_users"])
        message_lines.append(
            f"• *IP:* `{alert['ip']}`\n"
            f"  *Попыток:* {alert['attempts']}\n"
            f"  *Целевые логины:* {users}\n"
            f"  *Период:* {alert['first_seen']} — {alert['last_seen']}\n"
            f"  *Уровень риска:* {alert['severity']}\n"
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