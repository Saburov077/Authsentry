import re
from datetime import datetime
from typing import Optional, Dict

# Регулярное выражение для извлечения времени, статуса, пользователя и IP
FAILED_PATTERN = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<username>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def parse_auth_line(line: str, reference_year: int = 2026) -> Optional[Dict[str, str | datetime]]:
    """
    Парсит строку auth.log. Возвращает словарь с нормализованным datetime или None.
    """
    match = FAILED_PATTERN.search(line)
    if not match:
        return None

    data = match.groupdict()
    
    # Системный syslog не пишет год, поэтому подставляем текущий
    date_str = f"{reference_year} {data['month']} {data['day']} {data['time']}"
    try:
        timestamp = datetime.strptime(date_str, "%Y %b %d %H:%M:%S")
    except ValueError:
        timestamp = datetime.now()

    return {
        "timestamp": timestamp,
        "time_str": data["time"],
        "username": data["username"],
        "ip": data["ip"]
    }