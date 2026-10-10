import re
from typing import Optional, Dict

# Регулярное выражение для разбора неудачных попыток входа SSH
FAILED_LOGIN_REGEX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[\w\.\-]+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?"
    r"(?P<username>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def parse_auth_line(line: str) -> Optional[Dict[str, str]]:
    """
    Принимает одну строку лога.
    Возвращает словарь с полями (ip, username, time, host, month, day),
    либо None, если строка не содержит сведений о сбое пароля.
    """
    match = FAILED_LOGIN_REGEX.search(line.strip())
    if not match:
        return None
    return match.groupdict()