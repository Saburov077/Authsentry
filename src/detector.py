from collections import defaultdict
from typing import List, Dict, Any

class BruteForceDetector:
    def __init__(self, threshold: int = 4):
        """
        threshold: минимальное количество неудачных попыток,
        после которого IP считается атакующим.
        """
        self.threshold = threshold
        # Хранилище: {ip: {"count": N, "users": set(), "events": []}}
        self.ip_tracker = defaultdict(lambda: {"count": 0, "users": set(), "events": []})

    def process_event(self, event: Dict[str, str]):
        """Обрабатывает словарь, полученный из parse_auth_line."""
        ip = event["ip"]
        self.ip_tracker[ip]["count"] += 1
        self.ip_tracker[ip]["users"].add(event["username"])
        self.ip_tracker[ip]["events"].append(event["time"])

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Возвращает список алертов по IP, превысившим порог threshold."""
        alerts = []
        for ip, data in self.ip_tracker.items():
            if data["count"] >= self.threshold:
                alerts.append({
                    "ip": ip,
                    "attempts": data["count"],
                    "targeted_users": list(data["users"]),
                    "first_seen": data["events"][0],
                    "last_seen": data["events"][-1],
                    "severity": "CRITICAL" if data["count"] >= 10 else "HIGH"
                })
        return alerts