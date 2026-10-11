from collections import defaultdict, deque
from datetime import datetime
from typing import List, Dict, Any, Optional

class BruteForceDetector:
    def __init__(self, threshold: int = 4, window_seconds: int = 120, whitelist: Optional[List[str]] = None):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.whitelist = whitelist or []
        
        self.ip_windows = defaultdict(deque)
        self.confirmed_incidents = {}

    def is_trusted(self, ip: str) -> bool:
        from src.config import is_whitelisted
        return is_whitelisted(ip, self.whitelist)

    def process_event(self, event: Dict[str, Any]):
        ip = event["ip"]

        # Игнорируем адреса из белого списка
        if self.is_trusted(ip):
            return

        current_time: datetime = event["timestamp"]
        username = event["username"]

        queue = self.ip_windows[ip]
        queue.append((current_time, username))

        # Очистка очереди за пределами скользящего окна
        while queue and (current_time - queue[0][0]).total_seconds() > self.window_seconds:
            queue.popleft()

        if len(queue) >= self.threshold:
            targeted_users = list({user for _, user in queue})
            attempts_in_window = len(queue)
            
            self.confirmed_incidents[ip] = {
                "ip": ip,
                "attempts": attempts_in_window,
                "targeted_users": targeted_users,
                "first_seen": queue[0][0].strftime("%H:%M:%S"),
                "last_seen": queue[-1][0].strftime("%H:%M:%S"),
                "severity": "CRITICAL" if attempts_in_window >= 10 else "HIGH",
                "window_seconds": self.window_seconds
            }

    def get_alerts(self) -> List[Dict[str, Any]]:
        return list(self.confirmed_incidents.values())