from collections import defaultdict, deque
from datetime import datetime
from typing import List, Dict, Any

class BruteForceDetector:
    def __init__(self, threshold: int = 4, window_seconds: int = 120):
        """
        threshold: минимальное количество неудач для триггера.
        window_seconds: временное окно в секундах, за которое считаются неудачи.
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        
        # Хранилище очередей попыток: {ip: deque([(timestamp, username), ...])}
        self.ip_windows = defaultdict(deque)
        
        # Зафиксированные инциденты, чтобы не дублировать алерты
        self.confirmed_incidents = {}

    def process_event(self, event: Dict[str, Any]):
        ip = event["ip"]
        current_time: datetime = event["timestamp"]
        username = event["username"]

        queue = self.ip_windows[ip]
        queue.append((current_time, username))

        # Очищаем очередь: удаляем попытки, которые старше (current_time - window_seconds)
        while queue and (current_time - queue[0][0]).total_seconds() > self.window_seconds:
            queue.popleft()

        # Если внутри текущего окна накопилось >= threshold попыток
        if len(queue) >= self.threshold:
            targeted_users = list({user for _, user in queue})
            attempts_in_window = len(queue)
            
            # Обновляем или создаем карточку инцидента
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