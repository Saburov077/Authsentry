from datetime import datetime, timedelta
from src.detector import BruteForceDetector

def test_detector_triggers_above_threshold():
    detector = BruteForceDetector(threshold=3, window_seconds=60)
    now = datetime(2026, 10, 11, 12, 0, 0)

    for i in range(3):
        detector.process_event({
            "ip": "203.0.113.5",
            "username": f"user{i}",
            "timestamp": now + timedelta(seconds=i * 5)
        })

    alerts = detector.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "203.0.113.5"
    assert alerts[0]["attempts"] == 3

def test_detector_sliding_window_expiration():
    detector = BruteForceDetector(threshold=3, window_seconds=10)
    start_time = datetime(2026, 10, 11, 12, 0, 0)

    # Две попытки в начале
    detector.process_event({"ip": "198.51.100.2", "username": "admin", "timestamp": start_time})
    detector.process_event({"ip": "198.51.100.2", "username": "admin", "timestamp": start_time + timedelta(seconds=2)})

    # Третья попытка спустя 30 секунд (первые две должны выпасть из 10-секундного окна)
    detector.process_event({"ip": "198.51.100.2", "username": "admin", "timestamp": start_time + timedelta(seconds=30)})

    alerts = detector.get_alerts()
    assert len(alerts) == 0

def test_detector_ignores_whitelisted_ip():
    detector = BruteForceDetector(threshold=2, window_seconds=60, whitelist=["192.168.1.0/24"])
    now = datetime(2026, 10, 11, 12, 0, 0)

    for _ in range(5):
        detector.process_event({"ip": "192.168.1.50", "username": "root", "timestamp": now})

    assert len(detector.get_alerts()) == 0