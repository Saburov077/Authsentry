import json
import csv
from typing import List, Dict, Any

def export_to_json(alerts: List[Dict[str, Any]], filepath: str) -> None:
    """Сохраняет список алертов в структурированный JSON-файл."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=4, ensure_ascii=False)

def export_to_csv(alerts: List[Dict[str, Any]], filepath: str) -> None:
    """Экспортирует найденные инциденты в CSV-таблицу."""
    if not alerts:
        return

    fieldnames = ["ip", "attempts", "targeted_users", "first_seen", "last_seen", "severity"]
    
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            row = alert.copy()
            # Преобразуем список логинов в строку через запятую для плоской таблицы CSV
            row["targeted_users"] = ", ".join(row["targeted_users"])
            writer.writerow(row)