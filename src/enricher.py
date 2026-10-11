import ipaddress
import requests
from typing import Dict, Any

def get_ip_intel(ip_str: str) -> Dict[str, Any]:
    """
    Обогащает IP-адрес данными о геолокации и провайдере.
    Автоматически распознает локальные и серые адреса (RFC1918).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback:
            return {
                "country": "LAN (Private Network)",
                "city": "Internal",
                "org": "Local Infrastructure"
            }
    except ValueError:
        return {"country": "Unknown", "city": "Unknown", "org": "Invalid IP"}

    # Запрос к бесплатному GeoIP / ASN сервису
    url = f"http://ip-api.com/json/{ip_str}?fields=status,country,city,isp,org"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "org": data.get("org") or data.get("isp") or "Unknown"
                }
    except requests.RequestException:
        pass

    return {
        "country": "Lookup Failed",
        "city": "N/A",
        "org": "N/A"
    }