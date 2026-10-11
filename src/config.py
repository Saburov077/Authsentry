import ipaddress
import yaml
from typing import Dict, Any, List

DEFAULT_CONFIG: Dict[str, Any] = {
    "detection": {"threshold": 4, "window_seconds": 120},
    "log": {"file_path": "sample_logs/auth.log"},
    "mitigation": {"block_enabled": False, "dry_run": True},
    "whitelist": ["127.0.0.1"],
    "telegram": {"enabled": False, "bot_token": "", "chat_id": ""}
}

def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Loads configuration from YAML file, falling back to defaults on error."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict):
                return {**DEFAULT_CONFIG, **data}
    except FileNotFoundError:
        pass
    return DEFAULT_CONFIG

def is_whitelisted(ip_str: str, whitelist: List[str]) -> bool:
    """Checks whether an IP address matches any whitelist entry or CIDR subnet."""
    try:
        target_ip = ipaddress.ip_address(ip_str)
        for entry in whitelist:
            try:
                # Проверка подсети (например, 10.0.0.0/8) или одиночного IP
                network = ipaddress.ip_network(entry, strict=False)
                if target_ip in network:
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False