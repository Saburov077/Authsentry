import platform
import subprocess
from typing import Dict, Any

def block_ip(ip: str, dry_run: bool = True) -> Dict[str, Any]:
    """
    Generates and optionally applies firewall drop rules.
    Supports Linux (iptables) and Windows (netsh).
    """
    os_type = platform.system().lower()

    if os_type == "linux":
        command = f"iptables -I INPUT -s {ip} -j DROP"
    elif os_type == "windows":
        rule_name = f"AuthSentry_Block_{ip.replace('.', '_')}"
        command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
    else:
        command = f"# Unsupported OS: {os_type}"

    if dry_run:
        return {
            "status": "simulated",
            "command": command,
            "message": f"[DRY-RUN] Mitigation simulated. Command: {command}"
        }

    try:
        subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return {
            "status": "applied",
            "command": command,
            "message": f"Successfully blocked IP {ip} via system firewall."
        }
    except subprocess.CalledProcessError as err:
        return {
            "status": "failed",
            "command": command,
            "message": f"Firewall command failed: {err.stderr.strip()}"
        }