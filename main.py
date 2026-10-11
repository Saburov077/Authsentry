import argparse
import sys
from rich.console import Console
from rich.table import Table
from src.parser import parse_auth_line
from src.detector import BruteForceDetector
from src.reporter import export_to_json, export_to_csv
from src.notifier import send_telegram_alert
from src.enricher import get_ip_intel
from src.watcher import follow_log
from src.responder import block_ip
from src.config import load_config

console = Console()

def handle_incident_response(alert: dict, should_block: bool, dry_run: bool):
    if should_block:
        ip = alert["ip"]
        result = block_ip(ip, dry_run=dry_run)
        if result["status"] == "simulated":
            console.print(f"  [bold cyan]🛡️ Active Response:[/bold cyan] {result['message']}")
        elif result["status"] == "applied":
            console.print(f"  [bold green]🛡️ Active Response:[/bold green] {result['message']}")
        else:
            console.print(f"  [bold red]🛡️ Active Response:[/bold red] {result['message']}")

def print_alert_card(alert: dict):
    console.print(f"\n[bold red]🚨 REAL-TIME ATTACK DETECTED![/bold red]")
    console.print(f"  [cyan]Attacker IP:[/cyan] {alert['ip']} ([dim]{alert['geo']} | {alert['org']}[/dim])")
    console.print(f"  [magenta]Failed Attempts:[/magenta] {alert['attempts']} in {alert['window_seconds']}s window")
    console.print(f"  [yellow]Targeted Accounts:[/yellow] {', '.join(alert['targeted_users'])}")
    console.print(f"  [bold red]Severity:[/bold red] {alert['severity']}")

def run_batch_analysis(file_path: str, detector: BruteForceDetector, block: bool, dry_run: bool, json_path: str, csv_path: str, tg_config: dict):
    processed_lines = 0
    console.print(f"[bold cyan]Initiating log analysis:[/bold cyan] {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                processed_lines += 1
                event = parse_auth_line(line)
                if event:
                    detector.process_event(event)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] File {file_path} not found.")
        return

    alerts = detector.get_alerts()

    for alert in alerts:
        intel = get_ip_intel(alert["ip"])
        alert["geo"] = f"{intel['country']} ({intel['city']})"
        alert["org"] = intel["org"]

    table = Table(title=f"\n[bold red]INCIDENT REPORT (Processed lines: {processed_lines})[/bold red]")
    table.add_column("Attacker IP", style="cyan", no_wrap=True)
    table.add_column("Geo / Network Provider", style="blue")
    table.add_column("Attempts", justify="center", style="magenta")
    table.add_column("Targeted Accounts", style="yellow")
    table.add_column("Time Window", style="dim")
    table.add_column("Severity", justify="center", style="bold red")

    if not alerts:
        console.print("\n[bold green]✓ No suspicious activity or brute-force patterns identified.[/bold green]\n")
        return

    for alert in alerts:
        users = ", ".join(alert["targeted_users"])
        location_info = f"{alert['geo']}\n[dim]{alert['org']}[/dim]"
        time_interval = f"{alert['first_seen']} - {alert['last_seen']}"
        table.add_row(
            alert["ip"],
            location_info,
            str(alert["attempts"]),
            users,
            time_interval,
            alert["severity"]
        )

    console.print(table)

    if block:
        console.print("\n[bold]Applying automated mitigation countermeasures:[/bold]")
        for alert in alerts:
            handle_incident_response(alert, should_block=True, dry_run=dry_run)

    if json_path:
        export_to_json(alerts, json_path)
        console.print(f"[bold green]✓ JSON report exported to:[/bold green] {json_path}")

    if csv_path:
        export_to_csv(alerts, csv_path)
        console.print(f"[bold green]✓ CSV report exported to:[/bold green] {csv_path}")

    if tg_config.get("enabled") and tg_config.get("bot_token") and tg_config.get("chat_id"):
        console.print("[dim]Dispatching Telegram alerts...[/dim]")
        if send_telegram_alert(tg_config["bot_token"], tg_config["chat_id"], alerts):
            console.print("[bold green]✓ Alert notification successfully sent to Telegram![/bold green]")
        else:
            console.print("[bold red]✗ Failed to dispatch Telegram alert.[/bold red]")

def run_watch_mode(file_path: str, detector: BruteForceDetector, block: bool, dry_run: bool, tg_config: dict):
    console.print(f"[bold green]AuthSentry running in continuous monitoring mode (--watch)[/bold green]")
    console.print(f"Monitoring log target: [cyan]{file_path}[/cyan]. Press [bold yellow]Ctrl + C[/bold yellow] to exit.\n")
    
    reported_ips = set()

    try:
        for line in follow_log(file_path):
            event = parse_auth_line(line)
            if event:
                detector.process_event(event)
                alerts = detector.get_alerts()
                
                for alert in alerts:
                    ip = alert["ip"]
                    if ip not in reported_ips:
                        reported_ips.add(ip)
                        intel = get_ip_intel(ip)
                        alert["geo"] = f"{intel['country']} ({intel['city']})"
                        alert["org"] = intel["org"]

                        print_alert_card(alert)
                        handle_incident_response(alert, should_block=block, dry_run=dry_run)

                        if tg_config.get("enabled") and tg_config.get("bot_token") and tg_config.get("chat_id"):
                            send_telegram_alert(tg_config["bot_token"], tg_config["chat_id"], [alert])
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring loop terminated by user.[/yellow]")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="AuthSentry: OpenSSH Brute-Force Log Analyzer & Incident Responder")
    parser.add_argument("--config", "-c", default="config.yaml", help="Path to config.yaml (default: config.yaml)")
    parser.add_argument("--file", "-f", help="Override log file path")
    parser.add_argument("--threshold", "-t", type=int, help="Override threshold limit")
    parser.add_argument("--window", "-w", type=int, help="Override sliding window in seconds")
    parser.add_argument("--watch", action="store_true", help="Enable continuous real-time monitoring mode")
    parser.add_argument("--block", action="store_true", help="Enable firewall blocking")
    parser.add_argument("--no-dry-run", action="store_true", help="Execute real firewall commands")
    parser.add_argument("--json", metavar="PATH", help="Export findings to JSON file")
    parser.add_argument("--csv", metavar="PATH", help="Export findings to CSV file")
    parser.add_argument("--telegram", nargs=2, metavar=("TOKEN", "CHAT_ID"), help="Provide Telegram credentials directly")
    args = parser.parse_args()

    cfg = load_config(args.config)

    file_path = args.file or cfg["log"]["file_path"]
    threshold = args.threshold if args.threshold is not None else cfg["detection"]["threshold"]
    window = args.window if args.window is not None else cfg["detection"]["window_seconds"]
    whitelist = cfg.get("whitelist", [])
    
    block = args.block or cfg["mitigation"]["block_enabled"]
    dry_run = not args.no_dry_run if args.no_dry_run else cfg["mitigation"]["dry_run"]

    tg_cfg = cfg.get("telegram", {})
    if args.telegram:
        tg_cfg = {"enabled": True, "bot_token": args.telegram[0], "chat_id": args.telegram[1]}

    detector = BruteForceDetector(threshold=threshold, window_seconds=window, whitelist=whitelist)

    if args.watch:
        run_watch_mode(file_path, detector, block=block, dry_run=dry_run, tg_config=tg_cfg)
    else:
        run_batch_analysis(file_path, detector, block=block, dry_run=dry_run, json_path=args.json, csv_path=args.csv, tg_config=tg_cfg)

if __name__ == "__main__":
    main()