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

console = Console()

def handle_incident_response(alert: dict, should_block: bool, dry_run: bool):
    """Executes automated mitigation actions."""
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
    """Displays incident summary in real-time monitoring mode."""
    console.print(f"\n[bold red]🚨 REAL-TIME ATTACK DETECTED![/bold red]")
    console.print(f"  [cyan]Attacker IP:[/cyan] {alert['ip']} ([dim]{alert['geo']} | {alert['org']}[/dim])")
    console.print(f"  [magenta]Failed Attempts:[/magenta] {alert['attempts']} in {alert['window_seconds']}s window")
    console.print(f"  [yellow]Targeted Accounts:[/yellow] {', '.join(alert['targeted_users'])}")
    console.print(f"  [bold red]Severity:[/bold red] {alert['severity']}")

def run_batch_analysis(args, detector):
    processed_lines = 0
    console.print(f"[bold cyan]Initiating log analysis:[/bold cyan] {args.file}")

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                processed_lines += 1
                event = parse_auth_line(line)
                if event:
                    detector.process_event(event)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] File {args.file} not found.")
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

    # Active defense mitigation
    if args.block:
        console.print("\n[bold]Applying automated mitigation countermeasures:[/bold]")
        for alert in alerts:
            handle_incident_response(alert, should_block=True, dry_run=args.dry_run)

    # Artifact export
    if args.json:
        export_to_json(alerts, args.json)
        console.print(f"[bold green]✓ JSON report exported to:[/bold green] {args.json}")

    if args.csv:
        export_to_csv(alerts, args.csv)
        console.print(f"[bold green]✓ CSV report exported to:[/bold green] {args.csv}")

    # Telegram notification
    if args.telegram:
        token, chat_id = args.telegram
        console.print("[dim]Dispatching Telegram alerts...[/dim]")
        if send_telegram_alert(token, chat_id, alerts):
            console.print("[bold green]✓ Alert notification successfully sent to Telegram![/bold green]")
        else:
            console.print("[bold red]✗ Failed to dispatch Telegram alert (check token and chat ID).[/bold red]")

def run_watch_mode(args, detector):
    console.print(f"[bold green]AuthSentry running in continuous monitoring mode (--watch)[/bold green]")
    console.print(f"Monitoring log target: [cyan]{args.file}[/cyan]. Press [bold yellow]Ctrl + C[/bold yellow] to exit.\n")
    
    reported_ips = set()

    try:
        for line in follow_log(args.file):
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
                        handle_incident_response(alert, should_block=args.block, dry_run=args.dry_run)

                        if args.telegram:
                            token, chat_id = args.telegram
                            send_telegram_alert(token, chat_id, [alert])
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring loop terminated by user.[/yellow]")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="AuthSentry: OpenSSH Brute-Force Log Analyzer & Incident Responder"
    )
    parser.add_argument(
        "--file", "-f",
        default="sample_logs/auth.log",
        help="Path to authentication log file (default: sample_logs/auth.log)"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=4,
        help="Failed attempts threshold (default: 4)"
    )
    parser.add_argument(
        "--window", "-w",
        type=int,
        default=120,
        help="Sliding time window in seconds (default: 120)"
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Enable continuous real-time monitoring mode (live tail)"
    )
    parser.add_argument(
        "--block",
        action="store_true",
        help="Trigger automated firewall mitigation for detected attacker IPs"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Simulate firewall countermeasures without executing commands (default: True)"
    )
    parser.add_argument(
        "--json",
        metavar="OUTPUT_PATH",
        help="Export findings to structured JSON file"
    )
    parser.add_argument(
        "--csv",
        metavar="OUTPUT_PATH",
        help="Export findings to CSV spreadsheet"
    )
    parser.add_argument(
        "--telegram",
        nargs=2,
        metavar=("BOT_TOKEN", "CHAT_ID"),
        help="Dispatch alerts via Telegram API: provide BOT_TOKEN and CHAT_ID"
    )
    args = parser.parse_args()

    detector = BruteForceDetector(threshold=args.threshold, window_seconds=args.window)

    if args.watch:
        run_watch_mode(args, detector)
    else:
        run_batch_analysis(args, detector)

if __name__ == "__main__":
    main()