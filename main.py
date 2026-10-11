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

console = Console()

def print_alert_card(alert: dict):
    """Выводит карточку инцидента при обнаружении атаки в реальном времени."""
    console.print(f"\n[bold red]🚨 ОБНАРУЖЕНА АТАКА В РЕАЛЬНОМ ВРЕМЕНИ![/bold red]")
    console.print(f"  [cyan]IP:[/cyan] {alert['ip']} ([dim]{alert['geo']} | {alert['org']}[/dim])")
    console.print(f"  [magenta]Попыток:[/magenta] {alert['attempts']} в окне {alert['window_seconds']}с")
    console.print(f"  [yellow]Целевые логины:[/yellow] {', '.join(alert['targeted_users'])}")
    console.print(f"  [bold red]Уровень риска:[/bold red] {alert['severity']}\n")

def run_batch_analysis(args, detector):
    processed_lines = 0
    console.print(f"[bold cyan]Запуск анализа файла:[/bold cyan] {args.file}")

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                processed_lines += 1
                event = parse_auth_line(line)
                if event:
                    detector.process_event(event)
    except FileNotFoundError:
        console.print(f"[bold red]Ошибка:[/bold red] Файл {args.file} не найден.")
        return

    alerts = detector.get_alerts()

    for alert in alerts:
        intel = get_ip_intel(alert["ip"])
        alert["geo"] = f"{intel['country']} ({intel['city']})"
        alert["org"] = intel["org"]

    table = Table(title=f"\n[bold red]ОТЧЕТ ОБ ИНЦИДЕНТАХ (Обработано строк: {processed_lines})[/bold red]")
    table.add_column("Атакующий IP", style="cyan", no_wrap=True)
    table.add_column("Локация / Провайдер", style="blue")
    table.add_column("Попыток", justify="center", style="magenta")
    table.add_column("Целевые логины", style="yellow")
    table.add_column("Интервал", style="dim")
    table.add_column("Уровень риска", justify="center", style="bold red")

    if not alerts:
        console.print("\n[bold green]✓ Подозрительной активности и атак перебора не обнаружено.[/bold green]\n")
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

    if args.json:
        export_to_json(alerts, args.json)
        console.print(f"[bold green]✓ Отчет JSON сохранен:[/bold green] {args.json}")

    if args.csv:
        export_to_csv(alerts, args.csv)
        console.print(f"[bold green]✓ Отчет CSV сохранен:[/bold green] {args.csv}")

    if args.telegram:
        token, chat_id = args.telegram
        console.print("[dim]Отправка оповещения в Telegram...[/dim]")
        if send_telegram_alert(token, chat_id, alerts):
            console.print("[bold green]✓ Алерт успешно отправлен в Telegram![/bold green]")
        else:
            console.print("[bold red]✗ Не удалось отправить алерт в Telegram.[/bold red]")

def run_watch_mode(args, detector):
    console.print(f"[bold green]AuthSentry запущен в режиме постоянного мониторинга (--watch)[/bold green]")
    console.print(f"Отслеживание файла: [cyan]{args.file}[/cyan]. Нажмите [bold yellow]Ctrl + C[/bold yellow] для выхода.\n")
    
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

                        if args.telegram:
                            token, chat_id = args.telegram
                            send_telegram_alert(token, chat_id, [alert])
    except KeyboardInterrupt:
        console.print("\n[yellow]Мониторинг остановлен пользователем.[/yellow]")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="AuthSentry: SSH Brute-Force Log Analyzer & Incident Detector"
    )
    parser.add_argument(
        "--file", "-f",
        default="sample_logs/auth.log",
        help="Путь к файлу auth.log"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=4,
        help="Порог неудачных попыток (по умолчанию: 4)"
    )
    parser.add_argument(
        "--window", "-w",
        type=int,
        default=120,
        help="Ширина временного окна в секундах (по умолчанию: 120)"
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Запустить режим непрерывного мониторинга в реальном времени (live tail)"
    )
    parser.add_argument(
        "--json",
        metavar="OUTPUT_PATH",
        help="Путь для сохранения отчета в формате JSON"
    )
    parser.add_argument(
        "--csv",
        metavar="OUTPUT_PATH",
        help="Путь для сохранения отчета в формате CSV"
    )
    parser.add_argument(
        "--telegram",
        nargs=2,
        metavar=("BOT_TOKEN", "CHAT_ID"),
        help="Отправить алерт в Telegram: передайте TOKEN и CHAT_ID"
    )
    args = parser.parse_args()

    detector = BruteForceDetector(threshold=args.threshold, window_seconds=args.window)

    if args.watch:
        run_watch_mode(args, detector)
    else:
        run_batch_analysis(args, detector)

if __name__ == "__main__":
    main()