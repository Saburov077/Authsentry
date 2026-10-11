import argparse
from rich.console import Console
from rich.table import Table
from src.parser import parse_auth_line
from src.detector import BruteForceDetector
from src.reporter import export_to_json, export_to_csv
from src.notifier import send_telegram_alert

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="AuthSentry: SSH Brute-Force Log Analyzer & Incident Detector"
    )
    parser.add_argument(
        "--file", "-f",
        default="sample_logs/auth.log",
        help="Путь к файлу auth.log (по умолчанию: sample_logs/auth.log)"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=4,
        help="Порог неудачных попыток для срабатывания алерта (по умолчанию: 4)"
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

    detector = BruteForceDetector(threshold=args.threshold)
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

    # Отрисовка таблицы результатов
    table = Table(title=f"\n[bold red]ОТЧЕТ ОБ ИНЦИДЕНТАХ (Обработано строк: {processed_lines})[/bold red]")
    table.add_column("Атакующий IP", style="cyan", no_wrap=True)
    table.add_column("Попыток", justify="center", style="magenta")
    table.add_column("Целевые логины", style="yellow")
    table.add_column("Первая попытка", style="dim")
    table.add_column("Крайняя попытка", style="dim")
    table.add_column("Уровень риска", justify="center", style="bold red")

    if not alerts:
        console.print("\n[bold green]✓ Подозрительной активности и атак перебора не обнаружено.[/bold green]\n")
        return

    for alert in alerts:
        users = ", ".join(alert["targeted_users"])
        table.add_row(
            alert["ip"],
            str(alert["attempts"]),
            users,
            alert["first_seen"],
            alert["last_seen"],
            alert["severity"]
        )

    console.print(table)

    # Экспорт результатов
    if args.json:
        export_to_json(alerts, args.json)
        console.print(f"[bold green]✓ Отчет JSON сохранен:[/bold green] {args.json}")

    if args.csv:
        export_to_csv(alerts, args.csv)
        console.print(f"[bold green]✓ Отчет CSV сохранен:[/bold green] {args.csv}")

    # Отправка в Telegram
    if args.telegram:
        token, chat_id = args.telegram
        console.print("[dim]Отправка оповещения в Telegram...[/dim]")
        if send_telegram_alert(token, chat_id, alerts):
            console.print("[bold green]✓ Алерт успешно отправлен в Telegram![/bold green]")
        else:
            console.print("[bold red]✗ Не удалось отправить алерт в Telegram (проверьте токен и chat_id).[/bold red]")

if __name__ == "__main__":
    main()