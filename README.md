# AuthSentry 🛡️

**AuthSentry** — легковесная утилита командной строки (CLI) для синтаксического анализа журналов аутентификации Linux (`auth.log`), обнаружения атак перебора паролей (Brute-Force / Password Spraying) и оперативного оповещения специалистов по безопасности.

Соответствие матрице MITRE ATT&CK: **[T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)**.

---

## 🚀 Возможности

- **Парсинг логов OpenSSH:** извлечение IP-адресов, имен учетных записей, временных меток и статусов входа на базе регулярных выражений.
- **Детекция аномалий:** динамический подсчет неудачных попыток аутентификации с настраиваемым порогом срабатывания (`threshold`).
- **Оценка уровня риска:** категоризация инцидентов по степени критичности (`HIGH`, `CRITICAL`).
- **Интерактивный CLI:** визуализация результатов в терминале с помощью форматированных таблиц `rich`.
- **Экспорт данных:** выгрузка инцидентов в форматах `JSON` и `CSV` для интеграции с SIEM/SOAR.
- **Интеграция с Telegram Bot API:** мгновенная отправка алертов об инцидентах дежурным администраторам и аналитикам SOC.

---

## 📁 Структура проекта

```text
authsentry/
├── sample_logs/
│   └── auth.log           # Тестовые данные журналов аутентификации
├── src/
│   ├── detector.py        # Логика трекинга IP и выявления атак
│   ├── notifier.py        # Модуль отправки алертов в Telegram
│   ├── parser.py          # Модуль разбора строк лога через Regex
│   └── reporter.py        # Экспорт отчетов в JSON и CSV
├── main.py                # Точка входа CLI
├── requirements.txt       # Зависимости проекта
└── README.md

🛠️ Установка и запуск
1. Клонирование репозитория
git clone [https://github.com/Saburov077/authsentry.git](https://github.com/Saburov077/authsentry.git)
cd authsentry

2. Настройка виртуального окружения
python -m venv .venv
source .venv/Scripts/activate   # Linux/Git Bash
# или: .\.venv\Scripts\Activate.ps1 # PowerShell

3. Установка зависимостей
pip install -r requirements.txt

💻 Примеры использования
Базовый анализ тестового лога:
python main.py

Задание собственного порога срабатывания (например, от 5 попыток):
python main.py --file /var/log/auth.log --threshold 5

Экспорт результатов в JSON и CSV:
python main.py --json incidents.json --csv incidents.csv

Анализ с отправкой алерта в Telegram:
python main.py --telegram "YOUR_BOT_TOKEN" "YOUR_CHAT_ID"

📋 Требования
Python 3.10+

Зависимости: rich, requests