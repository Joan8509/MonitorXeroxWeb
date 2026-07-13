r"""
Monitor Xerox Cloud serials and notify when printers become CRITICAL.

Notification options:
- Telegram: set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.
- Email: set SMTP_USER, SMTP_PASS, MAIL_TO. Optional SMTP_HOST/SMTP_PORT.

Serial sources:
- CLOUD_ALERT_SERIALS environment variable, separated by commas or new lines.
- cloud_serials.txt in this folder, one serial per line.

Examples:
  .\venv\Scripts\python.exe monitor_cloud_alerts.py --once
  .\venv\Scripts\python.exe monitor_cloud_alerts.py --loop --interval-minutes 30
"""

from __future__ import annotations

import argparse
import json
import os
import smtplib
import time
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Iterable
try:
    import winreg
except ImportError:
    winreg = None

import requests

from cloud_routes import (
    _parse_remaining_pct,
    _printer_status,
    get_project_printers,
    load_inventory_excel,
    parse_serials,
)


BASE_DIR = Path(__file__).resolve().parent
SERIALS_FILE = BASE_DIR / "cloud_serials.txt"
STATE_FILE = BASE_DIR / ".cloud_alert_state.json"

SUPPLY_FIELDS = [
    ("Toner", "toner"),
    ("Drum", "drum"),
    ("Fuser", "fuser"),
    ("Transfer", "transfer_roller"),
    ("Transfer Belt Cleaner", "transfer_belt_cleaner"),
    ("Second Bias Transfer Roll", "second_bias_transfer_roll"),
    ("Waste Toner", "waste_toner"),
]


def get_config(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value:
        return value
    if winreg is None:
        return default
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value) if value else default
    except OSError:
        return default


def read_serials() -> list[str]:
    env_value = os.getenv("CLOUD_ALERT_SERIALS", "")
    if env_value.strip():
        return parse_serials(env_value)

    if SERIALS_FILE.exists():
        return parse_serials(SERIALS_FILE.read_text(encoding="utf-8"))

    return []


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def supply_values(printer: dict) -> list[tuple[str, str, int | None]]:
    values = []
    for label, key in SUPPLY_FIELDS:
        raw = printer.get(key, "")
        pct = _parse_remaining_pct(raw)
        if raw not in (None, ""):
            values.append((label, str(raw), pct))
    return values


def critical_reason(printer: dict) -> str:
    lows = []
    for label, raw, pct in supply_values(printer):
        if pct is not None and pct < 20:
            lows.append(f"{label} {pct}%")
    return ", ".join(lows) if lows else "Critical status"


def printer_signature(printer: dict) -> str:
    values = [
        str(printer.get("serial", "")),
        str(printer.get("model", "")),
        _printer_status(printer),
    ]
    values.extend(f"{key}={printer.get(key, '')}" for _, key in SUPPLY_FIELDS)
    return "|".join(values)


def format_message(critical: list[dict], missing: Iterable[str] = ()) -> str:
    now = datetime.now().strftime("%Y-%m-%d %I:%M %p")
    lines = [
        "Xerox Cloud critical supplies",
        f"Checked: {now}",
        f"Critical printers: {len(critical)}",
        "",
    ]

    for printer in critical:
        lines.append(f"{printer.get('model') or 'Unknown model'} | {printer.get('serial') or 'No serial'}")
        if printer.get("ip"):
            lines.append(f"IP: {printer.get('ip')}")
        if printer.get("business"):
            lines.append(f"Location: {printer.get('business')}")
        reason = critical_reason(printer)
        lines.append(f"Reason: {reason}")
        for label, raw, pct in supply_values(printer):
            if pct is not None:
                lines.append(f"- {label}: {pct}%")
            else:
                lines.append(f"- {label}: {raw}")
        lines.append("")

    missing_list = list(missing)
    if missing_list:
        lines.append("Not found:")
        lines.append(", ".join(missing_list))

    return "\n".join(lines).strip()


def send_telegram(message: str) -> bool:
    token = get_config("TELEGRAM_BOT_TOKEN")
    chat_id = get_config("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    response = requests.post(
        url,
        json={"chat_id": chat_id, "text": message[:3900]},
        timeout=20,
    )
    response.raise_for_status()
    return True


def send_email(subject: str, body: str) -> bool:
    smtp_user = get_config("SMTP_USER")
    smtp_pass = get_config("SMTP_PASS")
    mail_to = get_config("MAIL_TO")
    if not smtp_user or not smtp_pass or not mail_to:
        return False

    smtp_host = get_config("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(get_config("SMTP_PORT", "587"))

    msg = EmailMessage()
    msg["From"] = smtp_user
    msg["To"] = mail_to
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
    return True


def notify(message: str) -> bool:
    sent = False
    errors = []

    try:
        sent = send_telegram(message) or sent
    except Exception as exc:
        errors.append(f"Telegram failed: {exc}")

    try:
        sent = send_email("[Xerox Cloud] Critical printer supplies", message) or sent
    except Exception as exc:
        errors.append(f"Email failed: {exc}")

    if not sent:
        print(message)
        print()
        print("[WARN] No notification provider configured. Set TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID or SMTP_USER/SMTP_PASS/MAIL_TO.")

    for error in errors:
        print(f"[WARN] {error}")

    return sent


def run_once(repeat_minutes: int) -> int:
    serials = read_serials()
    if not serials:
        print(f"[ERROR] No serials found. Create {SERIALS_FILE.name} or set CLOUD_ALERT_SERIALS.")
        return 2

    inventory = load_inventory_excel()
    printers = get_project_printers(inventory=inventory, serials=serials)
    found = {str(printer.get("serial", "")).upper() for printer in printers}
    missing = [serial for serial in serials if serial.upper() not in found]

    critical = [printer for printer in printers if _printer_status(printer) == "CRITICAL"]
    now = int(time.time())
    state = load_state()
    previous = state.get("critical", {})
    repeat_seconds = max(1, repeat_minutes) * 60

    changed = []
    state_items = []
    for printer in critical:
        serial = str(printer.get("serial", "") or "UNKNOWN")
        signature = printer_signature(printer)
        previous_item = previous.get(serial, {})
        last_sent = int(previous_item.get("last_sent", 0) or 0)
        if previous_item.get("signature") != signature or now - last_sent >= repeat_seconds:
            changed.append(printer)
        state_items.append((serial, signature, last_sent, printer))

    if not critical:
        state["critical"] = {}
        state["last_check"] = now
        save_state(state)
        print("[OK] No critical printers found.")
        return 0

    if not changed:
        state["critical"] = {
            serial: {"signature": signature, "last_sent": last_sent}
            for serial, signature, last_sent, _printer in state_items
        }
        state["last_check"] = now
        save_state(state)
        print(f"[OK] {len(critical)} critical printer(s) still present, notification already sent.")
        return 0

    message = format_message(changed, missing=missing)
    sent = notify(message)
    state["critical"] = {
        serial: {
            "signature": signature,
            "last_sent": now if sent and printer in changed else last_sent,
        }
        for serial, signature, last_sent, printer in state_items
    }
    state["last_check"] = now
    save_state(state)
    if not sent:
        print(f"[ERROR] Notification failed for {len(changed)} critical printer(s).")
        return 3
    print(f"[OK] Notification processed for {len(changed)} critical printer(s).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor Xerox Cloud supplies and notify critical printers.")
    parser.add_argument("--once", action="store_true", help="Run one check and exit.")
    parser.add_argument("--loop", action="store_true", help="Run forever.")
    parser.add_argument("--interval-minutes", type=int, default=int(os.getenv("CLOUD_ALERT_INTERVAL_MINUTES", "30")))
    parser.add_argument("--repeat-minutes", type=int, default=int(os.getenv("CLOUD_ALERT_REPEAT_MINUTES", "360")))
    args = parser.parse_args()

    if not args.loop:
        try:
            return run_once(args.repeat_minutes)
        except Exception as exc:
            message = (
                "Xerox Cloud alert monitor failed\n"
                f"Checked: {datetime.now().strftime('%Y-%m-%d %I:%M %p')}\n"
                f"Error: {exc}"
            )
            notify(message)
            print(f"[ERROR] Monitor check failed: {exc}")
            return 4

    while True:
        try:
            run_once(args.repeat_minutes)
        except Exception as exc:
            message = (
                "Xerox Cloud alert monitor failed\n"
                f"Checked: {datetime.now().strftime('%Y-%m-%d %I:%M %p')}\n"
                f"Error: {exc}"
            )
            notify(message)
            print(f"[ERROR] Monitor check failed: {exc}")
        time.sleep(max(1, args.interval_minutes) * 60)


if __name__ == "__main__":
    raise SystemExit(main())
