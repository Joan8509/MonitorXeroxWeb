"""
auto_alert_supplies.py
----------------------
Revisa tus impresoras por SNMP (usando tu mismo app_ok.py) y manda un email
si encuentra algún consumible con % <= THRESHOLD.

Programado para correr con Windows Task Scheduler a las 8:30 AM y 3:30 PM.
"""

import os
import sys
import smtplib
from email.message import EmailMessage
from datetime import datetime

# ===================== AJUSTES =====================
THRESHOLD = 10  # alerta si pct <= 10
IPS_FILE = r"C:\MonitorXeroxWeb\ips.txt"  # una IP por linea

# Gmail SMTP
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

# Estas 3 variables las pondrás con setx (más abajo te digo cómo)
SMTP_USER = os.getenv("SMTP_USER", "")  # ej: jjperez8509@gmail.com
SMTP_PASS = os.getenv("SMTP_PASS", "")  # App Password de Gmail (NO tu password normal)
MAIL_TO   = os.getenv("MAIL_TO", "")    # a quién enviar (puede ser el mismo correo)

# SNMP
SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "public")
SNMP_TIMEOUT = int(os.getenv("SNMP_TIMEOUT", "3"))

# Si quieres que el correo incluya impresoras "offline", ponlo en True
INCLUDE_OFFLINE_ERRORS = False


# ===================== IMPORTAR TU SNMP =====================
# Este import reutiliza tu función principal SNMP del app_ok.py
try:
    # Importa desde C:\MonitorXeroxWeb (donde estará este script)
    from app_ok import fetch_supplies_generic
except Exception as e:
    print(f"[ERROR] No pude importar fetch_supplies_generic desde app_ok.py: {e}")
    print("Asegúrate de que este script esté en C:\\MonitorXeroxWeb y que ahí exista app_ok.py")
    sys.exit(1)


def read_ips(path: str) -> list[str]:
    ips = new_func()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            ips.append(ip)
    return ips

def new_func():
    ips: list[str] = []
    return ips


def _to_float(x):
    try:
        return float(x)
    except Exception:
        return None


def low_items_from_result(result: dict, threshold: int) -> list[dict]:
    low: list[dict] = []
    for it in (result.get("items") or []):
        pct = it.get("pct", None)
        pct_f = _to_float(pct)
        if pct_f is None:
            continue
        if pct_f <= threshold:
            low.append({
                "name": it.get("name") or it.get("desc") or "Unknown",
                "pct": pct_f
            })
    return low


def send_email(subject: str, body: str):
    if not SMTP_USER or not SMTP_PASS or not MAIL_TO:
        raise RuntimeError("Faltan SMTP_USER / SMTP_PASS / MAIL_TO (variables de entorno).")

    msg = EmailMessage()
    msg["From"] = SMTP_USER
    msg["To"] = MAIL_TO
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)


def main():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not os.path.exists(IPS_FILE):
        print(f"[ERROR] No existe el archivo de IPs: {IPS_FILE}")
        print("Crea C:\\MonitorXeroxWeb\\ips.txt con una IP por línea.")
        sys.exit(1)

    ips = read_ips(IPS_FILE)
    if not ips:
        print("[ERROR] ips.txt está vacío.")
        sys.exit(1)

    alerts = []  # (ip, printer_name, model, low_items)
    offline = []  # (ip, error)

    for ip in ips:
        try:
            r = fetch_supplies_generic(ip, SNMP_COMMUNITY, SNMP_TIMEOUT)
            low = low_items_from_result(r, THRESHOLD)
            if low:
                alerts.append((ip, r.get("printer_name", ""), r.get("model", ""), low))
        except Exception as e:
            if INCLUDE_OFFLINE_ERRORS:
                offline.append((ip, str(e)))

    # Si no hay nada bajo, no enviamos correo (para no spamearte)
    if not alerts and not offline:
        print(f"[OK] {now} - No hay consumibles <= {THRESHOLD}%. No se envió email.")
        return

    subject = f"[ALERTA Supplies] <= {THRESHOLD}% - {now}"
    lines = [f"Reporte automático - {now}", f"Umbral: <= {THRESHOLD}%", ""]

    if alerts:
        lines.append("IMPRESORAS CON SUPPLIES BAJOS:")
        for ip, pname, model, low in alerts:
            lines.append(f"- {ip} | {pname} | {model}")
            for it in low:
                lines.append(f"    • {it['name']}: {it['pct']}%")
            lines.append("")
    else:
        lines.append("No se detectaron supplies bajos.")
        lines.append("")

    if offline:
        lines.append("IMPRESORAS CON ERROR / OFFLINE:")
        for ip, err in offline:
            lines.append(f"- {ip}: {err}")
        lines.append("")

    body = "\n".join(lines)

    send_email(subject, body)
    print(f"[OK] {now} - Email enviado ({len(alerts)} con alerta).")


if __name__ == "__main__":
    main()
