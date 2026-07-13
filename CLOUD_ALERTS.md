# Xerox Cloud Critical Alerts

Este monitor consulta Xerox Cloud 3 veces al dia y envia las printers en estado `CRITICAL` por Telegram o correo.

## 1. Serial numbers

Crea `cloud_serials.txt` en esta carpeta, uno por linea:

```text
YEQ142895
HQH823013
YEQ142901
```

## 2. Telegram

1. En Telegram abre `@BotFather`.
2. Crea un bot con `/newbot`.
3. Copia el token.
4. Envia un mensaje cualquiera a tu bot.
5. Obtiene tu chat id.

Luego en PowerShell:

```powershell
setx TELEGRAM_BOT_TOKEN "tu_token"
setx TELEGRAM_CHAT_ID "tu_chat_id"
```

Cierra y abre PowerShell despues de usar `setx`.

## 3. Correo opcional

Tambien puedes usar SMTP:

```powershell
setx SMTP_USER "tu_correo@gmail.com"
setx SMTP_PASS "tu_app_password"
setx MAIL_TO "telefono_o_correo_destino@example.com"
```

Para Gmail, `SMTP_PASS` debe ser un App Password, no tu password normal.

## 4. Probar una vez

```powershell
cd C:\Joan\MonitorXeroxWeb
.\venv\Scripts\python.exe monitor_cloud_alerts.py --once
```

## 5. Programar manualmente 3 veces al dia

Abre Windows Task Scheduler:

```powershell
taskschd.msc
```

Crea una tarea nueva con estos valores:

- Name: `Xerox Cloud Critical Alerts`
- Trigger: Daily
- Times: `08:00`, `13:00`, `17:00`
- Action: Start a program
- Program/script:

```text
C:\Joan\MonitorXeroxWeb\venv\Scripts\python.exe
```

- Add arguments:

```text
monitor_cloud_alerts.py --once
```

- Start in:

```text
C:\Joan\MonitorXeroxWeb
```

## 6. Logs

Si quieres guardar log, cambia los argumentos a:

```text
monitor_cloud_alerts.py --once
```

Y revisa el History de la tarea en Task Scheduler.
