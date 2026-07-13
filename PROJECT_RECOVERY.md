# Monitor Xerox Web - Recovery Guide

This project has two main parts:

1. Web dashboard: `app.py`, `cloud_routes.py`, `templates/cloud.html`
2. Critical supply alerts: `monitor_cloud_alerts.py` plus Windows Scheduled Tasks

## Open From This PC

Local app:

```powershell
.\venv\Scripts\python.exe run.py
```

Then open:

```text
http://127.0.0.1:5000/cloud
```

## Open From Phone / Any Network

Use the provided script:

```powershell
.\Start-MonitorXeroxPublic.ps1
```

It starts Flask on port `5001`, opens a Cloudflare quick tunnel, and prints a URL like:

```text
https://something.trycloudflare.com/cloud
```

Keep the PC awake. If the PC sleeps, restarts, or the tunnel closes, run the script again and use the new URL.

To stop the public tunnel:

```powershell
.\Stop-MonitorXeroxPublic.ps1
```

You can also double-click:

```text
Start Public App.cmd
Stop Public App.cmd
```

## Inventory Button

The dashboard uses:

```text
Inventario Printers.xlsx
```

That file contains Address, Business, Location, IP, and Model. It does not include serial numbers, so the app recovers serials by matching IPs against the older inventory file.

Current smart groups include:

- Gallardo
- Flagler
- 107th
- Dallas
- Hialeah
- Doral
- Finca
- Icon
- Unique
- Dale Solution
- Main Zoo

## Alerts

Manual test:

```powershell
.\venv\Scripts\python.exe monitor_cloud_alerts.py --once
```

Telegram configuration is read from Windows user environment variables:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

Serials are read from:

- `cloud_serials.txt`, or
- `CLOUD_ALERT_SERIALS` environment variable

Scheduled tasks currently used:

- `XeroxCloudMonitorAM`
- `XeroxCloudMonitorPM`

## Backup

Create a safe backup:

```powershell
.\Backup-MonitorXeroxProject.ps1
```

It creates a zip in `backups\` with code, templates, scripts, inventory, and Cloudflare binary.

It intentionally does not include secrets or live data:

- `auth.db`
- `users.db`
- `xerox_auth.json`
- `xerox_curl.txt`
- `cloud_serials.txt`
- `.cloud_alert_state.json`
- logs
- virtual environments

## Moving To Another PC

1. Extract the safe backup.
2. Install Python 3.11+.
3. Create a virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\pip.exe install -r requirements.txt
```

4. Restore private files manually if authorized:

```text
xerox_auth.json
cloud_serials.txt
auth.db / users.db if you need the same local login users
```

5. Set Telegram variables in Windows if alerts are needed.
6. Run `Start-MonitorXeroxPublic.ps1` for phone access.

## Security Notes

Do not use public URL shorteners for this app. Use the direct `trycloudflare.com` URL or configure a real Cloudflare named tunnel with an approved domain.