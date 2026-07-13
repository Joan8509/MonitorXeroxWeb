param(
    [string]$Destination = "backups"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = Join-Path $Root $Destination
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$zip = Join-Path $backupDir "MonitorXeroxWeb_SAFE_$stamp.zip"
$temp = Join-Path $env:TEMP "MonitorXeroxWeb_SAFE_$stamp"
Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $temp | Out-Null

$includeFiles = @(
    "app.py",
    "cloud_routes.py",
    "xerox_cloud.py",
    "monitor_cloud_alerts.py",
    "run.py",
    "requirements.txt",
    "CLOUD_ALERTS.md",
    "PROJECT_RECOVERY.md",
    "Backup-MonitorXeroxProject.ps1",
    "Start-MonitorXeroxPublic.ps1",
    "Stop-MonitorXeroxPublic.ps1",
    "Start Public App.cmd",
    "Stop Public App.cmd",
    "run_cloud_monitor.cmd",
    "cloud_serials.example.txt",
    "xerox_auth.example.json",
    "Inventario Printers.xlsx",
    "cloudflared.exe"
)

foreach ($file in $includeFiles) {
    $src = Join-Path $Root $file
    if (Test-Path $src) {
        Copy-Item -LiteralPath $src -Destination (Join-Path $temp $file) -Force
    }
}

foreach ($dir in @("templates", "static", "modules", "tests")) {
    $src = Join-Path $Root $dir
    if (Test-Path $src) {
        Copy-Item -LiteralPath $src -Destination (Join-Path $temp $dir) -Recurse -Force
    }
}

Compress-Archive -Path (Join-Path $temp "*") -DestinationPath $zip -Force
Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Safe backup created: $zip" -ForegroundColor Green
Write-Host "Not included: auth.db, users.db, xerox_auth.json, xerox_curl.txt, cloud_serials.txt, logs, venv."