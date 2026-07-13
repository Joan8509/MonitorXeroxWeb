param(
    [int]$Port = 5001
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$Python = Join-Path $Root "venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    $Python = "python"
}

$Cloudflared = Join-Path $Root "cloudflared.exe"
if (-not (Test-Path $Cloudflared)) {
    throw "cloudflared.exe was not found in $Root"
}

Write-Host "Stopping any old Flask process on port $Port..."
Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }

Write-Host "Stopping old Cloudflare quick tunnels..."
Get-Process -Name cloudflared -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

$appOut = Join-Path $Root "public_app.out.log"
$appErr = Join-Path $Root "public_app.err.log"
$tunnelOut = Join-Path $Root "public_tunnel.out.log"
$tunnelErr = Join-Path $Root "public_tunnel.err.log"
Remove-Item -LiteralPath $appOut,$appErr,$tunnelOut,$tunnelErr -ErrorAction SilentlyContinue

$code = "from app import app; app.run(debug=False, host='0.0.0.0', port=$Port, threaded=True)"
Write-Host "Starting Flask on http://127.0.0.1:$Port ..."
Start-Process -FilePath $Python -ArgumentList @("-c", $code) -WorkingDirectory $Root -WindowStyle Hidden -RedirectStandardOutput $appOut -RedirectStandardError $appErr
Start-Sleep -Seconds 3

if (-not (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)) {
    Write-Host "Flask did not start. Check public_app.err.log" -ForegroundColor Red
    Get-Content $appErr -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "Starting Cloudflare Tunnel..."
Start-Process -FilePath $Cloudflared -ArgumentList @("tunnel", "--url", "http://127.0.0.1:$Port") -WorkingDirectory $Root -WindowStyle Hidden -RedirectStandardOutput $tunnelOut -RedirectStandardError $tunnelErr

$url = $null
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    $text = ""
    if (Test-Path $tunnelErr) { $text += Get-Content $tunnelErr -Raw -ErrorAction SilentlyContinue }
    if (Test-Path $tunnelOut) { $text += Get-Content $tunnelOut -Raw -ErrorAction SilentlyContinue }
    $match = [regex]::Match($text, "https://[a-z0-9-]+\.trycloudflare\.com")
    if ($match.Success) {
        $url = $match.Value
        break
    }
}

if ($url) {
    Write-Host ""
    Write-Host "Open this on your phone:" -ForegroundColor Green
    Write-Host "$url/cloud" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Keep this PC awake while you use the URL."
} else {
    Write-Host "Tunnel started, but the URL was not found yet. Check public_tunnel.err.log" -ForegroundColor Yellow
}