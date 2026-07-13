@echo off
cd /d "C:\Joan\MonitorXeroxWeb"
echo [%date% %time%] Iniciando monitor de Xerox Cloud>> "C:\Joan\MonitorXeroxWeb\cloud_monitor.log"
"C:\Joan\MonitorXeroxWeb\venv\Scripts\python.exe" "C:\Joan\MonitorXeroxWeb\monitor_cloud_alerts.py" --once >> "C:\Joan\MonitorXeroxWeb\cloud_monitor.log" 2>&1
echo [%date% %time%] Finalizado con codigo %ERRORLEVEL%>> "C:\Joan\MonitorXeroxWeb\cloud_monitor.log"
exit /b %ERRORLEVEL%
