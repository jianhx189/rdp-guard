@echo off
rem RDP Guard scheduled task registration (2026-08-03) - schtasks based, no PowerShell/AMSI
rem Import task XML files from tasks\ folder (UTF-16). Requires elevation.
schtasks /create /tn "wry-rdp-guard" /xml "E:\RDP-Guard\tasks\wry-rdp-guard.xml" /f
schtasks /create /tn "wry-rdp-report" /xml "E:\RDP-Guard\tasks\wry-rdp-report.xml" /f
echo.
echo ===== registration done, verify =====
schtasks /query /tn "wry-rdp-guard" /v /fo LIST
schtasks /query /tn "wry-rdp-report" /v /fo LIST
