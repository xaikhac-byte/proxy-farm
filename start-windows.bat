@echo off
rem Proxy Farm - double-click to install / start on Windows.
rem All checks and messages are in run.ps1 (Vietnamese).
chcp 65001 >nul
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
echo.
pause
