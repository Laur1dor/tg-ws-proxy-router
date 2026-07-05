@echo off
REM Лаунчер панели управления (Windows).
cd /d "%~dp0"
python -m proxy.menu %*
