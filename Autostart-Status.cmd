@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\Autostart.ps1" -Mode Status
set "taskResult=%errorlevel%"
pause
exit /b %taskResult%
