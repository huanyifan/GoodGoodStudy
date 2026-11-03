@echo off
setlocal
if "%~1"=="" (
    echo Usage: Import-Key.cmd path-to-client-import.key
    exit /b 2
)
"%~dp0GoodGoodStudy.exe" --import-key "%~f1"
exit /b %errorlevel%
