@echo off
setlocal
if "%~1"=="" (
    echo Usage: Import-Profile.cmd path-to-client-profile.json
    exit /b 2
)
"%~dp0GoodGoodStudy.exe" --import-profile "%~f1"
exit /b %errorlevel%
