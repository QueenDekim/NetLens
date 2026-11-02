@echo off
cd /d "%~dp0"
"%~dp0third-party\python\python.exe" -m netlens %*
if errorlevel 1 pause
