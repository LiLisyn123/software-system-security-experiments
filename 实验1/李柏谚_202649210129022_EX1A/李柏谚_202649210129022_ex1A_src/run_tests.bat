@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PY=python"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import pytest" >nul 2>nul
    if not errorlevel 1 set "PY=.venv\Scripts\python.exe"
)

"%PY%" -m pytest %*
pause
