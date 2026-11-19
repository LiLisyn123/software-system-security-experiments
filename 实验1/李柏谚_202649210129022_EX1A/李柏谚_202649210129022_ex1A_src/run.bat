@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PY=python"

rem Prefer a healthy .venv, but never let a broken virtual environment hide a
rem working system Python. A .venv created by an interrupted ensurepip run can
rem exist without pip or without PyQt5.
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import PyQt5" >nul 2>nul
    if not errorlevel 1 set "PY=.venv\Scripts\python.exe"
)

"%PY%" -c "import PyQt5" >nul 2>nul
if errorlevel 1 (
    echo [ERROR] PyQt5 is not available in: %PY%
    echo         Run setup_env.bat, or install it with:
    echo         python -m pip install -r requirements.txt
    pause
    exit /b 1
)

"%PY%" main.py %*
if errorlevel 1 pause
