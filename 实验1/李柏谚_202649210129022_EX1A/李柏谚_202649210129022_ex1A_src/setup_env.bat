@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "NOPAUSE="
if /I "%~1"=="--no-pause" set "NOPAUSE=1"

echo ============================================================
echo  NetSniffer 1A - environment check
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 goto :no_python

echo [1/3] Python
python -c "import sys, platform; print('  executable:', sys.executable); print('  version  :', sys.version.split()[0]); print('  arch     :', platform.architecture()[0])"
if errorlevel 1 goto :bad_python

python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) and sys.maxsize > 2**32 else 1)"
if errorlevel 1 (
    echo.
    echo [ERROR] 64-bit Python 3.10 or newer is required.
    goto :fail
)

echo.
echo [2/3] PyQt5
python -c "import PyQt5" >nul 2>nul
if errorlevel 1 (
    echo   PyQt5 not found; installing into the current Python...
    python -m pip install --disable-pip-version-check --no-input --prefer-binary -r requirements.txt
    if errorlevel 1 (
        echo.
        echo [ERROR] PyQt5 installation failed. Check network/proxy, or run:
        echo         python -m pip install -r requirements.txt
        goto :fail
    )
    python -c "import PyQt5" >nul 2>nul
    if errorlevel 1 goto :fail
    echo   PyQt5 installed.
) else (
    echo   PyQt5 is already available; no virtual environment is needed.
)

echo.
echo [3/3] pytest - optional
python -c "import pytest" >nul 2>nul
if errorlevel 1 (
    echo   [WARN] pytest not found; run_tests.bat will not work.
    echo          Install it with: python -m pip install pytest
) else (
    echo   pytest is available.
)

echo.
echo Environment is ready. Run one of:
echo    run.bat          start the GUI
echo    run_demo.bat     open the sample pcap
echo    run_tests.bat    run the unit tests
echo.
echo If an old .venv is broken, run.bat will ignore it and use the current Python.
if not defined NOPAUSE pause
exit /b 0

:no_python
echo [ERROR] python was not found on PATH.
echo         Install 64-bit Python 3.10+ and enable "Add Python to PATH".
goto :fail

:bad_python
echo [ERROR] Unable to run python.
goto :fail

:fail
echo.
echo Environment setup did not complete. You can still try:
echo    python main.py
echo if that Python already has PyQt5.
if not defined NOPAUSE pause
exit /b 1
