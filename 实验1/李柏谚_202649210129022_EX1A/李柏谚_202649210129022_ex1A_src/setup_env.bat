@echo off
cd /d "%~dp0"
echo Creating virtual environment .venv ...
python -m venv .venv
if errorlevel 1 goto :error
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
echo.
echo Done. Run run.bat or run_demo.bat.
pause
exit /b 0

:error
echo Failed to create the virtual environment. Check that Python 3.10+ is on PATH.
pause
exit /b 1
