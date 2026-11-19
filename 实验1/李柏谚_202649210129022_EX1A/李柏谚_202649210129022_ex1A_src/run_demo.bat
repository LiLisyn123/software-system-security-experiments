@echo off
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" main.py --pcap samples\demo.pcap
) else (
    python main.py --pcap samples\demo.pcap
)

if errorlevel 1 pause
