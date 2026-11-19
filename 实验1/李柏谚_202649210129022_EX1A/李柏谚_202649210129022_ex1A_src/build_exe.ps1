# Build a self-contained Windows executable with PyInstaller.
#
# Npcap is still required on the target machine (a kernel driver cannot be
# bundled into a Python executable).
#
#   powershell -ExecutionPolicy Bypass -File build_exe.ps1

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$python = "python"
if (Test-Path ".venv\Scripts\python.exe") {
    $python = ".venv\Scripts\python.exe"
}

& $python -m pip install --upgrade pyinstaller
if ($LASTEXITCODE -ne 0) { throw "failed to install PyInstaller" }

$args = @(
    "--noconfirm", "--clean", "--windowed", "--onefile",
    "--name", "NetSniffer1A",
    "--add-data", "samples;samples",
    "--add-data", "docs;docs",
    "main.py"
)
if (Test-Path "assets\netsniffer.ico") {
    $args = @("--icon", "assets\netsniffer.ico") + $args
}

& $python -m PyInstaller @args
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

Write-Host ""
Write-Host "Built: dist\NetSniffer1A.exe"
Write-Host "The target machine still needs Npcap (https://npcap.com/)."
