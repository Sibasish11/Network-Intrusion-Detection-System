@echo off
title NIDS Terminal Cyber Console
cd /d "%~dp0"
if exist venv\Scripts\python.exe (
    venv\Scripts\python.exe cli.py %*
) else (
    python cli.py %*
)
pause
