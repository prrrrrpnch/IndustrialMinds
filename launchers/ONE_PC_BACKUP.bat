@echo off
rem BACKUP (Windows): the whole system on THIS computer, loopback only. Double-click this file.
cd /d "%~dp0.."
if not exist ".venv\Scripts\activate.bat" (
  echo No .venv found in %CD% - run the one-time setup first.
  pause
  exit /b 1
)
call ".venv\Scripts\activate.bat"
python launchers\one_pc_demo.py
pause
