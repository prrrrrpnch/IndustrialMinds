@echo off
rem LAPTOP 4 (Windows): the attack BUTTON panel. Double-click this file; the panel opens in your browser.
cd /d "%~dp0.."
if not exist ".venv\Scripts\activate.bat" (
  echo No .venv found in %CD% - run the one-time setup first.
  pause
  exit /b 1
)
call ".venv\Scripts\activate.bat"
python -m attacker.control_panel
pause
