@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title FraudBeacon AI - Local Launcher

echo ========================================================
echo   FRAUDBEACON AI - INTERNATIONAL CYBER SAFETY WORKSPACE
echo ========================================================
echo.

set "PYTHON_CMD="
py -3.12 --version >nul 2>&1
if not errorlevel 1 set "PYTHON_CMD=py -3.12"
if not defined PYTHON_CMD (
  py -3.11 --version >nul 2>&1
  if not errorlevel 1 set "PYTHON_CMD=py -3.11"
)
if not defined PYTHON_CMD (
  python --version >nul 2>&1
  if not errorlevel 1 set "PYTHON_CMD=python"
)
if not defined PYTHON_CMD (
  echo Python 3.11 or 3.12 was not found.
  echo Install it from https://www.python.org/downloads/windows/
  echo IMPORTANT: enable "Add Python to PATH" during installation.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo [1/3] Creating an isolated Python environment...
  %PYTHON_CMD% -m venv .venv
  if errorlevel 1 goto fail
)

call ".venv\Scripts\activate.bat"
if not exist ".venv\fraudbeacon_deps_installed.txt" (
  echo [2/3] Installing application components. This is needed only once...
  python -m pip install --upgrade pip
  if errorlevel 1 goto fail
  python -m pip install -r requirements.txt
  if errorlevel 1 goto fail
  echo Installed on %date% %time%> ".venv\fraudbeacon_deps_installed.txt"
) else (
  echo Dependencies are already installed.
)

echo [3/3] Starting FraudBeacon AI in your browser...
echo Keep this black window open while using the application.
start "" cmd /c "timeout /t 3 /nobreak ^>nul ^& start http://127.0.0.1:8501"
python -m streamlit run streamlit_app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true
exit /b 0

:fail
echo.
echo Setup or launch failed. Check the error above.
echo If the error mentions a missing Python version, install Python 3.11 or 3.12.
pause
exit /b 1
