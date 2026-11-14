@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\activate.bat" (
  echo Please run START_FRAUDBEACON.bat once to install the project environment first.
  pause
  exit /b 1
)
call ".venv\Scripts\activate.bat"
echo This downloads the public UCI English SMS spam dataset and trains a separate English-only model.
echo It does NOT replace or validate Arabic / international phishing performance.
echo.
python train_uci_baseline.py
if errorlevel 1 (
  echo Training failed. Check the network and error above.
) else (
  echo Finished. Restart FraudBeacon AI to load the optional English model.
)
pause
