@echo off
setlocal EnableDelayedExpansion

:: -----------------------------------------------------------------------------
::  Offline Log Forensic Analyzer - launcher
::  Usage:
::    run.bat              -> show this menu
::    run.bat dashboard    -> start the Dash dashboard
::    run.bat cli <file>   -> run the CLI pipeline against <file>
::    run.bat generate     -> generate sample logs then open the dashboard
::    run.bat test         -> run the test suite
:: -----------------------------------------------------------------------------

set "VENV_PYTHON=%~dp0.venv\Scripts\python.exe"
set "SETUP_MARKER=%~dp0.venv\.setup_ok"

:: First run on a fresh copy of this folder: no .venv yet -> build it here.
:: Needs Python 3.11+ on PATH and one internet connection for this step only;
:: every run after this works fully offline.
if not exist "%VENV_PYTHON%" (
    echo.
    echo  First run detected - setting up the environment. This happens once
    echo  and needs an internet connection; every run after this is offline.
    echo.
    where python >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Python was not found on PATH.
        echo         Install Python 3.11+ from https://www.python.org/downloads/
        echo         and make sure "Add python.exe to PATH" is checked during install.
        pause
        exit /b 1
    )
    python -m venv "%~dp0.venv"
    if errorlevel 1 (
        echo [ERROR] Failed to create the virtual environment.
        pause
        exit /b 1
    )
)

:: Install/verify dependencies once per fresh .venv (marker file skips this
:: on every later launch so startup stays fast and offline).
if not exist "%SETUP_MARKER%" (
    echo  Installing dependencies from requirements.txt ...
    "%VENV_PYTHON%" -m pip install --upgrade pip >nul
    "%VENV_PYTHON%" -m pip install -r "%~dp0requirements.txt"
    if errorlevel 1 (
        echo [ERROR] Dependency installation failed. See the output above.
        pause
        exit /b 1
    )
    echo  Installing the Playwright Chromium browser, used for PDF reports ...
    "%VENV_PYTHON%" -m playwright install chromium
    if errorlevel 1 (
        echo [WARNING] Playwright browser install failed. The dashboard will
        echo           still run; PDF export will not work until you re-run
        echo           this script or:  .venv\Scripts\playwright install chromium
    )
    echo ok > "%SETUP_MARKER%"
    echo.
    echo  Setup complete.
    echo.
)

:: Make sure there is sample data to look at on a first launch.
if not exist "%~dp0data\synthetic\firewall_logs.csv" (
    echo  No sample logs found - generating a starter dataset ...
    "%VENV_PYTHON%" -c "from src.generate_logs import generate_firewall_logs; from src.utils import ensure_directory; from pathlib import Path; p=Path('data/synthetic/firewall_logs.csv'); ensure_directory(p.parent); generate_firewall_logs(rows=8000, seed=42, profile='attack-heavy').to_csv(p, index=False); print(f'Saved 8000 rows to {p}')"
    echo.
)

:: -- No argument -> launch dashboard directly ---------------------------------
if "%~1"=="" goto :dashboard

:: -- Argument dispatch ---------------------------------------------------------
if /i "%~1"=="dashboard" goto :dashboard
if /i "%~1"=="cli"       goto :cli
if /i "%~1"=="generate"  goto :generate
if /i "%~1"=="test"      goto :test

echo [ERROR] Unknown command: %~1
goto :usage

:: -----------------------------------------------------------------------------
:menu
cls
echo.
echo  ================================================
echo       Offline Log Forensic Analyzer
echo  ================================================
echo   1. Launch Dash dashboard (recommended)
echo   2. Run CLI pipeline on an existing log file
echo   3. Generate sample logs + open dashboard
echo   4. Run test suite
echo   5. Exit
echo  ================================================
echo.
set /p "CHOICE= Enter option [1-5]: "

if "%CHOICE%"=="1" goto :dashboard
if "%CHOICE%"=="2" goto :cli_prompt
if "%CHOICE%"=="3" goto :generate
if "%CHOICE%"=="4" goto :test
if "%CHOICE%"=="5" exit /b 0

echo [ERROR] Invalid option.
goto :menu

:: -----------------------------------------------------------------------------
:dashboard
:: Do not start a second Dash process on the same local port. Multiple Python
:: servers on 8050 can make the browser alternate between old and new layouts.
powershell -NoProfile -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('127.0.0.1', 8050); exit 0 } catch { exit 1 } finally { $client.Dispose() }"
if not errorlevel 1 (
    echo.
    echo  Dashboard is already running at http://127.0.0.1:8050
    echo  A second server was not started. Refresh the browser for a fresh page.
    echo  To fully restart it, press Ctrl+C in the original dashboard window,
    echo  then run this file again.
    echo.
    echo  Press any key to close this duplicate launcher.
    pause >nul
    goto :eof
)

echo.
echo  Starting Dash dashboard ...
echo  Open http://127.0.0.1:8050 in your browser.
echo  Press Ctrl+C to stop.
echo.
"%VENV_PYTHON%" "%~dp0app.py"
goto :eof

:: -----------------------------------------------------------------------------
:cli_prompt
echo.
set /p "LOG_FILE= Path to log file (CSV / JSON / JSONL): "
if "!LOG_FILE!"=="" (
    echo [ERROR] No file path provided.
    goto :menu
)
goto :run_cli

:cli
set "LOG_FILE=%~2"
if "%LOG_FILE%"=="" (
    echo [ERROR] Provide a log file path.  Example:  run.bat cli data\synthetic\firewall_logs.csv
    exit /b 1
)
goto :run_cli

:run_cli
echo.
echo  Running CLI pipeline on: !LOG_FILE!
echo.
"%VENV_PYTHON%" "%~dp0main.py" --input "!LOG_FILE!" --config "%~dp0config.yaml" --output "%~dp0outputs"
echo.
echo  Outputs written to: %~dp0outputs
pause
goto :eof

:: -----------------------------------------------------------------------------
:generate
echo.
echo  Generating synthetic firewall logs ...
"%VENV_PYTHON%" -c "from src.generate_logs import generate_firewall_logs; from src.utils import ensure_directory; from pathlib import Path; p=Path('data/synthetic/firewall_logs.csv'); ensure_directory(p.parent); generate_firewall_logs(rows=50000, seed=42, profile='attack-heavy').to_csv(p, index=False); print(f'Saved {50000} rows to {p}')"
echo.
echo  Logs generated. Opening dashboard ...
goto :dashboard

:: -----------------------------------------------------------------------------
:test
echo.
echo  Running test suite ...
echo.
"%VENV_PYTHON%" -m pytest "%~dp0tests" --basetemp="%~dp0.pytest_temp" -o cache_dir="%~dp0.pytest_cache_new" -v
pause
goto :eof

:: -----------------------------------------------------------------------------
:usage
echo.
echo  Usage:
echo    run.bat                      - interactive menu
echo    run.bat dashboard            - Dash dashboard
echo    run.bat cli ^<log_file^>       - CLI pipeline
echo    run.bat generate             - generate sample data + dashboard
echo    run.bat test                 - run tests
echo.
exit /b 1
