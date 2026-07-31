@echo off
setlocal EnableDelayedExpansion

:: ─────────────────────────────────────────────────────────────────────────────
::  Offline Log Forensic Analyzer – launcher
::  Usage:
::    run.bat              → show this menu
::    run.bat dashboard    → start the Streamlit dashboard
::    run.bat cli <file>   → run the CLI pipeline against <file>
::    run.bat generate     → generate sample logs then open the dashboard
::    run.bat test         → run the test suite
:: ─────────────────────────────────────────────────────────────────────────────

set "VENV_PYTHON=%~dp0.venv\Scripts\python.exe"
set "VENV_STREAMLIT=%~dp0.venv\Scripts\streamlit.exe"

:: Verify the virtual-environment exists
if not exist "%VENV_PYTHON%" (
    echo [ERROR] Virtual environment not found at .venv\Scripts\python.exe
    echo         Run:  python -m venv .venv
    echo         Then: .venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)

:: ── No argument → launch dashboard directly ─────────────────────────────────
if "%~1"=="" goto :dashboard

:: ── Argument dispatch ────────────────────────────────────────────────────────
if /i "%~1"=="dashboard" goto :dashboard
if /i "%~1"=="cli"       goto :cli
if /i "%~1"=="generate"  goto :generate
if /i "%~1"=="test"      goto :test

echo [ERROR] Unknown command: %~1
goto :usage

:: ─────────────────────────────────────────────────────────────────────────────
:menu
cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║      Offline Log Forensic Analyzer                  ║
echo  ╠══════════════════════════════════════════════════════╣
echo  ║  1. Launch Streamlit dashboard (recommended)         ║
echo  ║  2. Run CLI pipeline on an existing log file         ║
echo  ║  3. Generate sample logs + open dashboard            ║
echo  ║  4. Run test suite                                   ║
echo  ║  5. Exit                                             ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
set /p "CHOICE= Enter option [1-5]: "

if "%CHOICE%"=="1" goto :dashboard
if "%CHOICE%"=="2" goto :cli_prompt
if "%CHOICE%"=="3" goto :generate
if "%CHOICE%"=="4" goto :test
if "%CHOICE%"=="5" exit /b 0

echo [ERROR] Invalid option.
goto :menu

:: ─────────────────────────────────────────────────────────────────────────────
:dashboard
echo.
echo  Starting Streamlit dashboard …
echo  Open http://localhost:8501 in your browser.
echo  Press Ctrl+C to stop.
echo.
"%VENV_PYTHON%" -m streamlit run "%~dp0app.py" --server.headless false
goto :eof

:: ─────────────────────────────────────────────────────────────────────────────
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

:: ─────────────────────────────────────────────────────────────────────────────
:generate
echo.
echo  Generating synthetic firewall logs …
"%VENV_PYTHON%" -c "from src.generate_logs import generate_firewall_logs; from src.utils import ensure_directory; from pathlib import Path; p=Path('data/synthetic/firewall_logs.csv'); ensure_directory(p.parent); generate_firewall_logs(rows=50000, seed=42, profile='attack-heavy').to_csv(p, index=False); print(f'Saved {50000} rows to {p}')"
echo.
echo  Logs generated. Opening dashboard …
goto :dashboard

:: ─────────────────────────────────────────────────────────────────────────────
:test
echo.
echo  Running test suite …
echo.
"%VENV_PYTHON%" -m pytest "%~dp0tests" -v
pause
goto :eof

:: ─────────────────────────────────────────────────────────────────────────────
:usage
echo.
echo  Usage:
echo    run.bat                      – interactive menu
echo    run.bat dashboard            – Streamlit dashboard
echo    run.bat cli ^<log_file^>       – CLI pipeline
echo    run.bat generate             – generate sample data + dashboard
echo    run.bat test                 – run tests
echo.
exit /b 1
