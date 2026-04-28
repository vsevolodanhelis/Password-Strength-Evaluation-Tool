@echo off
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [!] Virtual environment not found. Creating one...
    python -m venv .venv
    if errorlevel 1 (
        echo [X] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [i] Installing dependencies...
    call .venv\Scripts\activate
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [X] Failed to install dependencies.
        pause
        exit /b 1
    )
) else (
    call .venv\Scripts\activate
)

echo [i] Launching Password Strength Analyzer...
python -m password_tool
if errorlevel 1 (
    echo.
    echo [X] Application exited with an error.
    pause
)
