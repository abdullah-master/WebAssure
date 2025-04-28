@echo off
echo Checking Python installation...

REM Check if python is in PATH
python --version 2>nul
if %errorlevel% equ 0 (
    echo Python found in PATH
    goto :run_app
)

REM Try common Python installation paths
for %%p in (
    "C:\Python311\python.exe"
    "C:\Python310\python.exe"
    "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python311\python.exe"
    "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python310\python.exe"
    "C:\Program Files\Python311\python.exe"
    "C:\Program Files\Python310\python.exe"
) do (
    if exist %%p (
        echo Found Python at: %%p
        set PYTHON_PATH=%%p
        goto :run_app
    )
)

echo Python not found. Please install Python from python.org
echo Press any key to open the Python download page...
pause
start https://www.python.org/downloads/
exit /b 1

:run_app
echo Starting Flask application...
"%PYTHON_PATH%" app.py
pause
