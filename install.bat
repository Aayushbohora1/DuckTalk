@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "VENV=%~dp0.venv"
set "VPY=%VENV%\Scripts\python.exe"
set "DUCK=%VENV%\Scripts\ducktalk.exe"

if exist "%VPY%" goto install

set "PY_CMD="
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
if not errorlevel 1 set "PY_CMD=py -3"
if not defined PY_CMD (
    python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
    if not errorlevel 1 set "PY_CMD=python"
)
if not defined PY_CMD (
    echo Python 3.10 or newer was not found.
    echo Install Python from https://www.python.org/downloads/ and enable "Add python.exe to PATH".
    exit /b 1
)

echo Creating virtual environment in "%VENV%"
%PY_CMD% -m venv "%VENV%"
if errorlevel 1 (
    echo Could not create the virtual environment.
    exit /b 1
)

:install
if not exist "%VPY%" (
    echo Virtual environment is incomplete: "%VPY%" is missing.
    exit /b 1
)

echo Installing DuckTalk
"%VPY%" -c "import cryptography" >nul 2>nul
if errorlevel 1 (
    "%VPY%" -m pip install --disable-pip-version-check "cryptography>=42"
    if errorlevel 1 (
        echo Could not install the cryptography dependency.
        exit /b 1
    )
)
"%VPY%" -m pip install --disable-pip-version-check --force-reinstall --no-deps .
if errorlevel 1 (
    echo pip install failed.
    exit /b 1
)

"%DUCK%" --version
if errorlevel 1 (
    echo DuckTalk did not start after installation.
    exit /b 1
)

echo.
echo Installed. From this folder, start the menu with:
echo   ducktalk -m
echo.
echo Or run it directly with:
echo   "%DUCK%" -m
endlocal
exit /b 0
