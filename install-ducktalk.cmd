@echo off
setlocal EnableExtensions
set "DEFAULT_URL=https://YOUR-HOST.example/ducktalk-1.0.0-py3-none-any.whl"
set "WHEEL_URL=%~1"
if not defined WHEEL_URL set "WHEEL_URL=%DUCKTALK_WHEEL_URL%"
if not defined WHEEL_URL set "WHEEL_URL=%DEFAULT_URL%"

if /I "%WHEEL_URL%"=="%DEFAULT_URL%" (
    echo Usage:
    echo   install-ducktalk.cmd https://your-host/ducktalk-1.0.0-py3-none-any.whl
    echo.
    echo Or set DUCKTALK_WHEEL_URL, or edit DEFAULT_URL in this file.
    exit /b 1
)

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

where curl.exe >nul 2>nul
if errorlevel 1 (
    echo curl.exe was not found. Windows 10 version 1803 or newer is required.
    exit /b 1
)

%PY_CMD% -m pip --version >nul 2>nul
if errorlevel 1 (
    echo pip was not found; trying ensurepip...
    %PY_CMD% -m ensurepip --upgrade
    if errorlevel 1 (
        echo Could not install pip.
        exit /b 1
    )
)

set "DLDIR=%TEMP%\ducktalk-install-%RANDOM%%RANDOM%"
mkdir "%DLDIR%" >nul 2>nul
set "WHEEL=%DLDIR%\ducktalk-1.0.0-py3-none-any.whl"
echo Downloading DuckTalk from:
echo   %WHEEL_URL%
curl.exe -fsSL --retry 2 -o "%WHEEL%" "%WHEEL_URL%"
if errorlevel 1 (
    echo Download failed.
    if exist "%WHEEL%" del /f /q "%WHEEL%" >nul 2>nul
    if exist "%DLDIR%" rmdir "%DLDIR%" >nul 2>nul
    exit /b 1
)

echo Installing DuckTalk for the current user...
%PY_CMD% -c "import cryptography" >nul 2>nul
if errorlevel 1 (
    %PY_CMD% -m pip install --user --disable-pip-version-check "cryptography>=42"
    if errorlevel 1 (
        echo Could not install the cryptography dependency.
        if exist "%WHEEL%" del /f /q "%WHEEL%" >nul 2>nul
        if exist "%DLDIR%" rmdir "%DLDIR%" >nul 2>nul
        exit /b 1
    )
)
%PY_CMD% -m pip install --user --upgrade --force-reinstall --no-deps --disable-pip-version-check "%WHEEL%"
if errorlevel 1 (
    echo Installation failed.
    if exist "%WHEEL%" del /f /q "%WHEEL%" >nul 2>nul
    if exist "%DLDIR%" rmdir "%DLDIR%" >nul 2>nul
    exit /b 1
)
if exist "%WHEEL%" del /f /q "%WHEEL%" >nul 2>nul
if exist "%DLDIR%" rmdir "%DLDIR%" >nul 2>nul

%PY_CMD% -m ducktalk --version
if errorlevel 1 (
    echo DuckTalk was installed but could not be started.
    exit /b 1
)

set "USER_SCRIPTS="
for /f "usebackq delims=" %%S in (`%PY_CMD% -c "import sysconfig; print(sysconfig.get_path('scripts', scheme='nt_user'))"`) do set "USER_SCRIPTS=%%S"
if defined USER_SCRIPTS if exist "%USER_SCRIPTS%\ducktalk.exe" (
    set "DUCKTALK_SCRIPTS=%USER_SCRIPTS%"
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=$env:DUCKTALK_SCRIPTS; $p=[Environment]::GetEnvironmentVariable('Path','User'); $parts=@($p -split ';' | Where-Object { $_ }); if ($parts -notcontains $d) { [Environment]::SetEnvironmentVariable('Path', (($parts + $d) -join ';'), 'User'); Write-Output 'Added DuckTalk to your user PATH.' } else { Write-Output 'DuckTalk is already on your user PATH.' }"
    if errorlevel 1 echo Could not update PATH automatically.
)

echo.
echo Installed. Open a NEW Command Prompt and run:
echo   ducktalk -m
echo.
echo If ducktalk is not recognized, run:
echo   %PY_CMD% -m ducktalk -m
endlocal
exit /b 0
