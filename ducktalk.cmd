@echo off
setlocal EnableExtensions

if exist "%~dp0.venv\Scripts\ducktalk.exe" (
    "%~dp0.venv\Scripts\ducktalk.exe" %*
    exit /b %errorlevel%
)

py -3 -m ducktalk %*
if not errorlevel 9009 exit /b %errorlevel%
python -m ducktalk %*
exit /b %errorlevel%
