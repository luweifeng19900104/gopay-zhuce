@echo off

cd /d "%~dp0.."

set PYTHONIOENCODING=utf-8

if exist ".venv\Scripts\python.exe" (

  ".venv\Scripts\python.exe" gopayquick\server.py

) else (

  python gopayquick\server.py

)

pause
