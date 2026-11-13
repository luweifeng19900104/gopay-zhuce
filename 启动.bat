@echo off

setlocal

pushd "%~dp0"

set "PYTHONPATH=%CD%\app\src"

set "PYTHONUTF8=1"

set "OPAI_GOPAY_PAYMENT_MODE=protocol"

set "OPAI_GOPAY_AUTH_MODE=protocol"

set "OPAI_GOPAY_DEVICE_SIM=mobile"

if not exist "config\runtime.env" if exist "config\runtime.env.example" (

  copy /Y "config\runtime.env.example" "config\runtime.env" >nul

)

if exist ".venv\Scripts\python.exe" (

  ".venv\Scripts\python.exe" -c "import sys" >nul 2>nul

  if not errorlevel 1 goto run_venv

)

where py >nul 2>nul

if errorlevel 1 goto no_python

py -3.11 -c "import sys" >nul 2>nul

if errorlevel 1 goto no_python

py -3.11 -m gopay.server

set "ERR=%ERRORLEVEL%"

popd

exit /b %ERR%

:run_venv

".venv\Scripts\python.exe" -m gopay.server

set "ERR=%ERRORLEVEL%"

popd

exit /b %ERR%

:no_python

echo Python 3.11 x64 runtime not found.

echo Please install Python 3.11 x64 with the py launcher, then retry.

pause

popd

exit /b 1
