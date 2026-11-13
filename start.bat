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

  ".venv\Scripts\python.exe" -m gopay.server

) else (

  python -m gopay.server

)

set "ERR=%ERRORLEVEL%"

popd

exit /b %ERR%
