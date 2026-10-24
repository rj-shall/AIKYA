@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  set PYTHON=py
) else (
  set PYTHON=python
)
if not exist ".venv\Scripts\python.exe" (
  echo Creating Python virtual environment...
  %PYTHON% -m venv .venv
  if errorlevel 1 goto error
)
echo Installing or checking dependencies...
.venv\Scripts\python.exe -m pip install --upgrade pip
if errorlevel 1 goto error
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto error
echo.
echo AIKYA is starting on http://127.0.0.1:8000
 echo Keep this window open while using AIKYA.
start "" http://127.0.0.1:8000
.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
if errorlevel 1 goto error
goto end
:error
echo.
echo Setup failed. Install Python 3.10 or newer and try again.
pause
:end
endlocal
