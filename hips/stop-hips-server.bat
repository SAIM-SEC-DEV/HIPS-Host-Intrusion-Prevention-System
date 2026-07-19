@echo off
setlocal enabledelayedexpansion
TITLE HIPS Server - Shutdown
color 0C

echo.
echo  ╔═══════════════════════════════════════════════════════╗
echo  ║   HIPS Server - Stopping All Services                 ║
echo  ╚═══════════════════════════════════════════════════════╝
echo.

REM Auto-detect XAMPP installation directory
set "XAMPP_DIR="
for %%D in (C:\xampp E:\xampp D:\xampp "%ProgramFiles%\xampp" "%ProgramFiles(x86)%\xampp") do (
    if exist "%%~D\apache\bin\httpd.exe" (
        set "XAMPP_DIR=%%~D"
        goto :xampp_stop_found
    )
)
set "XAMPP_DIR=C:\xampp"
:xampp_stop_found

REM ── Stop Discovery Service ─────────────────────────────────
echo  [1/3] Stopping Discovery Service...

REM Kill all java processes that are running ServerDiscovery
REM Use WMIC to find java processes with our specific classpath
set "KILLED_DISC=0"
for /f "skip=1 tokens=1" %%p in ('wmic process where "name='java.exe' and commandline like '%%ServerDiscovery%%'" get processid 2^>nul') do (
    set "PID=%%p"
    REM Trim whitespace
    set "PID=!PID: =!"
    if not "!PID!"=="" (
        taskkill /F /PID !PID! >nul 2>&1
        set "KILLED_DISC=1"
    )
)

if "!KILLED_DISC!"=="1" (
    echo  [OK] Discovery Service stopped.
) else (
    echo  [OK] Discovery Service was not running.
)

REM Clean up PID file if it exists
set "HIPS_DIR=%~dp0"
if "!HIPS_DIR:~-1!"=="\" set "HIPS_DIR=!HIPS_DIR:~0,-1!"
if exist "!HIPS_DIR!\discovery.pid" del "!HIPS_DIR!\discovery.pid" >nul 2>&1
echo.

REM ── Stop Apache ────────────────────────────────────────────
echo  [2/3] Stopping Apache...

tasklist /FI "IMAGENAME eq httpd.exe" 2>NUL | findstr /I "httpd.exe" >nul
if !errorlevel!==0 (
    taskkill /F /IM httpd.exe >nul 2>&1
    if exist "%XAMPP_DIR%\apache\logs\httpd.pid" del "%XAMPP_DIR%\apache\logs\httpd.pid" >nul 2>&1
    echo  [OK] Apache stopped.
) else (
    echo  [OK] Apache was not running.
)
echo.

REM ── Stop MySQL ─────────────────────────────────────────────
echo  [3/3] Stopping MySQL...

tasklist /FI "IMAGENAME eq mysqld.exe" 2>NUL | findstr /I "mysqld.exe" >nul
if !errorlevel!==0 (
    REM Try graceful shutdown first
    "%XAMPP_DIR%\mysql\bin\mysqladmin" -u root shutdown >nul 2>&1
    
    REM Wait for graceful shutdown
    ping -n 4 127.0.0.1 >nul 2>&1
    
    REM Force kill if still running
    tasklist /FI "IMAGENAME eq mysqld.exe" 2>NUL | findstr /I "mysqld.exe" >nul
    if !errorlevel!==0 (
        taskkill /F /IM mysqld.exe >nul 2>&1
    )
    echo  [OK] MySQL stopped.
) else (
    echo  [OK] MySQL was not running.
)
echo.

echo  ╔═══════════════════════════════════════════════════════╗
echo  ║   All HIPS services have been stopped.                ║
echo  ╚═══════════════════════════════════════════════════════╝
echo.

REM Only pause if run directly (not called from start script)
if "%~1"=="" pause
endlocal
