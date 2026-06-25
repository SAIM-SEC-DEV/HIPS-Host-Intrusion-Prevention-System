@echo off
setlocal enabledelayedexpansion
TITLE HIPS Server Controller
color 0A

echo.
echo  ╔═══════════════════════════════════════════════════════╗
echo  ║                                                       ║
echo  ║   ██╗  ██╗██╗██████╗ ███████╗                        ║
echo  ║   ██║  ██║██║██╔══██╗██╔════╝                        ║
echo  ║   ███████║██║██████╔╝███████╗                        ║
echo  ║   ██╔══██║██║██╔═══╝ ╚════██║                        ║
echo  ║   ██║  ██║██║██║     ███████║                        ║
echo  ║   ╚═╝  ╚═╝╚═╝╚═╝     ╚══════╝                        ║
echo  ║                                                       ║
echo  ║   Server Controller - Start All Services              ║
echo  ║   Apache + MySQL + Discovery Service                  ║
echo  ║                                                       ║
echo  ╚═══════════════════════════════════════════════════════╝
echo.

REM ── Configuration ──────────────────────────────────────────
set "HIPS_DIR=%~dp0"
REM Remove trailing backslash from HIPS_DIR
if "!HIPS_DIR:~-1!"=="\" set "HIPS_DIR=!HIPS_DIR:~0,-1!"

REM Auto-detect XAMPP installation directory
set "XAMPP_DIR="
for %%D in (C:\xampp E:\xampp D:\xampp "%ProgramFiles%\xampp" "%ProgramFiles(x86)%\xampp") do (
    if exist "%%~D\apache\bin\httpd.exe" (
        set "XAMPP_DIR=%%~D"
        goto :xampp_found
    )
)
REM Not found automatically — ask the user
set /p XAMPP_DIR="[INPUT] XAMPP not found. Enter XAMPP path (e.g. C:\xampp): "
:xampp_found

REM ── Preflight Checks ──────────────────────────────────────
echo  [1/7] Preflight checks...

REM Check XAMPP exists
if not exist "%XAMPP_DIR%\apache\bin\httpd.exe" (
    echo  [ERROR] XAMPP not found at %XAMPP_DIR%
    echo  Please update the XAMPP_DIR variable in this script.
    pause
    exit /b 1
)

REM Check Java exists
java -version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Java is not installed or not in PATH.
    echo  Install Java 11+ and try again.
    pause
    exit /b 1
)

REM Check agent binaries exist
if not exist "!HIPS_DIR!\agent\bin\com\hips\agent\core\ServerDiscovery.class" (
    echo  [ERROR] Discovery Service binaries not found.
    echo  Compile the HIPS agent project first.
    pause
    exit /b 1
)

echo  [OK] XAMPP found at %XAMPP_DIR%
echo  [OK] Java found
echo  [OK] Discovery Service binaries found
echo.

REM ── Auto-Detect Local IP ──────────────────────────────────
echo  [2/7] Detecting local IP address...
set "LOCAL_IP="
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /R /C:"IPv4 Address"') do (
    if not defined LOCAL_IP set "LOCAL_IP=%%a"
)
REM Trim leading space
for /f "tokens=*" %%b in ("!LOCAL_IP!") do set "LOCAL_IP=%%b"
echo  [OK] Server IP: !LOCAL_IP!
echo  [OK] Server URL: http://!LOCAL_IP!/hips
echo.

REM ── Step 1: Start MySQL ────────────────────────────────────
echo  [3/7] Starting MySQL...

tasklist /FI "IMAGENAME eq mysqld.exe" 2>NUL | findstr /I "mysqld.exe" >nul
if !errorlevel!==0 (
    echo  [OK] MySQL is already running.
) else (
    start "HIPS-MySQL" /MIN cmd /c "cd /D %XAMPP_DIR% && mysql\bin\mysqld --defaults-file=mysql\bin\my.ini --standalone"
    echo  [OK] MySQL started.
    REM Wait for MySQL to initialize (3 seconds via ping)
    ping -n 4 127.0.0.1 >nul 2>&1
)
echo.

REM ── Step 2: Start Apache ───────────────────────────────────
echo  [4/7] Starting Apache...

tasklist /FI "IMAGENAME eq httpd.exe" 2>NUL | findstr /I "httpd.exe" >nul
if !errorlevel!==0 (
    echo  [OK] Apache is already running.
) else (
    start "HIPS-Apache" /MIN cmd /c "cd /D %XAMPP_DIR% && apache\bin\httpd.exe"
    echo  [OK] Apache started.
    REM Wait for Apache to bind ports (2 seconds)
    ping -n 3 127.0.0.1 >nul 2>&1
)
echo.

REM ── Step 3: Verify Apache is responding ────────────────────
echo  [5/7] Verifying Apache is responding...
ping -n 3 127.0.0.1 >nul 2>&1

powershell -NoProfile -Command "try { $r = Invoke-WebRequest -Uri 'http://localhost' -TimeoutSec 5 -UseBasicParsing; if ($r.StatusCode -eq 200) { Write-Host '  [OK] Apache is responding on port 80.' } else { Write-Host '  [WARN] Apache responded with status:' $r.StatusCode } } catch { Write-Host '  [WARN] Apache not responding yet. It may still be starting.' }"
echo.

REM ── Step 4: Start Discovery Service ────────────────────────
echo  [6/7] Starting Discovery Service...

REM Check if Discovery is already running using tasklist window title
set "DISC_RUNNING=0"
for /f "tokens=2" %%p in ('tasklist /V /FI "IMAGENAME eq java.exe" 2^>nul ^| findstr /I "ServerDiscovery"') do (
    set "DISC_RUNNING=1"
)

if "!DISC_RUNNING!"=="1" (
    echo  [OK] Discovery Service is already running.
) else (
    REM Write a temporary launcher to avoid nested quoting issues
    echo @echo off > "!HIPS_DIR!\discovery-launcher-temp.bat"
    echo cd /D "!HIPS_DIR!" >> "!HIPS_DIR!\discovery-launcher-temp.bat"
    echo java -cp "agent\bin;agent\lib\gson-2.10.1.jar" com.hips.agent.core.ServerDiscovery "http://!LOCAL_IP!/hips" >> "!HIPS_DIR!\discovery-launcher-temp.bat"
    start "HIPS-Discovery" /MIN cmd /c "!HIPS_DIR!\discovery-launcher-temp.bat"
    ping -n 3 127.0.0.1 >nul 2>&1
    echo  [OK] Discovery Service started on UDP port 41900.
)
echo.

REM ── Step 5: Open Dashboard in Browser ──────────────────────
echo  [7/7] Opening Dashboard in browser...
start "" "http://localhost/hips/dashboard/"
echo  [OK] Dashboard opened in default browser.
echo.

REM ── Launch Background Watchdog ─────────────────────────────
REM This watchdog monitors this controller window. If the window is
REM closed via the X button, the watchdog will automatically run
REM stop-hips-server.bat to clean up all services.

REM Save our own PID so the watchdog knows what to monitor.
REM We use the window title "HIPS Server Controller" to find ourselves.
set "WATCHDOG_SCRIPT=!HIPS_DIR!\hips-watchdog-temp.ps1"

(
echo $controllerTitle = 'HIPS Server Controller'
echo $stopScript = '!HIPS_DIR!\stop-hips-server.bat'
echo # Wait for the controller window to appear
echo Start-Sleep -Seconds 2
echo # Find the controller cmd.exe process by window title
echo $controllerProc = Get-Process -Name "cmd" -ErrorAction SilentlyContinue ^| Where-Object { $_.MainWindowTitle -eq $controllerTitle } ^| Select-Object -First 1
echo if ($null -eq $controllerProc^) { exit }
echo $controllerPid = $controllerProc.Id
echo # Monitor: wait until the controller process exits
echo try { Wait-Process -Id $controllerPid -ErrorAction Stop } catch { }
echo # Controller is gone — clean up all services
echo Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$stopScript`" nopause" -WindowStyle Hidden -Wait
) > "!WATCHDOG_SCRIPT!"

REM Start the watchdog hidden in the background
start "" /MIN powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "!WATCHDOG_SCRIPT!"

echo  ╔═══════════════════════════════════════════════════════╗
echo  ║                                                       ║
echo  ║   ALL HIPS SERVICES ARE RUNNING                       ║
echo  ║                                                       ║
echo  ║   Dashboard:  http://localhost/hips/dashboard/         ║
echo  ║   Server IP:  !LOCAL_IP!
echo  ║   Discovery:  UDP port 41900                          ║
echo  ║                                                       ║
echo  ║   Agents can now auto-discover this server.           ║
echo  ║                                                       ║
echo  ║   Close this window or press any key to                ║
echo  ║   stop ALL services automatically.                    ║
echo  ║                                                       ║
echo  ╚═══════════════════════════════════════════════════════╝
echo.
pause

REM ── Shutdown triggered by keypress ─────────────────────────
REM If user pressed a key (not X button), stop services directly.
REM The watchdog will also try to stop, but stop-hips-server.bat
REM is idempotent — running it twice is harmless.
echo.
echo  Stopping all HIPS services...
call "!HIPS_DIR!\stop-hips-server.bat" nopause
endlocal
