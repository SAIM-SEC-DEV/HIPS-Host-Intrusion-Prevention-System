@echo off
TITLE HIPS Discovery Service
echo.
echo  ==========================================
echo   HIPS Server Discovery Service
echo   Helps agents find this server on the
echo   local network automatically.
echo  ==========================================
echo.

REM Auto-detect local IP address (filtered — excludes VirtualBox, VPN, WSL adapters)
set "LOCAL_IP="
for /f "tokens=*" %%a in ('powershell -NoProfile -Command "try { $ip = Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp -ErrorAction Stop | Where-Object { $_.InterfaceAlias -notmatch 'VirtualBox|VMware|WSL|vEthernet|Hyper-V|VPN|Loopback' } | Select-Object -First 1 -ExpandProperty IPAddress; Write-Output $ip } catch { }" 2^>nul') do (
    set "LOCAL_IP=%%a"
)
REM Fallback to classic ipconfig if PowerShell detection failed
if not defined LOCAL_IP (
    for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /R /C:"IPv4 Address"') do (
        if not defined LOCAL_IP set "LOCAL_IP=%%a"
    )
)
REM Trim leading space
for /f "tokens=*" %%b in ("!LOCAL_IP!") do set "LOCAL_IP=%%b"

echo  Detected Server IP: %LOCAL_IP%
echo  Server URL: http://%LOCAL_IP%/hips
echo.
echo  Starting discovery listener on UDP port 41900...
echo  Agents will automatically find this server.
echo  Press Ctrl+C to stop.
echo.

java -cp "agent\bin;agent\lib\gson-2.10.1.jar" com.hips.agent.core.ServerDiscovery "http://%LOCAL_IP%/hips"
pause
