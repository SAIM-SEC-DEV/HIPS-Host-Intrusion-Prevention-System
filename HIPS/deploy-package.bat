@echo off
TITLE HIPS Agent Deployment Packager
echo.
echo  ==========================================
echo   HIPS Agent Deployment Packager
echo   Creates a portable agent distribution
echo  ==========================================
echo.

REM Create distribution directory
if exist dist rmdir /s /q dist
mkdir dist
mkdir dist\agent\bin
mkdir dist\agent\lib

echo [1/5] Copying agent class files...
xcopy /E /Y agent\bin\* dist\agent\bin\ >nul 2>&1

echo [2/5] Copying dependencies...
copy agent\lib\gson-2.10.1.jar dist\agent\lib\ >nul 2>&1

echo [3/5] Creating clean configuration...
(
echo # HIPS Agent Configuration
echo # Auto-generated for deployment
echo #
echo # The agent will auto-discover the server on the network.
echo # You can also manually set the server URL below.
echo #
echo server.url=http://localhost/hips
echo auth.token=
echo agent.id=0
echo agent.uuid=
echo heartbeat.interval=30
echo poll.interval=10
echo agent.owner=
echo baseline.start=
echo baseline.complete=false
echo watch.directories=C:\\Windows\\System32,C:\\Users
echo whitelist.ips=
) > dist\hips-agent.properties

echo [4/5] Creating run script...
(
echo @echo off
echo TITLE HIPS Security Agent
echo echo Starting HIPS Security Agent...
echo echo The agent will auto-discover the server on the network.
echo echo.
echo java -cp "agent\bin;agent\lib\gson-2.10.1.jar" com.hips.agent.HipsAgent
echo pause
) > dist\run-agent.bat

echo [5/5] Creating setup script...
(
echo @echo off
echo TITLE HIPS Agent Setup
echo echo.
echo echo  ==========================================
echo echo   HIPS Agent Setup
echo echo  ==========================================
echo echo.
echo set /p SERVER_IP="Enter the HIPS Server IP address: "
echo echo.
echo echo Updating configuration...
echo.
echo REM Update server URL in properties file
echo powershell -Command "(Get-Content 'hips-agent.properties'^) -replace 'server.url=.*', 'server.url=http://%SERVER_IP%/hips' ^| Set-Content 'hips-agent.properties'"
echo.
echo echo.
echo echo Configuration updated!
echo echo Server URL set to: http://%%SERVER_IP%%/hips
echo echo.
echo echo You can now run the agent with: run-agent.bat
echo echo Or install as a Windows Service using NSSM.
echo echo.
echo pause
) > dist\setup-agent.bat

echo.
echo  ==========================================
echo   Deployment package created in: dist\
echo  ==========================================
echo.
echo  Contents:
echo    dist\agent\          - Agent binaries
echo    dist\run-agent.bat   - Run the agent
echo    dist\setup-agent.bat - Configure server IP
echo    dist\hips-agent.properties - Configuration
echo.
echo  To deploy on another computer:
echo    1. Copy the 'dist' folder to the target machine
echo    2. Run setup-agent.bat OR let auto-discovery find the server
echo    3. Run run-agent.bat
echo.
pause
