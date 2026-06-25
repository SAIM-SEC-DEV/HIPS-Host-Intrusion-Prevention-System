$controllerTitle = 'HIPS Server Controller'
$stopScript = '$PSScriptRoot\stop-hips-server.bat'
# Wait for the controller window to appear
Start-Sleep -Seconds 2
# Find the controller cmd.exe process by window title
$controllerProc = Get-Process -Name "cmd" -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -eq $controllerTitle } | Select-Object -First 1
if ($null -eq $controllerProc) { exit }
$controllerPid = $controllerProc.Id
# Monitor: wait until the controller process exits
try { Wait-Process -Id $controllerPid -ErrorAction Stop } catch { }
# Controller is gone — clean up all services
Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$stopScript`" nopause" -WindowStyle Hidden -Wait
