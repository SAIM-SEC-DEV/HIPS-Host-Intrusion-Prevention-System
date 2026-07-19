@echo off
TITLE HIPS Agent Recompiler (Java 21 Target)
echo.
echo  ╔═══════════════════════════════════════════════════════╗
echo  ║  HIPS Agent Recompiler (Compatibility Mode)           ║
echo  ║  Targeting: Java 21 (Class Version 65)                ║
echo  ╚═══════════════════════════════════════════════════════╝
echo.

REM Set base directory
set "BASE_DIR=%~dp0"
if "%BASE_DIR:~-1%"=="\" set "BASE_DIR=%BASE_DIR:~0,-1%"

echo  [1/3] Cleaning old binaries...
if exist "agent\bin" rmdir /s /q "agent\bin"
mkdir "agent\bin"

echo  [2/3] Compiling for Java 21 Compatibility...
echo       (Using --release 21)
echo.

REM Compile all packages
dir /s /b "agent\src\*.java" > sources.txt

javac -d "agent\bin" -cp "agent\lib\*" --release 21 @sources.txt

del sources.txt

if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Compilation failed!
    echo  Ensure you have JDK 21 or higher installed and in your PATH.
    pause
    exit /b %errorlevel%
)

echo.
echo  [3/3] Updating deployment package...
call "deploy-package.bat"

echo.
echo  =======================================================
echo   SUCCESS! The agent is now Java 21 compatible.
echo   You can now deploy the 'dist' folder to any machine
echo   running Java 21 or 22.
echo  =======================================================
echo.
pause
