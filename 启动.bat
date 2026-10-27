@echo off
title CTF-RE-TOOL v1.9.2

echo ========================================
echo   CTF-RE-TOOL v1.9.2
echo   CTF Reverse Engineering AI Workbench
echo ========================================
echo.
echo   [1] Drag files in for auto-detection
echo   [2] One-click tools: IDA / JEB / jadx / Burp
echo   [3] Frida auto hook
echo   [4] Directed dynamic debugging: local PE / remote ELF
echo   [5] Offline crypto and recipe chains
echo   [6] Local verification loop
echo.
echo Starting...
echo.

cd /d "%~dp0"

if not exist node_modules (
  echo [INFO] node_modules not found, installing dependencies...
  call npm install
  if errorlevel 1 (
    echo.
    echo [ERROR] npm install failed. Please check Node.js installation.
    pause
    exit /b 1
  )
)

call npm start

if errorlevel 1 (
  echo.
  echo [ERROR] Failed to start. See output above.
)

pause
