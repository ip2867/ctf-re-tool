@echo off
echo ========================================
echo   CTF Reverse Engineering Tool v1.3.4
echo ========================================
echo.
echo 功能特性:
echo   - 文件拖入自动识别
echo   - 一键调用逆向工具
echo   - Frida自动Hook
echo   - 解密脚本生成
echo   - 反调试绕过
echo.
echo 启动中...
echo.

cd /d "%~dp0"
npm start

pause
