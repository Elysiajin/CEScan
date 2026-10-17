@echo off
chcp 65001 >nul
echo ============================================
echo   加载 Test11.sys (含 PPL 绕过) - 需管理员
echo ============================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] 请以管理员身份运行本脚本
    pause
    exit /b 1
)

set SRV=Test11
set SYSFILE=%~dp0build_out\Test11.sys

echo [*] 目标驱动: %SYSFILE%
if not exist "%SYSFILE%" (
    echo [-] 文件不存在: %SYSFILE%
    pause
    exit /b 1
)

echo [*] 1. 停止并删除旧服务 %SRV% (若存在)...
sc stop %SRV% >nul 2>&1
sc delete %SRV% >nul 2>&1
timeout /t 1 /nobreak >nul

echo [*] 2. 创建服务 %SRV% ...
sc create %SRV% type= kernel binPath= "\??\%SYSFILE%" start= demand >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] 创建服务失败 (errorlevel=%errorlevel%)
    pause
    exit /b 1
)

echo [*] 3. 启动服务 %SRV% ...
sc start %SRV%
if %errorlevel% neq 0 (
    echo [-] 启动失败 (errorlevel=%errorlevel%) — 可能需要禁用驱动签名强制
    echo     或用 DSE 绕过工具
    pause
    exit /b 1
)

echo.
echo [+] 驱动已加载! 设备: \\.\JfDebug
echo [+] 现在可运行: forcetest.exe ^<pid^>
echo.
pause
