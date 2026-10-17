@echo off
setlocal
chcp 936 >nul 2>&1
title 一键编译 - Test 驱动 (x64)

set "SRCDIR=%~dp0"
set "BUILDENV=%~dp0..\_BuildEnv"

if not exist "%BUILDENV%\build.bat" (
    echo [错误] 找不到编译环境: %BUILDENV%
    goto :fail
)

echo 源码目录: %SRCDIR%
echo 编译环境: %BUILDENV%
echo.

call "%BUILDENV%\build.bat" "%SRCDIR%"
if errorlevel 1 goto :fail

if not exist "%SRCDIR%build_out" mkdir "%SRCDIR%build_out"
del /q "%SRCDIR%build_out\*.sys" >nul 2>&1
copy /y "%BUILDENV%\out\*.sys" "%SRCDIR%build_out\" >nul 2>&1
ren "%SRCDIR%build_out\-main=.sys" "Test.sys" >nul 2>&1

echo.
echo 编译成功！产物: %SRCDIR%build_out\Test.sys
pause
exit /b 0

:fail
echo.
echo [失败] 编译出错，请检查上方错误信息。
pause
exit /b 1
