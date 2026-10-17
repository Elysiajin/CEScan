@echo off
rem ============================================================
rem  CEScan x64 一键编译（自动探测工具链）
rem  产物: bin\CEScan.exe (图形界面, OllyDbg 风格 MDI 调试器 + 内存搜索)
rem  注: CLI 版本已移除，只保留 GUI。
rem
rem  工具链探测顺序:
rem    1) 便携版 MSVC(曙光C++IDE VC64, 含 SDK)
rem    2) Q 盘 VS2017 Enterprise
rem    3) vswhere 找到的任意 VS/BuildTools
rem ============================================================
setlocal
chcp 65001 >nul
cd /d "%~dp0"
if not exist bin mkdir bin
if not exist obj mkdir obj
del /q obj\*.obj 2>nul

set "PORTABLE_VCBIN=C:\Users\Administrator\Desktop\新建文件夹 (2)\vc+++曙光C++IDE+2014年6月21日\曙光C++IDE\Release\VC64"
set "QVSVARS=Q:\Visual Studio 2017 Enterprise\VC\Auxiliary\Build\vcvars64.bat"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

rem ---- 工具链 1: 便携版 VC64（自带 SDK，已验证） ----
if exist "%PORTABLE_VCBIN%\bin\cl.exe" (
  echo [工具链] 便携版 MSVC 19.10 x64 ^(%PORTABLE_VCBIN%^)
  set "CL_EXE=%PORTABLE_VCBIN%\bin\cl.exe"
  set "LINK_EXE=%PORTABLE_VCBIN%\bin\link.exe"
  set "INCLUDE=%PORTABLE_VCBIN%\include"
  set "LIB=%PORTABLE_VCBIN%\lib"
  goto :toolchain_ok
)

rem ---- 工具链 2: Q 盘 VS2017 ----
if exist "%QVSVARS%" (
  echo [工具链] VS2017 Enterprise
  call "%QVSVARS%" >nul 2>&1
  if exist "%WindowsSdkDir%" (
    set "CL_EXE=cl.exe"
    set "LINK_EXE=link.exe"
    goto :toolchain_ok
  )
  echo [跳过] 该 VS 缺少 Windows SDK
)

rem ---- 工具链 3: vswhere ----
if exist "%VSWHERE%" (
  for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do set "VSPATH=%%i"
  if defined VSPATH (
    echo [工具链] %%VSPATH%%
    call "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    set "CL_EXE=cl.exe"
    set "LINK_EXE=link.exe"
    goto :toolchain_ok
  )
)

echo [错误] 未找到可用的 MSVC 工具链
goto :fail

:toolchain_ok
set "CFLAGS=/nologo /std:c++latest /utf-8 /EHsc /O2 /W3 /MT /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /D_WINSOCKAPI_ /Iinclude /Fo:obj\"
set "SOURCES=CETypes CEUtil ProcessMemory RegionFilter PatternScan ScanEngine Disasm Debugger McpClient StrSearch HookRestore ThreadLocator DBVM DbvmLoader DbvmTools"

echo.
echo ==== 编译模块 (x64) ====
for %%f in (%SOURCES%) do (
  echo [编译] src\%%f.cpp
  %CL_EXE% %CFLAGS% /c src\%%f.cpp
  if errorlevel 1 goto :fail
)

echo ==== 编译图形界面版 (MDI) ====
%CL_EXE% %CFLAGS% /c src\main_gui.cpp
if errorlevel 1 goto :fail

echo.
echo ==== 链接 bin\CEScan.exe ====
%LINK_EXE% /nologo /OUT:bin\CEScan.exe /SUBSYSTEM:WINDOWS /MACHINE:X64 obj\main_gui.obj obj\CETypes.obj obj\CEUtil.obj obj\ProcessMemory.obj obj\RegionFilter.obj obj\PatternScan.obj obj\ScanEngine.obj obj\Disasm.obj obj\Debugger.obj obj\McpClient.obj obj\StrSearch.obj obj\HookRestore.obj obj\ThreadLocator.obj obj\DBVM.obj obj\DbvmLoader.obj obj\DbvmTools.obj psapi.lib user32.lib advapi32.lib ole32.lib oleaut32.lib comdlg32.lib comctl32.lib gdi32.lib ws2_32.lib winhttp.lib uxtheme.lib
if errorlevel 1 goto :fail

echo.
echo ============================================================
echo   编译完成!
echo     bin\CEScan.exe  OllyDbg 风格 MDI 调试器 + 内存搜索
echo   64 位 (x64) 程序
echo ============================================================
pause
exit /b 0

:fail
echo.
echo [错误] 编译失败，请检查上方错误信息
pause
exit /b 1
