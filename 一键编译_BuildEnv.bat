@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem ============================================================
rem  One-click build using the local _BuildEnv toolchain.
rem  Output: bin\CEdbg.exe  (GUI debugger + DBVM loader)
rem
rem  Toolchain is auto-located under %USERPROFILE%\Desktop
rem  (folder "windows...\_BuildEnv") -- no Chinese literals here,
rem  so this batch parses fine under any console codepage.
rem ============================================================

rem ---- locate _BuildEnv (Desktop level 1) ----
set "ENVROOT="
for /d %%D in ("%USERPROFILE%\Desktop\*") do (
  if exist "%%D\_BuildEnv\MSVC_x64\bin\x64\cl.exe" set "ENVROOT=%%D\_BuildEnv"
)
if not defined ENVROOT (
  echo [ERROR] _BuildEnv\MSVC_x64\bin\x64\cl.exe not found under %USERPROFILE%\Desktop
  goto :fail
)

set "CL_EXE=!ENVROOT!\MSVC_x64\bin\x64\cl.exe"
set "LINK_EXE=!ENVROOT!\MSVC_x64\bin\x64\link.exe"
set "INCLUDE=!ENVROOT!\SDK\Include\um;!ENVROOT!\SDK\Include\shared;!ENVROOT!\SDK\Include\ucrt;!ENVROOT!\SDK\Include\vc;!ENVROOT!\MSVC_x64\include"
set "LIB=!ENVROOT!\SDK\Lib\x64"
set "PATH=!ENVROOT!\MSVC_x64\bin\x64;%SystemRoot%\system32;%SystemRoot%"

if not exist "!CL_EXE!" (
  echo [ERROR] Toolchain not found: !CL_EXE!
  goto :fail
)

if not exist bin mkdir bin
if not exist obj_be mkdir obj_be
del /q obj_be\*.obj 2>nul

set "CFLAGS=/nologo /std:c++latest /utf-8 /EHsc /O2 /W3 /MT /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /D_WINSOCKAPI_ /Iinclude /Fo:obj_be\"
set "SOURCES=CETypes CEUtil ProcessMemory RegionFilter PatternScan ScanEngine Disasm Debugger McpClient StrSearch HookRestore ThreadLocator DBVM DbvmLoader DbvmTools"

echo.
echo ==== Compile core modules (x64) ====
for %%f in (%SOURCES%) do (
  echo [compiling] src\%%f.cpp
  !CL_EXE! %CFLAGS% /c src\%%f.cpp
  if errorlevel 1 goto :fail
)

echo ==== Compile GUI ====
!CL_EXE! %CFLAGS% /c src\main_gui.cpp
if errorlevel 1 goto :fail

echo.
echo ==== Link bin\CEdbg.exe ====
!LINK_EXE! /nologo /OUT:bin\CEdbg.exe /SUBSYSTEM:WINDOWS /MACHINE:X64 obj_be\main_gui.obj obj_be\CETypes.obj obj_be\CEUtil.obj obj_be\ProcessMemory.obj obj_be\RegionFilter.obj obj_be\PatternScan.obj obj_be\ScanEngine.obj obj_be\Disasm.obj obj_be\Debugger.obj obj_be\McpClient.obj obj_be\StrSearch.obj obj_be\HookRestore.obj obj_be\ThreadLocator.obj obj_be\DBVM.obj obj_be\DbvmLoader.obj obj_be\DbvmTools.obj psapi.lib user32.lib advapi32.lib ole32.lib oleaut32.lib comdlg32.lib comctl32.lib gdi32.lib ws2_32.lib winhttp.lib uxtheme.lib
if errorlevel 1 goto :fail

echo.
echo ==== DBVM runtime files (bin\dbk64.sys / bin\vmdisk.img) ====
if not exist "bin\dbk64.sys" (
  if exist "%~dp0dbk64.sys"              copy /y "%~dp0dbk64.sys"              "bin\" >nul & echo   [copied] dbk64.sys
  if exist "%USERPROFILE%\Desktop\dbk64.sys"  copy /y "%USERPROFILE%\Desktop\dbk64.sys"  "bin\" >nul & echo   [copied] dbk64.sys
  if exist "%USERPROFILE%\Downloads\dbk64.sys" copy /y "%USERPROFILE%\Downloads\dbk64.sys" "bin\" >nul & echo   [copied] dbk64.sys
)
if not exist "bin\vmdisk.img" (
  if exist "%~dp0vmdisk.img"             copy /y "%~dp0vmdisk.img"             "bin\" >nul & echo   [copied] vmdisk.img
  if exist "%USERPROFILE%\Desktop\vmdisk.img"  copy /y "%USERPROFILE%\Desktop\vmdisk.img"  "bin\" >nul & echo   [copied] vmdisk.img
  if exist "%USERPROFILE%\Downloads\vmdisk.img" copy /y "%USERPROFILE%\Downloads\vmdisk.img" "bin\" >nul & echo   [copied] vmdisk.img
)
for /d %%E in ("%ProgramFiles%\Cheat Engine*") do (
  if not exist "bin\dbk64.sys"  if exist "%%E\dbk64.sys"  copy /y "%%E\dbk64.sys"  "bin\" >nul & echo   [copied] dbk64.sys  from "%%E"
  if not exist "bin\vmdisk.img" if exist "%%E\vmdisk.img" copy /y "%%E\vmdisk.img" "bin\" >nul & echo   [copied] vmdisk.img from "%%E"
)
for /d %%E in ("%ProgramFiles(x86)%\Cheat Engine*") do (
  if not exist "bin\dbk64.sys"  if exist "%%E\dbk64.sys"  copy /y "%%E\dbk64.sys"  "bin\" >nul & echo   [copied] dbk64.sys  from "%%E"
  if not exist "bin\vmdisk.img" if exist "%%E\vmdisk.img" copy /y "%%E\vmdisk.img" "bin\" >nul & echo   [copied] vmdisk.img from "%%E"
)
if exist "bin\dbk64.sys"  (echo   [OK] bin\dbk64.sys)  else (echo   [MISSING] bin\dbk64.sys  - not found: get it from a Cheat Engine install, or ask me to build it from DBKKernel source)
if exist "bin\vmdisk.img" (echo   [OK] bin\vmdisk.img) else (echo   [MISSING] bin\vmdisk.img - not found: vmdisk.img can only be built on Linux, download it from CE or ask for help)

echo.
echo ============================================================
echo   Build OK!
echo     bin\CEdbg.exe  GUI debugger + DBVM loader
echo   To use DBVM: run bin\CEdbg.exe as Administrator,
echo   menu Plugin(P) -^> Load and start DBVM...  (needs bin\dbk64.sys + bin\vmdisk.img)
echo ============================================================
pause
exit /b 0

:fail
echo.
echo [ERROR] Build failed, see messages above.
pause
exit /b 1
