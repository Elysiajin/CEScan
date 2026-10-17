@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem ============================================================
rem  DBVM Breakpoint self-test: build & run
rem    target  : a process with an infinite ++counter loop
rem    tester  : loads DBVM, sets a DBVM breakpoint on the target
rem               function, verifies freeze (下断) and resume (续跑)
rem
rem  Run with a fully elevated (Administrator) console:
rem    - loader talks to SCM to start the dbk driver
rem    - requires bin\dbk64.sys + bin\vmdisk.img already in place
rem ============================================================

rem ---- require admin (SCM access for kernel driver) ----
net session >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Please run this list from an Administrator console.
  goto :fail
)

rem ---- locate _BuildEnv toolchain (same as build script) ----
set "ENVROOT="
for /d %%D in ("%USERPROFILE%\Desktop\*") do (
  if exist "%%D\_BuildEnv\MSVC_x64\bin\x64\cl.exe" set "ENVROOT=%%D\_BuildEnv"
)
if not defined ENVROOT (
  echo [ERROR] _BuildEnv toolchain not found under %USERPROFILE%\Desktop
  goto :fail
)

set "CL_EXE=!ENVROOT!\MSVC_x64\bin\x64\cl.exe"
set "LINK_EXE=!ENVROOT!\MSVC_x64\bin\x64\link.exe"
set "INCLUDE=!ENVROOT!\SDK\Include\um;!ENVROOT!\SDK\Include\shared;!ENVROOT!\SDK\Include\ucrt;!ENVROOT!\SDK\Include\vc;!ENVROOT!\MSVC_x64\include;%CD%\include"
set "LIB=!ENVROOT!\SDK\Lib\x64"
set "PATH=!ENVROOT!\MSVC_x64\bin\x64;!PATH!"

if not exist "!CL_EXE!" ( echo [ERROR] cl.exe not found & goto :fail )
if not exist bin\dbk64.sys ( echo [ERROR] bin\dbk64.sys missing & goto :fail )
if not exist bin\vmdisk.img ( echo [ERROR] bin\vmdisk.img missing & goto :fail )

if not exist obj_test mkdir obj_test

set "CFLAGS=/nologo /c /utf-8 /std:c++latest /EHsc /O2 /D_WINSOCKAPI_ /DWIN32_LEAN_AND_MEAN"

echo [BUILD] compiling sources (per-file) ...
"!CL_EXE!" %CFLAGS% tests\dbvm_bp_target.cpp /Fo:obj_test\dbvm_bp_target.obj || goto :fail
"!CL_EXE!" %CFLAGS% tests\dbvm_bp_test.cpp    /Fo:obj_test\dbvm_bp_test.obj    || goto :fail
"!CL_EXE!" %CFLAGS% src\DBVM.cpp              /Fo:obj_test\DBVM.obj            || goto :fail
"!CL_EXE!" %CFLAGS% src\DbvmLoader.cpp        /Fo:obj_test\DbvmLoader.obj      || goto :fail
"!CL_EXE!" %CFLAGS% src\DbvmTools.cpp         /Fo:obj_test\DbvmTools.obj       || goto :fail

echo [BUILD] linking ...
"!LINK_EXE!" /nologo /OUT:obj_test\dbvm_bp_target.exe /SUBSYSTEM:CONSOLE obj_test\dbvm_bp_target.obj kernel32.lib user32.lib advapi32.lib || goto :fail
"!LINK_EXE!" /nologo /OUT:obj_test\dbvm_bp_test.exe /SUBSYSTEM:CONSOLE obj_test\dbvm_bp_test.obj obj_test\DBVM.obj obj_test\DbvmLoader.obj obj_test\DbvmTools.obj kernel32.lib user32.lib advapi32.lib || goto :fail

echo [RUN] DBVM breakpoint self-test ...
"!CD!\obj_test\dbvm_bp_test.exe" "!CD!\obj_test\dbvm_bp_target.exe" "!CD!\bin\dbk64.sys" "!CD!\bin\vmdisk.img"
set "TESTRC=%ERRORLEVEL%"
echo [RUN] tester exit code = %TESTRC%
exit /b %TESTRC%

:fail
echo [FAILED] DBVM breakpoint self-test aborted.
exit /b 1