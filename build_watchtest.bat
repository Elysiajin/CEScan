@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
rem ---- 便携 MSVC 工具链（与主工程一致）----
set "VCBIN=C:\Users\Administrator\Desktop\新建文件夹 (2)\vc+++曙光C++IDE+2014年6月21日\曙光C++IDE\Release\VC64"
set "INCLUDE=%VCBIN%\include"
set "LIB=%VCBIN%\lib"
set "PATH=%VCBIN%\bin;%PATH%"
set "CL=/nologo /std:c++latest /utf-8 /EHsc /O2 /W3 /MT /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /D_WINSOCKAPI_ /Iinclude"
if not exist obj_watch mkdir obj_watch

echo [1/3] 编译调试引擎...
cl /c /Fo:obj_watch\ src\CETypes.cpp src\CEUtil.cpp src\ProcessMemory.cpp src\RegionFilter.cpp src\PatternScan.cpp src\ScanEngine.cpp src\Disasm.cpp src\Debugger.cpp
if errorlevel 1 exit /b 1

echo [2/3] 链接监视验证工具 watchtest.exe...
cl /c /Fo:obj_watch\ tests\watch_harness.cpp
if errorlevel 1 exit /b 1
link /nologo /OUT:bin\watchtest.exe /SUBSYSTEM:CONSOLE /MACHINE:X64 ^
  obj_watch\watch_harness.obj obj_watch\CETypes.obj obj_watch\CEUtil.obj ^
  obj_watch\ProcessMemory.obj obj_watch\RegionFilter.obj obj_watch\PatternScan.obj ^
  obj_watch\ScanEngine.obj obj_watch\Disasm.obj obj_watch\Debugger.obj ^
  psapi.lib user32.lib advapi32.lib
if errorlevel 1 exit /b 1

echo [3/3] 编译测试目标 watch_target.exe...
cl /nologo /O2 /MT /utf-8 /EHsc /Fo:obj_watch\ tests\watch_target.cpp /Fe:bin\watch_target.exe
if errorlevel 1 exit /b 1

echo BUILD_OK
