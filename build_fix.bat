@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set "VCBIN=%~dp0vc64link"
set "INCLUDE=%VCBIN%\include"
set "LIB=%VCBIN%\lib"
set "PATH=%VCBIN%\bin;%PATH%"
if not exist bin mkdir bin
if not exist obj mkdir obj
del /q obj\*.obj 2>nul
set "CL=/nologo /std:c++latest /utf-8 /EHsc /O2 /W3 /MT /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /D_WINSOCKAPI_ /Iinclude /Fo:obj\"
for %%f in (CETypes CEUtil ProcessMemory RegionFilter PatternScan ScanEngine Disasm Debugger McpClient StrSearch HookRestore ThreadLocator main_entry main main_gui) do (
  cl /c src\%%f.cpp
  if errorlevel 1 exit /b 1
)
link /nologo /OUT:bin\CEScan.exe /SUBSYSTEM:CONSOLE /MACHINE:X64 obj\main_entry.obj obj\main.obj obj\CETypes.obj obj\CEUtil.obj obj\ProcessMemory.obj obj\RegionFilter.obj obj\PatternScan.obj obj\ScanEngine.obj obj\Disasm.obj obj\Debugger.obj obj\McpClient.obj obj\StrSearch.obj obj\HookRestore.obj psapi.lib user32.lib advapi32.lib ole32.lib ws2_32.lib winhttp.lib
if errorlevel 1 exit /b 1
link /nologo /OUT:bin\CEScanGUI.exe /SUBSYSTEM:WINDOWS /MACHINE:X64 obj\main_gui.obj obj\CETypes.obj obj\CEUtil.obj obj\ProcessMemory.obj obj\RegionFilter.obj obj\PatternScan.obj obj\ScanEngine.obj obj\Disasm.obj obj\Debugger.obj obj\McpClient.obj obj\StrSearch.obj obj\HookRestore.obj obj\ThreadLocator.obj psapi.lib user32.lib advapi32.lib ole32.lib oleaut32.lib comctl32.lib comdlg32.lib gdi32.lib ws2_32.lib winhttp.lib
if errorlevel 1 exit /b 1
echo BUILD_OK
