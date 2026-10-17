#!/usr/bin/env bash
# 用便携 MSVC 编译「谁访问/谁写入」测试工具（bash 版，避免 cmd 校验限制）
set -e
cd "$(dirname "$0")"

VCBIN="C:/Users/Administrator/Desktop/新建文件夹 (2)/vc+++曙光C++IDE+2014年6月21日/曙光C++IDE/Release/VC64"
export INCLUDE="$VCBIN/include"
export LIB="$VCBIN/lib"
export PATH="$VCBIN/bin:$PATH"
export MSYS2_ARG_CONV_EXCL="*"

CLFLAGS="/nologo /std:c++latest /utf-8 /EHsc /O2 /W3 /MT /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /D_WINSOCKAPI_ /Iinclude"
mkdir -p obj_watch bin

echo "[1/3] 编译调试引擎 + 测试目标..."
"$VCBIN/bin/cl.exe" $CLFLAGS /c /Fo:obj_watch/ \
  src/CETypes.cpp src/CEUtil.cpp src/ProcessMemory.cpp src/RegionFilter.cpp \
  src/PatternScan.cpp src/ScanEngine.cpp src/Disasm.cpp src/Debugger.cpp 2>&1 \
  | tr -d '\000' | grep -a -v "C4819" || true

echo "[2/3] 编译监视验证工具..."
"$VCBIN/bin/cl.exe" $CLFLAGS /c /Fo:obj_watch/ tests/watch_harness.cpp 2>&1 \
  | tr -d '\000' | grep -a -v "C4819" || true
"$VCBIN/bin/link.exe" /nologo /OUT:bin/watchtest.exe /SUBSYSTEM:CONSOLE /MACHINE:X64 \
  obj_watch/watch_harness.obj obj_watch/CETypes.obj obj_watch/CEUtil.obj \
  obj_watch/ProcessMemory.obj obj_watch/RegionFilter.obj obj_watch/PatternScan.obj \
  obj_watch/ScanEngine.obj obj_watch/Disasm.obj obj_watch/Debugger.obj \
  psapi.lib user32.lib advapi32.lib 2>&1 | tr -d '\000'

echo "[3/3] 编译测试目标 watch_target.exe..."
"$VCBIN/bin/cl.exe" /nologo /O2 /MT /utf-8 /EHsc /Fo:obj_watch/ \
  tests/watch_target.cpp /Fe:bin/watch_target.exe 2>&1 | tr -d '\000'

echo "BUILD_OK"
ls -la bin/watchtest.exe bin/watch_target.exe
