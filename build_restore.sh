#!/usr/bin/env bash
# 编译「VM/HOOK 还原字节自动查找」引擎 + 验证程序 + 靶子（bash 版）
set -e
cd "$(dirname "$0")"

VCBIN="C:/Users/Administrator/Desktop/新建文件夹 (2)/vc+++曙光C++IDE+2014年6月21日/曙光C++IDE/Release/VC64"
export INCLUDE="$VCBIN/include"
export LIB="$VCBIN/lib"
export PATH="$VCBIN/bin:$PATH"
export MSYS2_ARG_CONV_EXCL="*"

CLFLAGS="/nologo /std:c++latest /utf-8 /EHsc /O2 /W3 /MT /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /D_WINSOCKAPI_ /Iinclude"
mkdir -p obj_restore bin

echo "[1/3] 编译还原引擎 + 依赖..."
"$VCBIN/bin/cl.exe" $CLFLAGS /c /Fo:obj_restore/ \
  src/CETypes.cpp src/CEUtil.cpp src/ProcessMemory.cpp src/Disasm.cpp \
  src/HookRestore.cpp 2>&1 \
  | tr -d '\000' | grep -a -vE "warning C4819" || true

echo "[2/3] 编译验证程序..."
"$VCBIN/bin/cl.exe" $CLFLAGS /c /Fo:obj_restore/ tests/hook_restore_test.cpp 2>&1 \
  | tr -d '\000' | grep -a -vE "warning C4819" || true
"$VCBIN/bin/link.exe" /nologo /OUT:bin/hook_restore_test.exe /SUBSYSTEM:CONSOLE /MACHINE:X64 \
  obj_restore/hook_restore_test.obj obj_restore/HookRestore.obj obj_restore/Disasm.obj \
  obj_restore/ProcessMemory.obj obj_restore/CETypes.obj obj_restore/CEUtil.obj \
  psapi.lib user32.lib advapi32.lib 2>&1 | tr -d '\000'

echo "[3/3] 编译靶子 hook_target.exe..."
"$VCBIN/bin/cl.exe" /nologo /O2 /MT /utf-8 /EHsc /Fo:obj_restore/ \
  tests/hook_target.cpp /Fe:bin/hook_target.exe 2>&1 | tr -d '\000'

echo "BUILD_OK"
ls -la bin/hook_restore_test.exe bin/hook_target.exe
