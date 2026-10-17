#!/usr/bin/env bash
# 编译「硬件访问断点/线程定位」的控制台回归：
#   bin/hwbptest.exe       —— 断言工具（附加靶子、下 ba r1/ba w4、校验命中线程）
#   bin/hwbp_target.exe    —— 靶子（主线程+读线程读代码、写线程写数据）
#
# 与 build_gui.sh 同样做"失败即报错退出"：管道会吞掉 cl 的退出码，
# 编译失败时旧 obj 还在、link 照样成功，会得到一个假的"通过"。
set -e
cd "$(dirname "$0")"

VCBIN="C:/Users/Administrator/Desktop/新建文件夹 (2)/vc+++曙光C++IDE+2014年6月21日/曙光C++IDE/Release/VC64"
export INCLUDE="$VCBIN/include"
export LIB="$VCBIN/lib"
export PATH="$VCBIN/bin:$PATH"
export MSYS2_ARG_CONV_EXCL="*"

CLFLAGS="/nologo /std:c++latest /utf-8 /EHsc /O2 /W3 /MT /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /D_WINSOCKAPI_ /Iinclude"
mkdir -p obj_hwbp bin

run_cl() {   # 保留 cl 的退出码（管道会吃掉它）
  set +e
  "$VCBIN/bin/cl.exe" "$@" 2>&1 | tr -d '\000' | grep -a -vE "warning C4819|note:"
  local rc=${PIPESTATUS[0]}
  set -e
  if [ "$rc" -ne 0 ]; then echo "COMPILE_FAILED (cl exit=$rc)" >&2; exit 1; fi
}

echo "[1/4] 编译调试引擎..."
run_cl $CLFLAGS /c /Fo:obj_hwbp/ \
  src/CETypes.cpp src/CEUtil.cpp src/ProcessMemory.cpp src/Disasm.cpp src/Debugger.cpp

echo "[2/4] 编译断言工具..."
run_cl $CLFLAGS /c /Fo:obj_hwbp/ tests/hwbp_harness.cpp

echo "[3/4] 链接 bin/hwbptest.exe ..."
set +e
"$VCBIN/bin/link.exe" /nologo /OUT:bin/hwbptest.exe /SUBSYSTEM:CONSOLE /MACHINE:X64 \
  obj_hwbp/hwbp_harness.obj obj_hwbp/CETypes.obj obj_hwbp/CEUtil.obj \
  obj_hwbp/ProcessMemory.obj obj_hwbp/Disasm.obj obj_hwbp/Debugger.obj \
  psapi.lib user32.lib advapi32.lib 2>&1 | tr -d '\000'
LNKRC=${PIPESTATUS[0]}
set -e
if [ "$LNKRC" -ne 0 ]; then echo "LINK_FAILED (exit=$LNKRC)" >&2; exit 1; fi

echo "[4/4] 编译靶子 bin/hwbp_target.exe ..."
run_cl /nologo /O2 /MT /utf-8 /EHsc /Fo:obj_hwbp/hwbp_target.obj \
  tests/hwbp_target.cpp /Fe:bin/hwbp_target.exe

echo "BUILD_OK"
ls -la bin/hwbptest.exe bin/hwbp_target.exe
