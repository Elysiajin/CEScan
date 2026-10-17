#!/usr/bin/env bash
# 编译 CEScanVC 的 GUI（bash 版）。产物为 bin/CEdbg.exe，
# 避免与并行会话正在运行的 bin/CEScanGUI.exe 抢文件锁。
set -e
cd "$(dirname "$0")"

VCBIN="D:/dnf工具2/vc/VC64"
export INCLUDE="$VCBIN/include"
export LIB="$VCBIN/lib"
export PATH="$VCBIN/bin:$PATH"
export MSYS2_ARG_CONV_EXCL="*"

OUT="${1:-CEdbg}"
CLFLAGS="/nologo /std:c++latest /utf-8 /EHsc /O2 /W3 /MT /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /D_WINSOCKAPI_ /Iinclude"
mkdir -p obj_gui bin

echo "[1/2] 编译 GUI 与依赖..."
set +e
"$VCBIN/bin/cl.exe" $CLFLAGS /c /Fo:obj_gui/ \
  src/main_gui.cpp src/CETypes.cpp src/CEUtil.cpp src/ProcessMemory.cpp \
  src/RegionFilter.cpp src/PatternScan.cpp src/ScanEngine.cpp src/Disasm.cpp \
  src/Debugger.cpp src/McpClient.cpp src/StrSearch.cpp src/HookRestore.cpp \
  src/ThreadLocator.cpp src/DBVM.cpp src/DbvmLoader.cpp src/DbvmTools.cpp 2>&1 \
  | tr -d '\000' | grep -a -vE "warning C4819|warning C4267|warning C4477|warning C4554|warning C4806|warning C4101|note:"
CLRC=${PIPESTATUS[0]}
set -e
# 注意：不能只看脚本末尾是否打印 BUILD_OK —— 管道会吃掉 cl 的退出码，
# 编译失败时旧 obj 仍在，link 照样成功，就会得到一个"假成功"的旧 exe。
if [ "$CLRC" -ne 0 ]; then
  echo ""
  echo "COMPILE_FAILED (cl exit=$CLRC) —— bin/$OUT.exe 未被更新，禁止拿它做验证！" >&2
  exit 1
fi

echo "[2/2] 链接 bin/$OUT.exe ..."
set +e
"$VCBIN/bin/link.exe" /nologo /OUT:bin/$OUT.exe /SUBSYSTEM:WINDOWS /MACHINE:X64 /MAP:obj_gui/$OUT.map \
  obj_gui/main_gui.obj obj_gui/CETypes.obj obj_gui/CEUtil.obj obj_gui/ProcessMemory.obj \
  obj_gui/RegionFilter.obj obj_gui/PatternScan.obj obj_gui/ScanEngine.obj \
  obj_gui/Disasm.obj obj_gui/Debugger.obj obj_gui/McpClient.obj obj_gui/StrSearch.obj \
  obj_gui/HookRestore.obj obj_gui/ThreadLocator.obj obj_gui/DBVM.obj obj_gui/DbvmLoader.obj obj_gui/DbvmTools.obj \
  psapi.lib user32.lib advapi32.lib ole32.lib oleaut32.lib comdlg32.lib comctl32.lib gdi32.lib ws2_32.lib winhttp.lib uxtheme.lib 2>&1 \
  | tr -d '\000'
LNKRC=${PIPESTATUS[0]}
set -e
if [ "$LNKRC" -ne 0 ]; then
  echo ""
  echo "LINK_FAILED (link exit=$LNKRC) —— bin/$OUT.exe 可能仍是旧文件！" >&2
  exit 1
fi

echo "BUILD_OK -> bin/$OUT.exe"
ls -la bin/$OUT.exe
