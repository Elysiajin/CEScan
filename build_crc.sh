#!/bin/bash
# 编译 CRC 保护模拟靶子 + 自动寻找/绕过演示
#   bin/crc_target.exe   模拟游戏保护（CRC 完整性校验，被抓则退出码 2）
#   bin/crc_hunter.exe   自动寻找 CRC 检测点 + 过检测 + 自验证
set -e
VCBIN="C:/Users/Administrator/Desktop/新建文件夹 (2)/vc+++曙光C++IDE+2014年6月21日/曙光C++IDE/Release/VC64"
export INCLUDE="$VCBIN/include" LIB="$VCBIN/lib" PATH="$VCBIN/bin:$PATH" MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")"
mkdir -p obj_crc bin
CL="$VCBIN/bin/cl.exe"
LINK="$VCBIN/bin/link.exe"

# 靶子必须用 /Od：保持 add 立即数、cmp+jcc 的代码形状，供自动寻找匹配
"$CL" /nologo /Od /Zi /utf-8 /W3 /MT /D_CRT_SECURE_NO_WARNINGS \
      /c /Fo:obj_crc/ tests/crc_target.cpp
"$LINK" /nologo /OUT:bin/crc_target.exe /SUBSYSTEM:CONSOLE /MACHINE:X64 \
        obj_crc/crc_target.obj kernel32.lib user32.lib

# 猎手用 /O2 即可
"$CL" /nologo /O2 /Zi /utf-8 /W3 /MT /EHsc /D_CRT_SECURE_NO_WARNINGS \
      /c /Fo:obj_crc/ tools/crc_hunter.cpp
"$LINK" /nologo /OUT:bin/crc_hunter.exe /SUBSYSTEM:CONSOLE /MACHINE:X64 \
        obj_crc/crc_hunter.obj

echo BUILD_OK
