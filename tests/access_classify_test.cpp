// ============================================================================
//  access_classify_test.cpp —— 「访问性质自动分类」验证程序
//
//  验证 ClassifyAccessStatic / RefineAccessVerdict 的判定规则：
//    · crc32 指令                        → CRC校验（置信度3）
//    · RIP 在匿名可执行内存 + 累加特征   → CRC(VM区)
//    · RIP 在匿名可执行内存（其他指令）  → VM/检测代码（置信度3）
//    · 模块内 cmp/test [mem]             → 检测(比对)
//    · 模块内 add/xor（读值后累加）      → CRC校验
//    · 模块内 mov 读 / 写入              → 普通访问 / 普通写入
//    · 普通 mov + 高频规律轮询           → 疑似轮询（行为修正）
//    · CRC 判定 + 规律轮询               → 置信度提升
//  不需要目标进程：分类只吃指令文本与标志位。
// ============================================================================
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <cstdio>
#include <string>

#include "HookRestore.h"

using namespace ce;

static int g_pass = 0, g_fail = 0;

static void Check(const char* what, AccessKind kind, int conf,
                  const AccessVerdict& v) {
  const bool ok = (v.kind == kind && v.confidence == conf);
  if (ok) { ++g_pass; std::printf("  [PASS] %s\n", what); }
  else {
    ++g_fail;
    std::printf("  [FAIL] %s\n         期望 kind=%d conf=%d，实际 kind=%d conf=%d"
                " label=%s\n",
                what, (int)kind, conf, (int)v.kind, v.confidence, v.label.c_str());
  }
}

int main() {
  std::printf("== 访问性质自动分类 ==\n\n");

  // 1) 硬件 CRC32 指令
  Check("crc32 eax, byte ptr [rsi]",
        AccessKind::CRC, 3,
        ClassifyAccessStatic("crc32 eax, byte ptr [rsi]", false, false));

  // 2) VM 区（不在模块里）+ 累加特征
  Check("VM区 add eax, byte [rax]",
        AccessKind::CRC, 2,
        ClassifyAccessStatic("add eax, byte ptr [rax]", false, true));
  Check("VM区 movzx 逐字节",
        AccessKind::CRC, 2,
        ClassifyAccessStatic("movzx eax, byte ptr [rsi]", false, true));

  // 3) VM 区（不在模块里）普通指令
  Check("VM区 mov 读取",
        AccessKind::VM, 3,
        ClassifyAccessStatic("mov eax, dword ptr [rbx+0x28]", false, true));

  // 4) 模块内直接比对 → 检测
  Check("模块内 cmp [hp], 0",
        AccessKind::Detect, 2,
        ClassifyAccessStatic("cmp dword ptr [rbx+0x28], 0", false, false));
  Check("模块内 test [hp], ecx",
        AccessKind::Detect, 2,
        ClassifyAccessStatic("test dword ptr [rbx+0x28], ecx", false, false));

  // 5) 模块内累加 → CRC
  Check("模块内 add edx, [hp]",
        AccessKind::CRC, 2,
        ClassifyAccessStatic("add edx, dword ptr [rcx+4]", false, false));
  Check("模块内 rep movsd（拷贝代码页）",
        AccessKind::CRC, 2,
        ClassifyAccessStatic("rep movsd dword ptr [rdi], dword ptr [rsi]",
                             false, false));

  // 6) 模块内普通读写
  Check("模块内 mov 读取",
        AccessKind::Normal, 1,
        ClassifyAccessStatic("mov eax, dword ptr [rbx+0x28]", false, false));
  Check("模块内 mov 写入",
        AccessKind::Normal, 2,
        ClassifyAccessStatic("mov dword ptr [rbx+0x28], eax", true, false));

  // 7) 特征不足
  Check("fld 浮点（待定）",
        AccessKind::Unknown, 0,
        ClassifyAccessStatic("fld qword ptr [rsp+0x30]", false, false));

  // 8) 行为修正：普通访问 + 高频规律轮询 → 疑似轮询
  {
    AccessVerdict base =
        ClassifyAccessStatic("mov eax, dword ptr [rbx+0x28]", false, false);
    AccessVerdict v = RefineAccessVerdict(base, 30, 100.0, 0.05);
    Check("普通mov+30次/100ms规律 → 疑似轮询",
          AccessKind::Detect, 1, v);
  }
  // 9) 行为修正：抖动大（不规律）→ 维持普通
  {
    AccessVerdict base =
        ClassifyAccessStatic("mov eax, dword ptr [rbx+0x28]", false, false);
    AccessVerdict v = RefineAccessVerdict(base, 30, 900.0, 1.20);
    Check("普通mov+抖动大 → 维持普通访问",
          AccessKind::Normal, 1, v);
  }
  // 10) 行为修正：CRC 判定 + 规律轮询 → 置信度 +1
  {
    AccessVerdict base =
        ClassifyAccessStatic("add edx, dword ptr [rcx+4]", false, false);
    AccessVerdict v = RefineAccessVerdict(base, 10, 100.0, 0.02);
    Check("CRC+规律轮询 → 置信度提升",
          AccessKind::CRC, 3, v);
  }
  // 11) count<3 不参与行为修正
  {
    AccessVerdict base =
        ClassifyAccessStatic("mov eax, dword ptr [rbx+0x28]", false, false);
    AccessVerdict v = RefineAccessVerdict(base, 2, 100.0, 0.05);
    Check("仅2次命中不升级",
          AccessKind::Normal, 1, v);
  }

  std::printf("\n结果: PASS=%d FAIL=%d\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
