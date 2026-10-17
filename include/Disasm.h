#pragma once
// ============================================================================
//  Disasm.h —— x64 迷你反汇编引擎（够用于调试器显示，不追求 100% 覆盖）
// ============================================================================
#include <string>
#include <vector>
#include "CETypes.h"

namespace ce {

struct DisasmResult {
  std::string text;      // "mov eax, [rbx+8]" 风格文本
  int  length = 0;       // 指令长度（字节）
  bool isCall = false;
  bool isJump = false;
  bool isRet  = false;
  bool isInt3 = false;
  ptruint jumpTarget = 0;
};

// 反汇编一条指令；返回 length；失败时 length=1, text="db ??"
int Disassemble(const ubyte* code, size_t maxLen, ptruint rip, DisasmResult* out);

// 便捷：把一段内存反汇编成多行
std::vector<DisasmResult> DisassembleRange(const ubyte* code, size_t len, ptruint base, int maxLines);

} // namespace ce
