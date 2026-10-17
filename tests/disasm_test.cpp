// ============================================================================
//  disasm_test.cpp —— 迷你反汇编引擎回归测试
//  用手工编码的字节序列核对寄存器编号 / ModRM / SIB / RIP 相对 / 位移，
//  防止"mov r9d, r8]"这类寄存器错位回归。
// ============================================================================
#include "../include/Disasm.h"
#include <stdio.h>
#include <string.h>

using namespace ce;

struct Case {
  const char* bytes;   // 空格分隔的十六进制
  const char* expect;  // 期望的 Intel 风格文本（不含长度）
  int len = 0;         // 0 = 不校验长度；指令长度错会让"边界对齐"类算法算错，故可单独断言
};

static const Case kCases[] = {
  {"8B 08",                     "mov ecx, [rax]"},
  {"89 08",                     "mov [rax], ecx"},
  {"8B 00",                     "mov eax, [rax]"},
  {"41 8B 00",                  "mov eax, [r8]"},
  {"41 89 00",                  "mov [r8], eax"},
  {"4D 8B 00",                  "mov r8, [r8]"},
  {"49 89 10",                  "mov [r8], rdx"},
  {"48 8B 43 08",               "mov rax, [rbx+0x8]"},
  {"48 8B 45 F8",               "mov rax, [rbp-0x8]"},
  {"8B 44 24 08",               "mov eax, [rsp+0x8]"},
  {"48 8B 05 10 00 00 00",      "mov rax, [rip+0x10]  ; 0x00001017"},
  {"48 8D 0D 20 00 00 00",      "lea rcx, [rip+0x20]  ; 0x00001027"},
  {"4C 8B 04 25 00 10 00 00",   "mov r8, [0x1000]"},
  {"55",                        "push rbp"},
  {"5D",                        "pop rbp"},
  {"C3",                        "ret"},
  {"90",                        "nop"},
  {"48 83 EC 28",               "sub rsp, 0x28"},
  {"B8 01 00 00 00",            "mov eax, 0x1"},
  {"48 63 C1",                  "movsxd rax, ecx"},
  {"88 08",                     "mov [rax], cl"},
  {"40 88 38",                  "mov [rax], dil"},
  // ---- push 立即数 / AL,eAX 短格式（VM/HOOK 还原要靠它们算指令长度）----
  {"6A FF",                     "push -0x1", 2},
  {"6A 08",                     "push 0x8", 2},
  {"68 10 74 68 01",            "push 0x01687410", 5},
  {"55 8B EC 6A FF",            "push rbp", 1},          // 经典序言第一条，长度必须=1
  {"04 05",                     "add al, 0x5", 2},
  // ---- A3 moffs64：x64 绝对地址写（VM 蹦床常用）----
  {"A3 34 12 78 56 00 00 00 00", "mov [56781234], eax", 9},
  {"3C 41",                     "cmp al, 0x41", 2},
  {"2D 01 00 00 00",            "sub eax, 0x00000001", 5},
  {"E9 4A 78 65 01",            "jmp 0x0165884F", 5},
};

static int HexVal(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

int main() {
  int pass = 0, fail = 0;
  for (const Case& c : kCases) {
    ubyte buf[16] = {};
    int n = 0;
    for (const char* p = c.bytes; *p && n < 16;) {
      while (*p == ' ') ++p;
      if (!*p) break;
      int hi = HexVal(*p++), lo = HexVal(*p++);
      if (hi < 0 || lo < 0) break;
      buf[n++] = (ubyte)((hi << 4) | lo);
    }
    DisasmResult r;
    int len = Disassemble(buf, (size_t)n, 0x1000, &r);
    bool ok = (r.text == c.expect) && (c.len == 0 || len == c.len);
    printf("%s  %-26s  len=%d  got=\"%s\"%s\n", ok ? "[OK]  " : "[FAIL]",
           c.bytes, len, r.text.c_str(),
           ok ? "" : (std::string("   期望 \"") + c.expect + "\"" +
                      (c.len ? (" 长度=" + std::to_string(c.len)) : "")).c_str());
    ok ? ++pass : ++fail;
  }
  printf("\n通过 %d / 失败 %d\n", pass, fail);
  return fail ? 1 : 0;
}
