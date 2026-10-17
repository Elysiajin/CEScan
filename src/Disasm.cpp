// ============================================================================
//  Disasm.cpp —— x64 迷你反汇编引擎实现
//  覆盖常见整数/数据搬运/控制流指令；遇到不认识的就按前缀+操作码估长
// ============================================================================
#include "Disasm.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace ce {

namespace {

struct Ctx {
  const ubyte* p;
  size_t len;
  ptruint rip;
  size_t pos = 0;
  bool rexW = false, rexR = false, rexX = false, rexB = false;
  int  opsize = 4;      // 操作数大小 4/8
  int  addrlen = 8;
  int  rep = 0;         // 0 无 1 F3 2 F2
  bool has66 = false;
  bool ok = true;
  bool hasRex = false;   // 出现过 0x40-0x4F（即使 REX 位全 0 也影响 8 位寄存器命名）
  bool rexPresent() const { return hasRex; }
};

ubyte Next(Ctx& c) {
  if (c.pos >= c.len) { c.ok = false; return 0x90; }
  return c.p[c.pos++];
}

const char* Reg64[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                       "r8","r9","r10","r11","r12","r13","r14","r15"};
const char* Reg32[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi",
                       "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
const char* Reg16[] = {"ax","cx","dx","bx","sp","bp","si","di",
                       "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
const char* Reg8[]  = {"al","cl","dl","bl","spl","bpl","sil","dil",
                       "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};

// r 传 0..15 的完整寄存器编号（已含 REX.R/B/X 扩展位）；
// rexPresent 只用于区分 8 位寄存器命名（al/ah 还是 al/spl）
std::string RegName(int r, int size, bool rexPresent) {
  const int idx = r & 15;
  if (size == 8) return Reg64[idx];
  if (size == 4) return Reg32[idx];
  if (size == 2) return Reg16[idx];
  if (!rexPresent && idx < 8)
    return std::string(1, "acdb"[idx & 3]) + (idx < 4 ? "l" : "h");  // al..bl / ah..bh
  return Reg8[idx];
}

std::string HexN(unsigned long long v, int digits) {
  char buf[32];
  snprintf(buf, sizeof(buf), "0x%0*llX", digits, (unsigned long long)v);
  return buf;
}

// ModRM 解析：reg 输出寄存器号(0-7，未含 REX.R)，rm 输出操作数文本
int ParseModRM(Ctx& c, int* regOut, std::string* rmOut) {
  ubyte modrm = Next(c);
  int mod = (modrm >> 6) & 3;
  int reg = (modrm >> 3) & 7;
  int rm  = modrm & 7;
  *regOut = reg;
  const bool rex = c.rexPresent();

  if (mod == 3) {                                  // 寄存器直接寻址
    *rmOut = RegName(rm | (c.rexB ? 8 : 0), c.opsize, rex);
    return mod;
  }

  std::string s = "[";
  int dispBytes = 0;                               // 0 / 1 / 4
  if (rm == 4) {                                   // SIB
    ubyte sib = Next(c);
    int scale = 1 << ((sib >> 6) & 3);
    int idxf  = (sib >> 3) & 7;
    int basef = sib & 7;
    if (!(mod == 0 && basef == 5))                 // basef==5 && mod==0 → 无基址，只有 disp32
      s += RegName(basef | (c.rexB ? 8 : 0), 8, rex);
    if (idxf != 4) {                               // idxf==4 且无 REX.X → 无变址
      if (s.size() > 1) s += "+";
      s += RegName(idxf | (c.rexX ? 8 : 0), 8, rex) + "*" + std::to_string(scale);
    }
    if (mod == 1) dispBytes = 1;
    else if (mod == 2 || (mod == 0 && basef == 5)) dispBytes = 4;
  } else if (mod == 0 && rm == 5) {                // RIP 相对
    int disp = 0;
    memcpy(&disp, c.p + c.pos, 4); c.pos += 4;
    ptruint target = c.rip + c.pos + (long long)disp;   // c.pos 已是本条指令末尾
    s += "rip";
    if (disp) s += (disp > 0 ? "+" : "-") +
                   HexN(disp < 0 ? -(unsigned long long)disp : (unsigned long long)disp, 1);
    *rmOut = s + "]  ; " + HexN(target, 8);
    return mod;
  } else {                                         // [reg]
    s += RegName(rm | (c.rexB ? 8 : 0), 8, rex);
    if (mod == 1) dispBytes = 1;
    else if (mod == 2) dispBytes = 4;
  }

  if (dispBytes) {
    long long disp = 0;
    if (dispBytes == 1) disp = (signed char)Next(c);
    else { int d32 = 0; memcpy(&d32, c.p + c.pos, 4); c.pos += 4; disp = d32; }
    if (disp) {
      if (s.size() > 1) s += (disp > 0 ? "+" : "-");
      s += HexN(disp < 0 ? -(unsigned long long)disp : (unsigned long long)disp, 1);
    }
  }
  *rmOut = s + "]";
  return mod;
}

std::string Mnemonic(Ctx& c, const char* mn) {
  std::string s = mn;
  if (c.rep == 1) s = "rep " + s;
  if (c.rep == 2) s = "repne " + s;
  return s;
}

} // anonymous namespace

int Disassemble(const ubyte* code, size_t maxLen, ptruint rip, DisasmResult* out) {
  Ctx c{code, maxLen, rip};
  DisasmResult r;

  // ---- 前缀 ----
  for (;;) {
    ubyte b = code[c.pos];
    if (b == 0x66) { c.has66 = true; c.opsize = 2; c.pos++; continue; }
    if (b == 0x67) { c.addrlen = 4; c.pos++; continue; }
    if (b == 0xF3) { c.rep = 1; c.pos++; continue; }
    if (b == 0xF2) { c.rep = 2; c.pos++; continue; }
    if (b == 0xF0) { c.pos++; continue; }             // lock
    if (b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36 || b == 0x64 || b == 0x65) { c.pos++; continue; }
    if (b >= 0x40 && b <= 0x4F) { // REX
      c.hasRex = true;
      c.rexW = (b & 8) != 0; c.rexR = (b & 4) != 0;
      c.rexX = (b & 2) != 0; c.rexB = (b & 1) != 0;
      if (c.rexW) c.opsize = 8;
      c.pos++; continue;
    }
    break;
  }

  ubyte op = Next(c);
  std::string text;
  int reg; std::string rm;

  // ---- int3 ----
  if (op == 0xCC) {
    r.text = "int3"; r.isInt3 = true; r.length = c.pos;
    if (out) *out = r;
    return r.length;
  }
  // ---- NOP ----
  if (op == 0x90) {
    r.text = "nop"; r.length = c.pos;
    if (out) *out = r; return r.length;
  }
  // ---- ret ----
  if (op == 0xC3 || op == 0xC2) {
    if (op == 0xC2) c.pos += 2;
    r.text = "ret"; r.isRet = true; r.length = c.pos;
    if (out) *out = r; return r.length;
  }
  // ---- call/jmp rel32 ----
  if (op == 0xE8 || op == 0xE9) {
    int rel = 0; memcpy(&rel, code + c.pos, 4); c.pos += 4;
    ptruint target = rip + c.pos + rel;
    text = (op == 0xE8 ? "call " : "jmp ") + HexN(target, 8);
    r.isCall = (op == 0xE8); r.isJump = (op == 0xE9); r.jumpTarget = target;
    r.text = text; r.length = c.pos;
    if (out) *out = r; return r.length;
  }
  // ---- mov [moffs64], eax (A3, x64 绝对地址写) ----
  if (op == 0xA3) {
    if (c.pos + 8 > c.len) { c.ok = false; r.length = 0; if (out) *out = r; return 0; }
    uint64_t a = 0; memcpy(&a, code + c.pos, 8); c.pos += 8;
    char b[32];
    std::snprintf(b, sizeof(b), "%llX", (unsigned long long)a);
    r.text = std::string("mov [") + b + "], eax";
    r.length = c.pos;
    if (out) *out = r; return r.length;
  }
  // ---- jmp rel8 ----
  if (op == 0xEB) {
    char rel = (char)Next(c);
    ptruint target = rip + c.pos + rel;
    r.text = "jmp " + HexN(target, 8); r.isJump = true; r.jumpTarget = target;
    r.length = c.pos;
    if (out) *out = r; return r.length;
  }
  // ---- Jcc rel32 (0F 8x) / rel8 (7x) ----
  const char* jcc[] = {"jo","jno","jb","jae","je","jne","jbe","ja","js","jns","jp","jnp","jl","jge","jle","jg"};
  if (op == 0x0F) {
    ubyte op2 = Next(c);
    if (op2 >= 0x80 && op2 <= 0x8F) {
      int rel = 0; memcpy(&rel, code + c.pos, 4); c.pos += 4;
      ptruint t = rip + c.pos + rel;
      r.text = std::string(jcc[op2 - 0x80]) + " " + HexN(t, 8);
      r.isJump = true; r.jumpTarget = t; r.length = c.pos;
      if (out) *out = r; return r.length;
    }
    if (op2 >= 0x90 && op2 <= 0x9F) { // setcc
      r.text = std::string("set") + jcc[op2 - 0x90];
      ParseModRM(c, &reg, &rm);
      r.text += " " + rm; r.length = c.pos;
      if (out) *out = r; return r.length;
    }
    if (op2 == 0x05) { r.text = "syscall"; r.length = c.pos; if (out) *out = r; return r.length; }
    if (op2 == 0x0B) { r.text = "ud2"; r.length = c.pos; if (out) *out = r; return r.length; }
    if (op2 == 0x1F) { // nop dword [..]
      ParseModRM(c, &reg, &rm);
      r.text = "nop " + rm; r.length = c.pos;
      if (out) *out = r; return r.length;
    }
    if (op2 == 0x10 || op2 == 0x11) { // movups/movupd/movss
      ParseModRM(c, &reg, &rm);
      r.text = Mnemonic(c, op2 == 0x10 ? "movups" : "movups") + " " + (op2==0x10?rm:Reg32[reg&7])+","+(op2==0x10?Reg32[reg&7]:rm);
      r.length = c.pos;
      if (out) *out = r; return r.length;
    }
    if (op2 == 0xAF) { // imul r, rm
      ParseModRM(c, &reg, &rm);
      r.text = "imul " + RegName(reg | (c.rexR?8:0), c.opsize, c.rexPresent()) + ", " + rm;
      r.length = c.pos; if (out) *out = r; return r.length;
    }
    if (op2 == 0xB6 || op2 == 0xB7) { // movzx
      ParseModRM(c, &reg, &rm);
      r.text = "movzx " + RegName(reg | (c.rexR?8:0), c.opsize, c.rexPresent()) + ", " + rm;
      r.length = c.pos; if (out) *out = r; return r.length;
    }
    if (op2 == 0xBE || op2 == 0xBF) { // movsx
      ParseModRM(c, &reg, &rm);
      r.text = "movsx " + RegName(reg | (c.rexR?8:0), c.opsize, c.rexPresent()) + ", " + rm;
      r.length = c.pos; if (out) *out = r; return r.length;
    }
    // 未知 0F：估长按 modrm
    ParseModRM(c, &reg, &rm);
    r.text = "db 0F " + HexN(op2, 2); r.length = c.pos;
    if (out) *out = r; return r.length;
  }

  // ---- Jcc rel8 ----
  if (op >= 0x70 && op <= 0x7F) {
    char rel = (char)Next(c);
    ptruint t = rip + c.pos + rel;
    r.text = std::string(jcc[op - 0x70]) + " " + HexN(t, 8);
    r.isJump = true; r.jumpTarget = t; r.length = c.pos;
    if (out) *out = r; return r.length;
  }

  // ---- push/pop reg ----
  if (op >= 0x50 && op <= 0x57) {
    r.text = std::string("push ") + RegName((op - 0x50) | (c.rexB?8:0), 8, c.rexPresent());
    r.length = c.pos; if (out) *out = r; return r.length;
  }
  if (op >= 0x58 && op <= 0x5F) {
    r.text = std::string("pop ") + RegName((op - 0x58) | (c.rexB?8:0), 8, c.rexPresent());
    r.length = c.pos; if (out) *out = r; return r.length;
  }

  // ---- push imm8 / push imm32 ----
  // 这两条以前没实现，会掉进兜底变成 "db 0x6A" 且只算 1 字节，
  // 于是 "55 8B EC 6A FF"（push ebp/mov ebp,esp/push -1）这类
  // 经典函数序言的指令边界会算错长度 —— VM/HOOK 还原要靠边界对齐，必须补上。
  if (op == 0x6A) {
    signed char imm = (signed char)Next(c);
    r.text = imm < 0 ? ("push -" + HexN((unsigned long long)(-(long long)imm), 1))
                     : ("push " + HexN((unsigned long long)imm, 1));
    r.length = c.pos; if (out) *out = r; return r.length;
  }
  if (op == 0x68) {
    int imm = 0; memcpy(&imm, code + c.pos, 4); c.pos += 4;
    r.text = "push " + HexN((unsigned long long)(unsigned)imm, 8);
    r.length = c.pos; if (out) *out = r; return r.length;
  }

  // ---- 算术组 0x00-0x3F, 0x80-0x8D 等：按 "op + modrm" 处理 ----
  const char* arith[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
  if ((op & 7) <= 5 && op < 0x40) {
    const char* mn = arith[op >> 3];
    const int form = op & 7;
    if (form <= 3) {
      ParseModRM(c, &reg, &rm);
      if (form == 0) r.text = Mnemonic(c, mn) + " " + rm + ", " + RegName(reg | (c.rexR?8:0), c.opsize, c.rexPresent());
      else           r.text = Mnemonic(c, mn) + " " + RegName(reg | (c.rexR?8:0), c.opsize, c.rexPresent()) + ", " + rm;
    } else if (form == 4) {          // AL, imm8（4/5 型短格式以前被误当 modrm 解析，长度会错）
      long long imm = (signed char)Next(c);
      r.text = Mnemonic(c, mn) + " al, " + HexN(imm, 1);
    } else {                          // eAX, imm32
      int imm = 0; memcpy(&imm, code + c.pos, 4); c.pos += 4;
      r.text = Mnemonic(c, mn) + " eax, " + HexN((unsigned long long)(unsigned)imm, 8);
    }
    r.length = c.pos; if (out) *out = r; return r.length;
  }
  if (op == 0x80 || op == 0x81 || op == 0x83) {
    ParseModRM(c, &reg, &rm);
    const char* mn = arith[reg & 7];
    long long imm = 0;
    if (op == 0x81) { memcpy(&imm, code + c.pos, (c.opsize==8)?4:c.opsize/8); c.pos += (c.opsize==8)?4:c.opsize/8; }
    else { imm = (signed char)Next(c); }
    r.text = Mnemonic(c, mn) + " " + rm + ", " + HexN(imm, 1);
    r.length = c.pos; if (out) *out = r; return r.length;
  }
  if (op == 0x88 || op == 0x89 || op == 0x8A || op == 0x8B) { // mov
    ParseModRM(c, &reg, &rm);
    std::string rr = RegName(reg | (c.rexR?8:0), (op&1)?c.opsize:1, c.rexPresent());
    if (op & 2) r.text = "mov " + rr + ", " + rm;
    else        r.text = "mov " + rm + ", " + rr;
    r.length = c.pos; if (out) *out = r; return r.length;
  }
  if (op == 0xB0 || op == 0xB3) { /* mov r8, imm8 已被下面覆盖 */ }
  if (op >= 0xB8 && op <= 0xBF) { // mov r, imm32/64
    std::string rr = RegName((op - 0xB8) | (c.rexB?8:0), c.opsize, c.rexPresent());
    if (c.rexW) {
      unsigned long long imm = 0;
      memcpy(&imm, code + c.pos, 8); c.pos += 8;
      r.text = "movabs " + rr + ", " + HexN(imm, 1);
    } else {
      int imm = 0; memcpy(&imm, code + c.pos, 4); c.pos += 4;
      r.text = "mov " + rr + ", " + HexN(imm, 1);
    }
    r.length = c.pos; if (out) *out = r; return r.length;
  }
  if (op == 0xC6 || op == 0xC7) { // mov rm, imm
    ParseModRM(c, &reg, &rm);
    long long imm = 0;
    if (op == 0xC7) { memcpy(&imm, code + c.pos, (c.opsize==8)?4:c.opsize/8); c.pos += (c.opsize==8)?4:c.opsize/8; }
    else imm = (unsigned char)Next(c);
    r.text = "mov " + rm + ", " + HexN(imm, 1);
    r.length = c.pos; if (out) *out = r; return r.length;
  }
  if (op == 0xC9) { r.text = "leave"; r.length = c.pos; if (out) *out = r; return r.length; }
  if (op == 0x63) { // movsxd（源操作数固定 32 位）
    { int save = c.opsize; c.opsize = 4; ParseModRM(c, &reg, &rm); c.opsize = save; }
    r.text = "movsxd " + RegName(reg | (c.rexR?8:0), 8, c.rexPresent()) + ", " + rm;
    r.length = c.pos; if (out) *out = r; return r.length;
  }
  if (op == 0x8D) { // lea
    ParseModRM(c, &reg, &rm);
    r.text = "lea " + RegName(reg | (c.rexR?8:0), c.opsize, c.rexPresent()) + ", " + rm;
    r.length = c.pos; if (out) *out = r; return r.length;
  }
  if (op == 0xFF || op == 0xFE) { // 组：inc/dec/call/jmp/push
    ParseModRM(c, &reg, &rm);
    static const char* gFF[] = {"inc","dec","call","call far","jmp","jmp far","push","?"};
    const char* mn = (op == 0xFF) ? gFF[reg&7] : (reg==0?"inc":"dec");
    r.text = std::string(mn) + " " + rm;
    r.isCall = (reg == 2 || reg == 3);
    r.isJump = (reg == 4 || reg == 5);
    r.length = c.pos; if (out) *out = r; return r.length;
  }
  if (op == 0xA4 || op == 0xA5) { r.text = Mnemonic(c, (op==0xA4)?"movsb":"movsd"); r.length = c.pos; if (out) *out = r; return r.length; }
  if (op == 0xAB || op == 0xAA) { r.text = Mnemonic(c, "stosb/stosd"); r.length = c.pos; if (out) *out = r; return r.length; }
  if (op == 0x84 || op == 0x85) { // test
    ParseModRM(c, &reg, &rm);
    std::string rr = RegName(reg | (c.rexR?8:0), (op&1)?c.opsize:1, c.rexPresent());
    r.text = "test " + rm + ", " + rr;
    r.length = c.pos; if (out) *out = r; return r.length;
  }
  if (op >= 0xF6 && op <= 0xF7) { // test rm, imm / group3
    ParseModRM(c, &reg, &rm);
    long long imm = 0;
    if (reg == 0 || reg == 1) {
      if (op == 0xF7) { memcpy(&imm, code + c.pos, (c.opsize==8)?4:c.opsize/8); c.pos += (c.opsize==8)?4:c.opsize/8; }
      else imm = (unsigned char)Next(c);
      r.text = "test " + rm + ", " + HexN(imm, 1);
    } else {
      const char* g3[] = {"test","?","not","neg","mul","imul","div","idiv"};
      r.text = g3[reg & 7] + (" " + rm);
    }
    r.length = c.pos; if (out) *out = r; return r.length;
  }

  // ---- 兜底：按已有长度输出 db ----
  char buf[64];
  snprintf(buf, sizeof(buf), "db 0x%02X", op);
  r.text = buf;
  r.length = std::max<size_t>(c.pos, 1);
  if (out) *out = r;
  return r.length;
}

std::vector<DisasmResult> DisassembleRange(const ubyte* code, size_t len, ptruint base, int maxLines) {
  std::vector<DisasmResult> v;
  size_t off = 0;
  while (off < len && (maxLines <= 0 || (int)v.size() < maxLines)) {
    DisasmResult r;
    int n = Disassemble(code + off, len - off, base + off, &r);
    if (n <= 0) n = 1;
    v.push_back(r);
    off += n;
  }
  return v;
}

} // namespace ce
