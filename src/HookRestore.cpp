// ============================================================================
//  HookRestore.cpp —— VM / HOOK 还原字节自动查找（实现）
//
//  思路（把《VM还原档案》的手工活自动化）：
//    ① 读命中地址处的字节，判断是不是 HOOK（E9/EB/E8/FF25/FF15/mov rax,imm64+jmp rax）
//    ② 算出"跳回点" R：
//         - 普通 5 字节 jmp → R = A+5
//         - 档案 2/2.txt 的 7 字节情形（jmp 5 + nop 2）→ R = A+5+尾部NOP数
//    ③ 全进程扫一遍可执行内存，找"跳到 R"的指令（jmp/call/push R）
//    ④ 该指令前面那 hookLen 个字节就是被覆盖掉的原始指令 —— 即还原字节
//    ⑤ 用反汇编器校验这段字节能否"刚好在跳回指令处结束"，能则高置信度
// ============================================================================
#include "HookRestore.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <map>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "Disasm.h"

namespace ce {
namespace {

//--- 小工具 -----------------------------------------------------------------

// 性能诊断开关：设 CE_RESTORE_TIMING=1 后会把各阶段耗时打到 stderr
bool TmOn() {
  static int v = -1;
  if (v < 0) { const char* e = ::getenv("CE_RESTORE_TIMING"); v = (e && *e == '1') ? 1 : 0; }
  return v != 0;
}

std::string HexSpaced(const ubyte* p, size_t n) {
  char b[8];
  std::string s;
  for (size_t i = 0; i < n; ++i) {
    std::snprintf(b, sizeof(b), "%02X ", p[i]);
    s += b;
  }
  if (!s.empty() && s.back() == ' ') s.pop_back();
  return s;
}

std::string HexAddr(ptruint v) {
  char b[32];
  if (v <= 0xFFFFFFFFull)
    std::snprintf(b, sizeof(b), "%08llX", (unsigned long long)v);
  else
    std::snprintf(b, sizeof(b), "%012llX", (unsigned long long)v);
  return b;
}

//--- ① HOOK 识别 -------------------------------------------------------------

struct HookInfo {
  int         len = 0;
  ptruint     target = 0;
  const char* kind = "";
  bool        indirect = false;   // 目标在内存里（FF 25/15）
};

bool DecodeHook(const ubyte* b, size_t n, ptruint addr, HookInfo* hi) {
  if (n >= 5 && b[0] == 0xE9) {
    int rel = 0; std::memcpy(&rel, b + 1, 4);
    hi->len = 5; hi->target = addr + 5 + (long long)rel; hi->kind = "jmp rel32";
    return true;
  }
  if (n >= 5 && b[0] == 0xE8) {
    int rel = 0; std::memcpy(&rel, b + 1, 4);
    hi->len = 5; hi->target = addr + 5 + (long long)rel; hi->kind = "call rel32";
    return true;
  }
  if (n >= 2 && b[0] == 0xEB) {
    signed char rel = (signed char)b[1];
    hi->len = 2; hi->target = addr + 2 + (long long)rel; hi->kind = "jmp rel8";
    return true;
  }
  if (n >= 6 && b[0] == 0xFF && b[1] == 0x25) {
    int disp = 0; std::memcpy(&disp, b + 2, 4);
    hi->len = 6; hi->target = addr + 6 + (long long)disp;   // 这里存的是"指针所在地址"
    hi->kind = "jmp [rip+disp]"; hi->indirect = true;
    return true;
  }
  if (n >= 6 && b[0] == 0xFF && b[1] == 0x15) {
    int disp = 0; std::memcpy(&disp, b + 2, 4);
    hi->len = 6; hi->target = addr + 6 + (long long)disp;
    hi->kind = "call [rip+disp]"; hi->indirect = true;
    return true;
  }
  // 常见热补丁：mov rax, imm64 ; jmp rax   （12 字节）
  if (n >= 12 && b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0) {
    unsigned long long t = 0; std::memcpy(&t, b + 2, 8);
    hi->len = 12; hi->target = (ptruint)t; hi->kind = "mov rax,imm64 + jmp rax";
    return true;
  }
  return false;
}

//--- ③④ 搜索"跳回点"并取前置字节 ---------------------------------------------

struct Region {
  ptruint base = 0;
  size_t  size = 0;
  int     cat = 3;
};

// 收集目标进程里所有"可执行且已提交"的区域，按"最像 VM 区"的顺序排好
void CollectExecRegions(ProcessMemory& proc, std::vector<Region>* out,
                        size_t* totalBytes) {
  *totalBytes = 0;
  HANDLE h = proc.Handle();
  if (!h || h == INVALID_HANDLE_VALUE) return;
  ptruint mn = 0, mx = 0;
  proc.AddressRange(&mn, &mx);
  ptruint addr = mn ? mn : 0x10000;
  MEMORY_BASIC_INFORMATION mbi{};
  while (addr < mx &&
         ::VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
    const ptruint base = (ptruint)mbi.BaseAddress;
    const size_t  size = mbi.RegionSize;
    if (size == 0) break;
    const DWORD p = mbi.Protect;
    if (mbi.State == MEM_COMMIT && !(p & PAGE_GUARD) && !(p & PAGE_NOACCESS) &&
        (p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
              PAGE_EXECUTE_WRITECOPY))) {
      const bool writable =
          (p & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_WRITECOPY)) != 0;
      int cat = 3;
      if (mbi.Type == MEM_PRIVATE) cat = writable ? 0 : 1;  // 最像 VM/蹦床区
      else if (mbi.Type == MEM_MAPPED) cat = 2;
      Region r; r.base = base; r.size = size; r.cat = cat;
      out->push_back(r);
      *totalBytes += size;
    }
    addr = base + size;
  }
  std::stable_sort(out->begin(), out->end(), [](const Region& a, const Region& b) {
    if (a.cat != b.cat) return a.cat < b.cat;
    return a.base < b.base;
  });
}

struct JumpHit {
  ptruint site = 0;
  int     kind = 0;   // 0=jmp rel32 1=call rel32 2=jmp rel8 3=push imm32
};

// 字节级快速预筛：只有 E9/E8/EB/68 才做算术校验，所以 200MB 也就一瞬间
void ScanForResume(ProcessMemory& proc, ptruint resume, size_t capBytes,
                   ptruint hintAddr, std::vector<JumpHit>* hits, ptruint* scanned,
                   size_t* regionCount, size_t* regionBytes, bool* hintScanned) {
  const DWORD t0 = TmOn() ? ::GetTickCount() : 0;
  std::vector<Region> regs;
  CollectExecRegions(proc, &regs, regionBytes);
  *regionCount = regs.size();
  if (TmOn())
    std::fprintf(stderr, "[tm] CollectExecRegions %u ms, %zu 区/%zu MB\n",
                 (unsigned)(::GetTickCount() - t0), regs.size(),
                 (size_t)(*regionBytes >> 20));

  // HOOK 跳去的那一页（VM/蹦床区）排到最前 —— 跳回指令几乎总在同一区域里，
  // 这样既快又不会因为总内存太大被扫描上限截断。
  ptruint hintBase = 0;
  size_t  hintSize = 0;
  if (hintAddr) {
    for (size_t i = 0; i < regs.size(); ++i) {
      if (hintAddr >= regs[i].base && hintAddr < regs[i].base + regs[i].size) {
        hintBase = regs[i].base;
        hintSize = regs[i].size;
        if (i != 0)
          std::rotate(regs.begin(), regs.begin() + i, regs.begin() + i + 1);
        break;
      }
    }
  }

  const size_t kChunk = 1u << 20;          // 1MB
  std::vector<ubyte> buf(kChunk + 16);
  *scanned = 0;
  DWORD tScan = TmOn() ? ::GetTickCount() : 0;
  size_t slowRegions = 0;
  for (const Region& rg : regs) {
    if (*scanned >= capBytes) break;
    if (hintBase && rg.base == hintBase && rg.size == hintSize) *hintScanned = true;
    size_t remaining = rg.size;
    ptruint pos = rg.base;
    while (remaining > 0 && *scanned < capBytes) {
      const size_t want = remaining < kChunk ? remaining : kChunk;
      const size_t got = proc.ReadPartial(pos, buf.data(), want);
      // 必须 <= 8：got==8 时下面的 step 会算成 0，内层循环永远退不出去（死循环）
      if (got <= 8) break;
      *scanned += got;
      const size_t lim = got - 8;          // 尾部 8 字节留给下一块（跨块指令）
      for (size_t i = 0; i < lim; ++i) {
        const ubyte op = buf[i];
        if (op == 0xE9 || op == 0xE8) {
          int rel = 0; std::memcpy(&rel, &buf[i + 1], 4);
          if ((ptruint)(pos + i + 5 + (long long)rel) == resume)
            hits->push_back({pos + i, op == 0xE9 ? 0 : 1});
        } else if (op == 0xEB) {
          signed char rel = (signed char)buf[i + 1];
          if ((ptruint)(pos + i + 2 + (long long)rel) == resume)
            hits->push_back({pos + i, 2});
        } else if (op == 0x68) {
          int imm = 0; std::memcpy(&imm, &buf[i + 1], 4);
          if ((ptruint)(unsigned)imm == resume) hits->push_back({pos + i, 3});
        }
        if (hits->size() >= 8) goto done;   // 少量候选足够，避免长跑
      }
      const size_t step = got - 8;
      pos += step;
      remaining -= step;
    }
    if (TmOn()) {
      const DWORD dt = ::GetTickCount() - tScan;
      if (dt > 200) {                        // 只报明显慢的区域
        ++slowRegions;
        std::fprintf(stderr, "[tm]   慢区 %llX size=%llu 读到 %llu ms\n",
                     (unsigned long long)rg.base, (unsigned long long)rg.size,
                     (unsigned long long)dt);
      }
      tScan = ::GetTickCount();
    }
  }
done:
  if (TmOn())
    std::fprintf(stderr, "[tm] ScanForResume 共扫 %llu MB / %zu 区，慢区 %zu 个\n",
                 (unsigned long long)(*scanned >> 20), regs.size(), slowRegions);
}

// 取 [site-hookLen, site) 作为还原字节，并用反汇编校验边界是否"刚好收在 site"
bool SolveRestore(ProcessMemory& proc, ptruint site, int hookLen,
                  std::vector<ubyte>* bytes, std::string* dis, bool* aligned) {
  if (hookLen <= 0 || hookLen > 32 || site < (ptruint)hookLen) return false;
  const ptruint start = site - (ptruint)hookLen;
  ubyte buf[64] = {};
  const size_t got = proc.ReadPartial(start, buf, (size_t)hookLen + 8);
  if (got < (size_t)hookLen) return false;
  bytes->assign(buf, buf + hookLen);

  size_t pos = 0;
  std::string text;
  bool bad = false;
  while (pos < (size_t)hookLen) {
    DisasmResult dr;
    int n = Disassemble(buf + pos, got - pos, start + pos, &dr);
    if (n <= 0) { n = 1; bad = true; }
    if (dr.text.compare(0, 3, "db ") == 0) bad = true;
    if (!text.empty()) text += " ; ";
    text += dr.text;
    pos += (size_t)n;
  }
  if (pos != (size_t)hookLen) bad = true;
  *dis = text;
  *aligned = !bad;
  return true;
}

}  // namespace

// ---------------------------------------------------------------------------
//  FindRestoreBytes
// ---------------------------------------------------------------------------

// ===========================================================================
//  多级回溯求解器 —— 《VM还原档案》3/1.txt 的自动化
//
//  档案原文（被 HOOK 的是 00A53D99，5 字节）：
//      "最后来到了这里……这里好像只存在 3 个字节 mov eax,[edx+0x48]
//       还少了 2 个。我们搜索 02F500A1 查找常量……（找到 023DCB12 call 02F500A1）
//       附近没有发现什么，再次查找常量 023DCB12 ……（找到 02F53C80 call 023DCB12）
//       剩下的 2 个字节找到了 mov edx,[esi]"
//
//  也就是说：跳回指令前面那几字节**不一定正好凑满 hookLen**，
//  差多少就要沿着"谁跳/调用到这里"再往上追一级，把缺的字节从上一级补回来。
//
//  算法（ChainSolve）：
//    ① 扫全进程，找所有"跳/调用/压栈 到 target"的指令（第一级 target = 跳回点 R）
//    ② 从命中点 site 往前取 L 字节，要求能"刚好反汇编到 site 结束"（对齐）
//    ③ L == need  → 齐了，直接返回
//    ④ L <  need  → 还缺 need-L，往上追一级，新目标取两个候选：
//         · H = 从 site 往前"最长完美对齐段"的起点（= 本 handler 的入口）
//         · site 本身（档案里"查找常量 023DCB12"就是拿那条 call 的地址当常量搜）
//       递归直到凑满或超过 maxDepth
//
//  档案 3 的两次上跳在算法里正好是：
//    级1 target=R(00A53D9E) → site=02F500B4 jmp R，取到 3 字节 8B 42 48，缺 2
//    级2 target=H(02F500A1) → site=023DCB12 call 02F500A1，前面凑不出
//    级3 target=023DCB12     → site=02F53C80 call 023DCB12，取到 2 字节 8B 16
//    拼起来 8B 16 8B 42 48 —— 与档案结论一致
// ===========================================================================

struct ChainNode {
  ptruint site = 0;    // 命中点（跳/调用指令所在地址）
  ptruint target = 0;  // 这一级搜索的目标地址
  int     len = 0;     // 从这一级取到的字节数
};

// 从 site 往前取 n 字节，且要求这 n 字节正好反汇编到 site 结束
static bool TakeAligned(ProcessMemory& proc, ptruint site, int n,
                        std::vector<ubyte>* bytes, std::string* dis) {
  std::string d;
  bool aligned = false;
  if (!SolveRestore(proc, site, n, bytes, &d, &aligned)) return false;
  if (!aligned) return false;
  *dis = d;
  return true;
}

// VM / 混淆壳的"垃圾指令"特征。
// 档案 3 里作者人工挑还原代码时，正是靠"认出哪些是 VM 自己的垃圾"：
// 例如 lea esp,[esp+0x34]（栈平衡）、pushfd/pushad/popad、bswap/das/aas/std 等。
// 取到的候选若混有这些，说明它不是纯粹的还原代码，应该让位给多级回溯的结果。
static bool IsVmJunky(const std::string& disasm) {
  static const char* kPat[] = {
      "pushfd", "popfd", "pushad", "popad", "bswap", "das ", "aas ", "aaa ",
      "std ",   "cld ",  "clc ",   "stc ",  "cwd ",  "cwde", "cdq ", "nop",
      "lea esp", "lea rsp", "lea  esp", "lea  rsp", "xchg", "salc",
  };
  std::string low;
  low.reserve(disasm.size());
  for (char c : disasm) low += (char)::tolower((unsigned char)c);
  for (const char* p : kPat)
    if (low.find(p) != std::string::npos) return true;

  // "对 8 位寄存器做立即数运算"（and al,0x34 / adc al,[rax] 之类）
  // 在正常函数头里几乎不出现，基本都是"从指令中间切开"产生的伪指令，
  // 或者 VM 混淆自己塞的垃圾 —— 一律视为可疑，让位给多级回溯。
  static const char* kArith[] = {"and", "or",  "adc", "sbb", "xor",
                                 "add", "sub", "cmp", "test"};
  static const char* kReg8[] = {"al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"};
  size_t pos = 0;
  for (;;) {
    const size_t e = low.find(" ; ", pos);
    std::string ins = (e == std::string::npos) ? low.substr(pos) : low.substr(pos, e - pos);
    for (const char* a : kArith) {
      if (ins.compare(0, std::strlen(a), a) != 0) continue;
      if (ins.size() <= std::strlen(a) || ins[std::strlen(a)] != ' ') continue;
      for (const char* r : kReg8) {
        std::string needle = std::string(" ") + r;
        if (ins.find(needle) != std::string::npos) return true;
      }
    }
    if (e == std::string::npos) break;
    pos = e + 3;
  }
  return false;
}

// 全进程"跳转表"：目标地址 → 所有跳/调用/压栈到它的指令位置。
// 只扫一次，之后各级回溯直接查表，不必每层重扫 128MB。
struct JumpTable {
  std::map<ptruint, std::vector<JumpHit>> byTarget;
};

static void CollectJumpTable(ProcessMemory& proc, ptruint hint, JumpTable* tab,
                             ptruint* scanned, size_t* regionCount,
                             size_t* regionBytes, bool* hintScanned) {
  std::vector<Region> regs;
  CollectExecRegions(proc, &regs, regionBytes);
  *regionCount = regs.size();

  ptruint hintBase = 0;
  size_t  hintSize = 0;
  if (hint) {
    for (size_t i = 0; i < regs.size(); ++i) {
      if (hint >= regs[i].base && hint < regs[i].base + regs[i].size) {
        hintBase = regs[i].base;
        hintSize = regs[i].size;
        if (i != 0) std::rotate(regs.begin(), regs.begin() + i, regs.begin() + i + 1);
        break;
      }
    }
  }

  const size_t   kChunk = 1u << 20;
  std::vector<ubyte> buf(kChunk + 16);
  *scanned = 0;
  const size_t kMaxEntries = 400000;      // 防止极端进程把内存吃满
  size_t       entries = 0;

  for (const Region& rg : regs) {
    if (*scanned >= (128ull << 20)) break;
    if (hintBase && rg.base == hintBase && rg.size == hintSize) *hintScanned = true;
    size_t  remaining = rg.size;
    ptruint pos = rg.base;
    while (remaining > 0 && *scanned < (128ull << 20)) {
      const size_t want = remaining < kChunk ? remaining : kChunk;
      const size_t got = proc.ReadPartial(pos, buf.data(), want);
      if (got <= 8) break;                 // 同上：got==8 时 step 会变 0，死循环
      *scanned += got;
      const size_t lim = got - 8;
      for (size_t i = 0; i < lim; ++i) {
        const ubyte op = buf[i];
        if (op == 0xE9 || op == 0xE8) {
          int     rel = 0;
          std::memcpy(&rel, &buf[i + 1], 4);
          const ptruint t = pos + i + 5 + (ptruint)(long long)rel;
          auto& v = tab->byTarget[t];
          if (v.size() < 64) { v.push_back({pos + i, op == 0xE9 ? 0 : 1}); ++entries; }
        } else if (op == 0xEB) {
          const ptruint t = pos + i + 2 + (ptruint)(long long)(signed char)buf[i + 1];
          auto& v = tab->byTarget[t];
          if (v.size() < 64) { v.push_back({pos + i, 2}); ++entries; }
        } else if (op == 0x68) {
          int imm = 0;
          std::memcpy(&imm, &buf[i + 1], 4);
          const ptruint t = (ptruint)(unsigned)imm;
          auto& v = tab->byTarget[t];
          if (v.size() < 64) { v.push_back({pos + i, 3}); ++entries; }
        }
      }
      const size_t step = got - 8;
      pos += step;
      remaining -= step;
      if (entries >= kMaxEntries) goto done;
    }
  }
done:
  (void)0;
}

// 从 site 往前找"能完美反汇编对齐到 site"的最长指令序列的起点
// —— 这通常就是本段 handler / 蹦床的入口（档案里人工认出的 02F500A1）
static ptruint FindAlignedStart(ProcessMemory& proc, ptruint site, int maxBack) {
  if (maxBack <= 0 || site < (ptruint)maxBack) return site;
  std::vector<ubyte> buf((size_t)maxBack);
  if (proc.ReadPartial(site - (ptruint)maxBack, buf.data(), (size_t)maxBack) !=
      (size_t)maxBack)
    return site;
  for (int k = maxBack; k >= 1; --k) {          // 从最长开始试，第一个成功的就是最长
    const size_t from = (size_t)(maxBack - k);
    size_t pos = from;
    bool ok = true;
    while (pos < (size_t)maxBack) {
      DisasmResult dr;
      const int n = Disassemble(buf.data() + pos, (size_t)maxBack - pos,
                                site - (ptruint)maxBack + pos, &dr);
      if (n <= 0 || dr.text.compare(0, 3, "db ") == 0) { ok = false; break; }
      pos += (size_t)n;
    }
    if (ok) return site - (ptruint)k;
  }
  return site;
}

// 从 site 往前 maxBack 字节，一次线性反汇编找出**所有**"能对齐到 site"的
// 指令起点，换算成相对 site 的距离 k（由小到大）。
// 这样每层只做 1 次读 + O(maxBack) 次反汇编，而不是对每个 k 都重读重解。
static void CollectAlignedStarts(ProcessMemory& proc, ptruint site, int maxBack,
                                 std::vector<int>* ks) {
  ks->clear();
  if (maxBack <= 0 || site < (ptruint)maxBack) return;
  std::vector<ubyte> buf((size_t)maxBack + 32);
  // site 常常贴着分配页的头部（蹦床就放在页首），一次读 64 字节会跨到
  // 不可读/未提交区域。逐步收缩回看窗口，直到读满为止。
  int back = maxBack;
  size_t got = 0;
  while (back >= 2) {
    got = proc.ReadPartial(site - (ptruint)back, buf.data(), (size_t)back + 32);
    if (got >= (size_t)back) break;
    back /= 2;
  }
  if (back < 2) return;
  maxBack = back;
  const size_t end = (size_t)maxBack;          // buf 里 site 对应的下标
  for (int k = 1; k <= maxBack; ++k) {
    const size_t from = end - (size_t)k;
    size_t pos = from;
    bool   ok = true;
    while (pos < end) {
      DisasmResult dr;
      const int n = Disassemble(buf.data() + pos, got - pos,
                                site - (ptruint)maxBack + pos, &dr);
      if (n <= 0 || dr.text.compare(0, 3, "db ") == 0) { ok = false; break; }
      pos += (size_t)n;
    }
    if (ok) ks->push_back(k);
  }
}

static bool ChainSolveTab(ProcessMemory& proc, const JumpTable& tab,
                          ptruint target, int need, int depth, int maxDepth,
                          bool allowJunk, int* budget, std::vector<ubyte>* out,
                          std::string* outDis, std::vector<ChainNode>* chain) {
  if (need <= 0) return true;
  if (need > 32 || depth > maxDepth) return false;
  if (--(*budget) <= 0) return false;          // 探索预算：防止组合爆炸
  const auto it = tab.byTarget.find(target);
  if (it == tab.byTarget.end()) return false;

  int tried = 0;
  for (const JumpHit& h : it->second) {
    if (tried >= 8) break;                     // 每个目标最多试 8 个命中点
    ++tried;
    std::vector<int> ks;
    CollectAlignedStarts(proc, h.site, 64, &ks);

    for (int L = need; L >= 1; --L) {          // 优先一步凑满，再试需要上追的短段
      if (std::find(ks.begin(), ks.end(), L) == ks.end()) continue;  // L 不是对齐边界
      std::vector<ubyte> b;
      std::string        d;
      if (!TakeAligned(proc, h.site, L, &b, &d)) continue;
      if (!allowJunk && IsVmJunky(d)) continue;

      if (L == need) {                         // 这一级就够了
        *out = b;
        *outDis = d;
        chain->push_back({h.site, target, L});
        return true;
      }

      // 还缺 need-L：往上追一级。
      // 上一级的目标 = 本段 handler 的入口（档案里人工认出的 02F500A1）。
      // 判定依据不是"对齐边界"，而是"这个地址被别处 call/jmp 引用过" ——
      // 真实壳里入口未必能反汇编对齐，用引用关系更稳。
      // map 有序 → 地址从小到大 = 离 site 由远及近，先试最外层的入口。
      int upTries = 0;
      const ptruint lo = h.site - 64;
      const ptruint hi = h.site - (ptruint)L;
      for (auto it2 = tab.byTarget.lower_bound(lo);
           it2 != tab.byTarget.end() && it2->first < hi; ++it2) {
        if (++upTries > 8) break;              // 每层最多试 8 个上游入口
        const ptruint p = it2->first;
        std::vector<ubyte>     pre;
        std::string            preDis;
        std::vector<ChainNode> sub;
        if (!ChainSolveTab(proc, tab, p, need - L, depth + 1, maxDepth, allowJunk,
                           budget, &pre, &preDis, &sub))
          continue;
        *out = pre;
        out->insert(out->end(), b.begin(), b.end());
        *outDis = preDis.empty() ? d : (preDis + " ; " + d);
        chain->insert(chain->end(), sub.begin(), sub.end());
        chain->push_back({h.site, target, L});
        return true;
      }
    }
  }
  return false;
}

// 把多级回溯的结果写进 RestoreResult（含可读的级链描述）
static bool TryChain(ProcessMemory& proc, ptruint resumeAddr, int hookLen,
                     ptruint hint, JumpTable* extTab, RestoreResult* r) {
  JumpTable local;
  JumpTable* tab = extTab ? extTab : &local;
  if (!extTab) {
    ptruint scanned = 0;
    size_t  rc = 0, rb = 0;
    bool    hs = false;
    CollectJumpTable(proc, hint, tab, &scanned, &rc, &rb, &hs);
    r->totalScanned = scanned;
    r->execRegions = rc;
    r->execBytes = rb;
    r->hintScanned = hs;
  }
  if (tab->byTarget.empty()) return false;

  std::vector<ubyte>     bytes;
  std::string            dis;
  std::vector<ChainNode> chain;
  int budget = 20000;                 // 探索预算：宁可放弃也不让分析卡死
  // 先要"不含 VM 垃圾"的解；实在没有再放宽
  bool ok = ChainSolveTab(proc, *tab, resumeAddr, hookLen, 0, 3, false, &budget,
                          &bytes, &dis, &chain);
  if (!ok) {
    bytes.clear(); dis.clear(); chain.clear();
    budget = 20000;
    ok = ChainSolveTab(proc, *tab, resumeAddr, hookLen, 0, 3, true, &budget,
                       &bytes, &dis, &chain);
  }
  if (!ok) return false;
  if ((int)bytes.size() != hookLen || chain.empty()) return false;

  r->found = true;
  r->origBytes = bytes;
  r->origHex = HexSpaced(bytes.data(), bytes.size());
  r->origDisasm = dis;
  r->confidence = 2;                       // 每一级都是对齐的指令，置信度高
  r->chainDepth = (int)chain.size();
  r->restoreSite = chain.back().site;      // 最底那一级 = 跳回指令所在

  std::string path;
  for (size_t i = 0; i < chain.size(); ++i) {
    if (i) path += "  ←  ";
    char b[192];
    std::snprintf(b, sizeof(b), "第%d级 搜%s → 命中 %s，取前 %d 字节",
                  (int)(chain.size() - i), HexAddr(chain[i].target).c_str(),
                  HexAddr(chain[i].site).c_str(), chain[i].len);
    path += b;
  }
  r->chainPath = path;

  char m[320];
  std::snprintf(m, sizeof(m),
                "多级回溯（共 %d 级，每级取对齐的指令片段拼成 %d 字节；《VM还原档案》3/1.txt 的做法）",
                (int)chain.size(), hookLen);
  r->method = m;
  r->note = (chain.size() > 1) ? "" : "";
  return true;
}

// 在已扫出来的一批"跳回点"里，取 hookLen 长度的前置字节，挑最好的一个。
// 与 ScanForResume 分开，是为了让 AnalyzeVMStub 能"只扫一次、试多个长度"
// （否则 31 个候选长度各扫一遍 128MB，要跑近 30 秒）。
//
// 三级择优：
//   ① 前置 hookLen 字节且边界对齐         → 高置信（档案 2 方法二）
//   ② 多级回溯：一级凑不齐就往上追       → 高置信（档案 3）
//   ③ 前置 hookLen 字节但边界不对齐      → 低置信兜底
static bool PickBest(ProcessMemory& proc, const std::vector<JumpHit>& hits,
                     ptruint resumeAddr, int hookLen, ptruint hint,
                     JumpTable* extTab, RestoreResult* r) {
  auto KindName = [](int k) -> const char* {
    return (k == 0) ? "jmp" : (k == 1) ? "call" : (k == 2) ? "jmp(短)" : "push";
  };

  // ① 前置 hookLen 字节，且反汇编边界正好收在跳回指令处。
  //    分"干净"和"混有 VM 垃圾"两档：干净的直接采用，
  //    带垃圾的先让位给多级回溯（档案 3 里作者正是这样人工取舍的）。
  struct Cand {
    bool               valid = false;
    ptruint            site = 0;
    int                kind = 0;
    std::vector<ubyte> bytes;
    std::string        dis;
  };
  auto Apply = [&](const Cand& c, const std::string& method,
                   const std::string& note) {
    r->found = true;
    r->restoreSite = c.site;
    r->origBytes = c.bytes;
    r->origHex = HexSpaced(c.bytes.data(), c.bytes.size());
    r->origDisasm = c.dis;
    r->confidence = 2;
    r->chainDepth = 1;
    r->method = method;
    r->note = note;
  };

  Cand clean, junky;
  for (const JumpHit& h : hits) {
    std::vector<ubyte> bytes;
    std::string        dis;
    if (!TakeAligned(proc, h.site, hookLen, &bytes, &dis)) continue;
    Cand c;
    c.valid = true; c.site = h.site; c.kind = h.kind; c.bytes = bytes; c.dis = dis;
    if (IsVmJunky(dis)) { if (!junky.valid) junky = c; }
    else                { clean = c; break; }
  }
  if (clean.valid) {
    char m[256];
    std::snprintf(m, sizeof(m),
                  "搜索跳回点：在 %s 找到 %s %s，取其前 %d 字节（《VM还原档案》方法二/三）",
                  HexAddr(clean.site).c_str(), KindName(clean.kind),
                  HexAddr(resumeAddr).c_str(), hookLen);
    Apply(clean, m, "");
    return true;
  }

  // ② 一级凑不齐 / 混了 VM 垃圾（档案 3 的典型情形）
  //    → 沿"谁跳/调用到这里"往上追一级，把缺的字节从上一级补回来
  if (TryChain(proc, resumeAddr, hookLen, hint, extTab, r)) return true;

  // ③ 退而求其次：带 VM 垃圾的对齐候选
  if (junky.valid) {
    char m[300];
    std::snprintf(m, sizeof(m),
                  "搜索跳回点：在 %s 找到 %s %s，取其前 %d 字节（含 VM 垃圾指令，未做多级回溯）",
                  HexAddr(junky.site).c_str(), KindName(junky.kind),
                  HexAddr(resumeAddr).c_str(), hookLen);
    Apply(junky, m, "该候选混有 VM 垃圾指令（如 lea rsp/pushfd），可能不是纯粹还原代码");
    return true;
  }

  // ③ 兜底：边界不干净也给出一个候选（里面可能夹着数据字节）
  int  bestScore = -1;
  bool any = false;
  for (const JumpHit& h : hits) {
    std::vector<ubyte> bytes;
    std::string        dis;
    bool aligned = false;
    if (!SolveRestore(proc, h.site, hookLen, &bytes, &dis, &aligned)) continue;
    if (aligned) continue;                  // 对齐的已在 ① 处理
    int score = 60;
    if (h.kind == 0) score += 10;
    else if (h.kind == 1) score += 4;
    if (score <= bestScore) continue;
    bestScore = score;
    any = true;
    r->found = true;
    r->restoreSite = h.site;
    r->origBytes = bytes;
    r->origHex = HexSpaced(bytes.data(), bytes.size());
    r->origDisasm = dis;
    r->confidence = 1;
    r->chainDepth = 1;
    const char* kn = (h.kind == 0)   ? "jmp"
                     : (h.kind == 1) ? "call"
                     : (h.kind == 2) ? "jmp(短)"
                                     : "push";
    char m[256];
    std::snprintf(m, sizeof(m),
                  "搜索跳回点：在 %s 找到 %s %s，取其前 %d 字节（边界未对齐，仅作候选）",
                  HexAddr(h.site).c_str(), kn, HexAddr(resumeAddr).c_str(),
                  hookLen);
    r->method = m;
    r->note = "字节边界未完全对齐（可能含数据），仅作候选";
  }
  return any;
}

RestoreResult FindRestoreBytes(ProcessMemory& proc, ptruint addr,
                               ptruint resumeAddr, int hookLen, ptruint hintAddr) {
  RestoreResult r;
  r.addr = addr;
  r.resumeAddr = resumeAddr;
  r.hookLen = hookLen;
  if (!proc.IsOpen()) { r.note = "进程未打开"; return r; }

  std::vector<JumpHit> hits;
  ScanForResume(proc, resumeAddr, 128ull << 20, hintAddr, &hits, &r.totalScanned,
                &r.execRegions, &r.execBytes, &r.hintScanned);
  if (hits.empty()) {
    char b[192];
    std::snprintf(b, sizeof(b),
                  "已扫 %llu MB（共 %llu 个可执行区/%llu MB），未找到跳回 %s 的指令",
                  (unsigned long long)(r.totalScanned >> 20),
                  (unsigned long long)r.execRegions,
                  (unsigned long long)(r.execBytes >> 20), HexAddr(resumeAddr).c_str());
    r.note = b;
    return r;
  }

  if (!PickBest(proc, hits, resumeAddr, hookLen, hintAddr, nullptr, &r))
    r.note = "找到跳回点但取不到前置字节";
  return r;
}

// ---------------------------------------------------------------------------
//  AnalyzeVMStub —— 命中的指令在 VM/蹦床区里（不是 HOOK 本身）
//
//  《VM还原档案》2/2.txt 的做法：
//    "他调回来的是下一句 00A53D9E 所以我们就搜索 jmp 00A53D9E"
//    （蹦床尾部必有一条跳回原函数的 jmp）
//    "刚刚好 7 个字节，于是还原了就是 ……"
//    （跳回点往前 hookLen 字节就是被偷走的原始代码）
//  再从跳回点往回反推 HOOK 入口（入口的 jmp 恰好跳进本 VM 区），
//  入口 + 长度都有了，就交给 FindRestoreBytes() 精确取字节。
// ---------------------------------------------------------------------------
static bool AllocOf(HANDLE h, ptruint a, ptruint* base) {
  MEMORY_BASIC_INFORMATION mbi{};
  if (!::VirtualQueryEx(h, (LPCVOID)a, &mbi, sizeof(mbi))) return false;
  *base = (ptruint)mbi.AllocationBase;
  return true;
}

static RestoreResult AnalyzeVMStub(ProcessMemory& proc, ptruint addr) {
  RestoreResult r;
  r.addr = addr;
  HANDLE h = proc.Handle();
  ptruint myAlloc = 0;
  if (!h || !AllocOf(h, addr, &myAlloc)) { r.note = "地址不可读"; return r; }

  // 1) 从命中处线性反汇编向前找"跳出本区的 jmp" = 蹦床尾部的跳回指令
  std::vector<ubyte> code(512);
  const size_t got = proc.ReadPartial(addr, code.data(), code.size());
  if (!got) { r.note = "地址不可读"; return r; }
  r.readable = true;
  code.resize(got);

  // 0) 先把命中处这条指令本身解出来，日志里"当前指令 / 写法"才不会空白
  {
    DisasmResult d0;
    const int l0 = Disassemble(code.data(), code.size(), addr, &d0);
    if (l0 > 0) {
      r.curBytes.assign(code.begin(), code.begin() + l0);
      r.curHex = HexSpaced(r.curBytes.data(), r.curBytes.size());
      r.curDisasm = d0.text;
    }
  }

  ptruint J = 0, T = 0;
  bool jumpBackFound = false;
  for (size_t p = 0; p < code.size();) {
    DisasmResult dr;
    const int len = Disassemble(code.data() + p, code.size() - p, addr + p, &dr);
    if (len <= 0) break;
    const ubyte b0 = code[p];
    ptruint t = 0;
    if (b0 == 0xE9 && p + 5 <= code.size()) {
      int32_t rel; std::memcpy(&rel, &code[p + 1], 4);
      t = addr + p + 5 + (int64_t)rel;
    } else if (b0 == 0xEB && p + 2 <= code.size()) {
      t = addr + p + 2 + (int8_t)code[p + 1];
    }
    if (t) {
      ptruint tAlloc = 0;
      if (AllocOf(h, t, &tAlloc) && tAlloc != myAlloc) {
        J = addr + p; T = t; jumpBackFound = true; break;   // 跳出去了 → 这就是跳回
      }
    }
    p += (size_t)len;
  }
  if (!jumpBackFound) {
    r.note = "VM区内向前512字节未找到跳回指令";
    return r;
  }
  r.restoreSite = J;      // 就算后面反推失败，跳回指令位置也有价值
  r.resumeAddr = T;

  // 2) 从跳回点 T 往回找 HOOK 入口：E=T-d 处的 jmp/call 恰好跳进本 VM 区。
  //    候选可能有多个（字节碰巧长得像 E9），逐个用 FindRestoreBytes 校验。
  //    注意：跳回点可能贴着页/区头部（回看窗口按实际可读范围收缩，最多 32）。
  MEMORY_BASIC_INFORMATION mbiT{};
  if (!::VirtualQueryEx(h, (LPCVOID)T, &mbiT, sizeof(mbiT))) {
    r.note = "找到跳回点，但无法查询其所在页";
    return r;
  }
  const ptruint regionStart = (ptruint)mbiT.BaseAddress;
  const size_t maxBack =
      (size_t)std::min<ptruint>((ptruint)32, T - regionStart);
  if (maxBack < 2) { r.note = "找到跳回点但太靠前，无法反推入口"; return r; }
  std::vector<ubyte> back(maxBack);
  if (proc.ReadPartial(T - maxBack, back.data(), maxBack) != maxBack) {
    r.note = "找到跳回点，但其前方字节不可读";
    return r;
  }
  RestoreResult best;
  bool haveBest = false;

  // 关键性能：跳回点 T 对所有候选长度 d 都是同一个，
  // 所以整段内存**只扫一次**，之后每个 d 只是"取前 d 字节再验边界"的廉价操作。
  // （改造前每个 d 都重扫 128MB，31 个候选要跑近 30 秒。）
  std::vector<JumpHit> vmHits;
  ptruint vmScanned = 0;
  size_t vmRegions = 0, vmBytes = 0;
  bool vmHint = false;
  ScanForResume(proc, T, 128ull << 20, addr, &vmHits, &vmScanned,
                &vmRegions, &vmBytes, &vmHint);
  // 跳转表只建一次，供下面所有候选长度 d 复用（否则 31 个 d 各建一次 = 各全扫一遍）
  JumpTable vmTab;
  {
    ptruint s2 = 0; size_t r2 = 0, b2 = 0; bool h2 = false;
    CollectJumpTable(proc, addr, &vmTab, &s2, &r2, &b2, &h2);
  }
  r.totalScanned = vmScanned;
  r.execRegions = vmRegions;
  r.execBytes = vmBytes;
  r.hintScanned = vmHint;

  for (int d = (int)maxBack; d >= 2; --d) {
    const size_t bi = back.size() - (size_t)d;
    const ubyte b = back[bi];
    if (b != 0xE9 && b != 0xE8 && b != 0xEB) continue;
    const int ilen = (b == 0xEB) ? 2 : 5;
    if (d < ilen) continue;
    const ptruint E = T - (ptruint)d;
    ptruint t = 0;
    if (b == 0xEB) t = E + 2 + (int8_t)back[bi + 1];
    else { int32_t rel; std::memcpy(&rel, &back[bi + 1], 4); t = E + 5 + (int64_t)rel; }
    ptruint tAlloc = 0;
    if (!AllocOf(h, t, &tAlloc) || tAlloc != myAlloc) continue;   // 必须跳进本 VM 区
    // 3) 入口/长度都有了：在已扫出的跳回点集合里，取前 d 字节并验边界
    RestoreResult rr;
    rr.addr = E;
    rr.resumeAddr = T;
    rr.hookLen = d;
    rr.totalScanned = vmScanned;
    rr.execRegions = vmRegions;
    rr.execBytes = vmBytes;
    rr.hintScanned = vmHint;
    if (!vmHits.empty()) PickBest(proc, vmHits, T, d, addr, &vmTab, &rr);
    if (!rr.found && vmHits.empty()) {
      // 本区（含 HOOK 跳去的那一页）里没有跳回 T 的指令 —— 再全内存兜一次
      RestoreResult fb = FindRestoreBytes(proc, E, T, d, addr);
      if (fb.found) rr = fb;
    }
    if (rr.found) {
      r.isHook = true;
      r.hookKind = (b == 0xE8) ? "call rel32（VM区反推）"
                  : ((b == 0xEB) ? "jmp rel8（VM区反推）" : "jmp rel32（VM区反推）");
      r.hookTarget = t;
      r.hookLen = d;
      r.totalScanned = rr.totalScanned;
      r.execRegions = rr.execRegions;
      r.execBytes = rr.execBytes;
      r.hintScanned = rr.hintScanned;
      r.found = true;
      r.origBytes = rr.origBytes;
      r.origHex = rr.origHex;
      r.origDisasm = rr.origDisasm;
      r.confidence = rr.confidence;
      r.method = "VM区跳回分析（命中在被搬进柱里的代码上，档案2的做法）";
      r.note = rr.note;
      return r;
    }
    if (!haveBest) { best = rr; haveBest = true; }
  }
  char nb[200];
  std::snprintf(nb, sizeof(nb), "找到跳回点 %s，但其前方反推不出能对齐的 HOOK 入口",
                HexAddr(T).c_str());
  r.note = nb;
  (void)haveBest; (void)best;
  return r;
}

// ---------------------------------------------------------------------------
//  AnalyzeHook
// ---------------------------------------------------------------------------
RestoreResult AnalyzeHook(ProcessMemory& proc, ptruint addr, bool scanWholeMemory) {
  (void)scanWholeMemory;   // 目前两条路径都全扫，预留参数
  RestoreResult r;
  r.addr = addr;
  if (!proc.IsOpen()) { r.note = "进程未打开"; return r; }

  ubyte buf[32] = {};
  const size_t got = proc.ReadPartial(addr, buf, sizeof(buf));
  if (!got) { r.note = "地址不可读"; return r; }
  r.readable = true;

  DisasmResult dr;
  Disassemble(buf, got, addr, &dr);
  const int dl = dr.length > 0 ? dr.length : 1;
  r.curDisasm = dr.text;
  r.curBytes.assign(buf, buf + (size_t)dl);
  r.curHex = HexSpaced(r.curBytes.data(), r.curBytes.size());

  HookInfo hi;
  if (!DecodeHook(buf, got, addr, &hi)) {
    // 档案教程的主场景：命中的指令不在模块里，而是在 VM/蹦床区
    //（被偷走的原始代码搬进去执行），自动按 2/2.txt 的方法反推还原
    MEMORY_BASIC_INFORMATION mbi{};
    const bool vmRegion =
        !ProcessMemory::FindModule(proc.CachedModules(), addr) &&
        ::VirtualQueryEx(proc.Handle(), (LPCVOID)addr, &mbi, sizeof(mbi)) &&
        (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                        PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE)) != 0;
    if (vmRegion) {
      RestoreResult vm = AnalyzeVMStub(proc, addr);
      if (vm.isHook || vm.found) return vm;
      char nb[300];
      std::snprintf(nb, sizeof(nb), "该处不是跳转/调用；%s", vm.note.c_str());
      r.note = nb;
    } else {
      r.note = "该处不是跳转/调用，判定未 HOOK";
    }
    return r;
  }
  r.isHook = true;
  r.hookKind = hi.kind;
  r.hookLen = hi.len;
  r.hookTarget = hi.target;
  if (hi.indirect) {
    // FF 25/15：目标存在 [rip+disp] 指向的 8 字节里，读出来才是真正的 VM 入口
    ptruint slot = 0;
    if (proc.Read(hi.target, &slot, sizeof(slot))) r.hookTarget = slot;
  }

  // 档案 2/2.txt：jmp 5 字节 + NOP 填充 → 真正跳回的是 A+5+nop数
  int nops = 0;
  while (nops < 8 && (size_t)(hi.len + nops) < got && buf[hi.len + nops] == 0x90) ++nops;

  const int cands[2] = {hi.len + nops, hi.len};
  for (int ci = 0; ci < 2; ++ci) {
    const int L = cands[ci];
    if (ci == 1 && cands[0] == cands[1]) continue;
    RestoreResult rr = FindRestoreBytes(proc, addr, addr + (ptruint)L, L, hi.target);
    r.totalScanned = rr.totalScanned;
    r.execRegions = rr.execRegions;
    r.execBytes = rr.execBytes;
    r.hintScanned = rr.hintScanned;
    if (rr.found) {
      r.found = true;
      r.hookLen = L;
      r.resumeAddr = addr + (ptruint)L;
      r.restoreSite = rr.restoreSite;
      r.origBytes = rr.origBytes;
      r.origHex = rr.origHex;
      r.origDisasm = rr.origDisasm;
      r.confidence = rr.confidence;
      r.chainDepth = rr.chainDepth;
      r.chainPath = rr.chainPath;
      r.method = rr.method;
      r.note = rr.note;
      if (nops > 0 && ci == 0) {
        char b[96];
        std::snprintf(b, sizeof(b), "（尾部有 %d 字节 NOP 填充，跳回点按 A+%d 计算）", nops, L);
        r.method += b;
      }
      return r;
    }
    if (ci == 0) r.note = rr.note;
  }

  r.hookLen = hi.len + nops;
  r.resumeAddr = addr + (ptruint)r.hookLen;
  if (r.note.empty())
    r.note = "已判定为 HOOK，但未找到跳回点（可能用间接跳转/跳回点不在可执行页）";
  return r;
}

// ---------------------------------------------------------------------------
//  文本化
// ---------------------------------------------------------------------------
std::string FormatRestoreLine(const RestoreResult& r) {
  std::string s = "[还原] " + HexAddr(r.addr) + "  写法: ";
  if (!r.readable) return s + "(不可读) " + r.note;
  s += r.curHex;
  s += "  ";
  s += r.curDisasm;
  if (!r.isHook) { s += "   （非 HOOK，无需还原）"; return s; }

  s += "   → 已 HOOK(" + r.hookKind + ", " + std::to_string(r.hookLen) + " 字节)";
  if (r.hookTarget) s += " 跳往 " + HexAddr(r.hookTarget);
  s += "  跳回点 " + HexAddr(r.resumeAddr);
  if (r.found) {
    s += "  还原 = " + r.origHex;
    s += r.confidence >= 2 ? "  [高]" : "  [低]";
  } else {
    s += "  还原 = 未找到(" + r.note + ")";
  }
  return s;
}

std::string FormatRestoreDetail(const RestoreResult& r) {
  std::string s;
  s += "还原分析 @ " + HexAddr(r.addr) + "\r\n";
  s += "  当前指令  : " + r.curHex + "   " + r.curDisasm + "\r\n";
  if (!r.isHook) {
    s += "  判定      : 非 HOOK（该处不是跳转/调用，原始字节就是它本身）\r\n";
    return s;
  }
  s += "  判定      : 已被 HOOK —— " + r.hookKind + "，覆盖 " +
       std::to_string(r.hookLen) + " 字节\r\n";
  if (r.hookTarget) s += "  跳往(VM)  : " + HexAddr(r.hookTarget) + "\r\n";
  s += "  跳回点    : " + HexAddr(r.resumeAddr) + "\r\n";
  if (r.found) {
    s += "  还原字节  : " + r.origHex + "\r\n";
    s += "  还原反汇编: " + r.origDisasm + "\r\n";
    s += "  还原码位置: " + HexAddr(r.restoreSite) + "（该处是跳回指令）\r\n";
    s += "  置信度    : " + std::string(r.confidence >= 2 ? "高（字节边界对齐）" : "低（原样取前置字节）") + "\r\n";
    if (!r.method.empty()) s += "  方法      : " + r.method + "\r\n";
    if (r.chainDepth > 1 && !r.chainPath.empty())
      s += "  回溯链    : " + r.chainPath + "\r\n";
    if (!r.note.empty()) s += "  备注      : " + r.note + "\r\n";
  } else {
    s += "  还原字节  : 未找到\r\n";
    s += "  原因      : " + r.note + "\r\n";
  }
  char st[192];
  std::snprintf(st, sizeof(st),
                "  扫描范围  : %llu MB / 可执行区 %llu 个 %llu MB，蹦床区已覆盖=%s\r\n",
                (unsigned long long)(r.totalScanned >> 20),
                (unsigned long long)r.execRegions,
                (unsigned long long)(r.execBytes >> 20),
                r.hintScanned ? "是" : "否");
  s += st;
  return s;
}

std::string FormatRestoreRecipe(const RestoreResult& r) {
  if (!r.isHook || !r.found) return {};   // 非 HOOK / 没找到还原字节，无从写起
  std::string s;
  s += "==== VM还原 写法 ====\r\n";
  s += "目标地址: " + HexAddr(r.addr) + "\r\n";
  s += "HOOK字节: " + r.curHex + "  (" + r.hookKind + "，" +
       std::to_string(r.hookLen) + "字节)\r\n";
  s += "原始字节: " + r.origHex + "  " + r.origDisasm + "\r\n";
  s += "手工操作: 把 " + HexAddr(r.addr) + " 起 " +
       std::to_string(r.hookLen) + " 字节改为 " + r.origHex + "\r\n";
  s += "（CE: Memory View → Ctrl+G 输入地址 → 右键 Disassemble → 逐字节改回）\r\n";
  return s;
}

// ---------------------------------------------------------------------------
//  RestoreJournal
// ---------------------------------------------------------------------------
RestoreJournal::~RestoreJournal() {
  if (fp_) { std::fclose(fp_); fp_ = nullptr; }
}

bool RestoreJournal::Open() {
  if (fp_) return true;
  wchar_t exe[MAX_PATH] = {};
  ::GetModuleFileNameW(nullptr, exe, MAX_PATH);
  std::wstring dir(exe);
  const size_t sl = dir.find_last_of(L"\\/");
  if (sl != std::wstring::npos) dir.resize(sl); else dir.clear();

  SYSTEMTIME st;
  ::GetLocalTime(&st);
  wchar_t name[128];
  std::swprintf(name, 128, L"\\还原记录_%04d%02d%02d_%02d%02d%02d.txt",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
  const std::wstring full = dir + name;
  fp_ = ::_wfopen(full.c_str(), L"ab");
  if (!fp_) return false;

  char head[256];
  std::snprintf(head, sizeof(head),
                "===== HOOK / VM 还原记录  %04d-%02d-%02d %02d:%02d:%02d =====\r\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
  std::fputs(head, fp_);
  std::fflush(fp_);

  char apath[MAX_PATH * 2] = {};
  ::WideCharToMultiByte(CP_ACP, 0, full.c_str(), -1, apath, sizeof(apath), nullptr,
                        nullptr);
  path_ = apath;
  return true;
}

void RestoreJournal::Write(const std::string& line) {
  if (!Open()) return;
  SYSTEMTIME st;
  ::GetLocalTime(&st);
  char ts[64];
  std::snprintf(ts, sizeof(ts), "[%04d-%02d-%02d %02d:%02d:%02d] ",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
  std::fputs(ts, fp_);
  std::fputs(line.c_str(), fp_);
  std::fputs("\r\n", fp_);
  std::fflush(fp_);
}

void RestoreJournal::WriteRaw(const std::string& text) {
  if (!Open()) return;
  std::fputs(text.c_str(), fp_);
  std::fflush(fp_);
}

// ===========================================================================
//  访问性质自动分类（普通访问 / 检测 / CRC校验 / VM）
// ===========================================================================
namespace {

std::string ToLowerCopy(std::string s) {
  for (char& c : s)
    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
  return s;
}

// 反汇编文本的第一个词 = 助记符（"movzx eax, byte ptr [rsi]" -> "movzx"）
std::string MnemonicOf(const std::string& disasmLower) {
  size_t b = disasmLower.find_first_not_of(" \t");
  if (b == std::string::npos) return {};
  size_t e = disasmLower.find_first_of(" \t", b);
  return disasmLower.substr(b, e == std::string::npos ? e : e - b);
}

bool HasAny(const std::string& s, std::initializer_list<const char*> keys) {
  for (const char* k : keys)
    if (s.find(k) != std::string::npos) return true;
  return false;
}

// 累加器类指令：把读进来的字节流累计成校验值 —— CRC/校验和的典型形态
bool IsAccumulator(const std::string& mn) {
  return mn == "add" || mn == "adc" || mn == "sub" || mn == "sbb" ||
         mn == "xor" || mn == "or"  || mn == "and" || mn == "ror" ||
         mn == "rol" || mn == "bswap" || mn == "neg" || mn == "not";
}

}  // namespace

AccessVerdict ClassifyAccessStatic(const std::string& disasm, bool write,
                                   bool moduleEmpty) {
  AccessVerdict v;
  const std::string d  = ToLowerCopy(disasm);
  const std::string mn = MnemonicOf(d);
  const bool memIndirect = d.find('[') != std::string::npos;
  // 逐字节/逐字读取特征（注意 "dword ptr"/"qword ptr" 里含 "word ptr" 子串，
  // 必须排除，否则 VM 区一条普通 mov 就会被误判成 CRC）
  const bool byteWord =
      d.find("byte ptr") != std::string::npos ||
      (d.find("word ptr") != std::string::npos &&
       d.find("dword ptr") == std::string::npos &&
       d.find("qword ptr") == std::string::npos &&
       d.find("oword ptr") == std::string::npos &&
       d.find("fword ptr") == std::string::npos);

  // S1-a：硬件 CRC32 指令 —— 铁证
  if (mn == "crc32") {
    v.kind = AccessKind::CRC;
    v.confidence = 3;
    v.label = "CRC校验";
    v.reason = "指令本身就是 crc32（硬件完整性校验指令）";
    return v;
  }

  // S2：RIP 在匿名可执行内存（不属于任何已加载模块）
  //     = VM 柱 / 蹦床 / 动态生成代码，即《VM还原档案》处理的那类区域
  if (moduleEmpty) {
    const bool accumStyle =
        IsAccumulator(mn) ||
        ((mn == "movzx" || mn == "movsx" || mn == "mov") && byteWord) ||
        mn.rfind("rep", 0) == 0;
    if (accumStyle) {
      v.kind = AccessKind::CRC;
      v.confidence = 2;
      v.label = "CRC(VM区)";
      v.reason = "RIP 在匿名可执行内存（VM/蹦床区）且带累加/逐字节读取特征 —— "
                 "像保护线程在扫描代码或数据";
    } else {
      v.kind = AccessKind::VM;
      v.confidence = 3;
      v.label = "VM/检测代码";
      v.reason = "RIP 不在任何已加载模块内 —— 匿名可执行内存，"
                 "通常是 VM 柱/蹦床或动态生成的检测代码";
    }
    return v;
  }

  // S1-b：模块内代码的指令特征
  if (write) {
    v.kind = AccessKind::Normal;
    v.confidence = 2;
    v.label = "普通写入";
    v.reason = "模块内代码写入该地址，符合游戏自身逻辑";
    return v;
  }
  if ((mn == "cmp" || mn == "test") && memIndirect) {
    v.kind = AccessKind::Detect;
    v.confidence = 2;
    v.label = "检测(比对)";
    v.reason = "模块内代码直接把该地址的值拿来比较 —— 典型的数值校验动作";
    return v;
  }
  if (IsAccumulator(mn) || mn.rfind("rep", 0) == 0) {
    v.kind = AccessKind::CRC;
    v.confidence = 2;
    v.label = "CRC校验";
    v.reason = "累加/串搬运类指令（" + mn + "）—— 完整性校验的常见形态";
    return v;
  }
  if ((mn == "movzx" || mn == "movsx" || mn == "mov" || mn == "lea") &&
      memIndirect) {
    v.kind = AccessKind::Normal;
    v.confidence = mn == "mov" ? 1 : 0;
    v.label = "普通访问";
    v.reason = "模块内代码以普通取数指令（" + mn + "）访问 —— 最像游戏逻辑";
    return v;
  }

  v.kind = AccessKind::Unknown;
  v.confidence = 0;
  v.label = "待定";
  v.reason = "指令特征不明显，等命中次数积累后再用轮询规律修正";
  return v;
}

AccessVerdict RefineAccessVerdict(const AccessVerdict& base,
                                  int count, double avgInterval, double jitter) {
  if (count < 3 || avgInterval <= 0.0) return base;
  // 规律轮询：间隔抖动小（<35%）且频率不低（<5s 一次）
  const bool regular  = jitter >= 0.0 && jitter < 0.35;
  const bool frequent = avgInterval < 5000.0;
  if (!regular || !frequent) return base;

  AccessVerdict v = base;
  char why[160];
  std::snprintf(why, sizeof(why),
                "（同一指令已命中 %d 次，平均间隔 %.0fms、抖动 %.0f%% —— 规律性轮询）",
                count, avgInterval, jitter * 100.0);

  if (base.kind == AccessKind::Normal || base.kind == AccessKind::Unknown) {
    // 高频规律读取即使长着"普通 mov"的脸，也多半是校验/检测线程
    v.kind = AccessKind::Detect;
    v.confidence = 1;
    v.label = "疑似轮询";
    v.reason = base.reason + " 但" + why;
  } else {
    // 已有 CRC/VM/检测判定：轮询规律是佐证，提升置信度
    if (v.confidence < 3) ++v.confidence;
    v.reason += " " + std::string(why);
  }
  return v;
}

}  // namespace ce
