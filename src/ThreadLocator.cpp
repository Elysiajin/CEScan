// ============================================================================
//  ThreadLocator.cpp —— 「线程定位」窗口实现
//  见 include/ThreadLocator.h 的说明。
//
//  界面：
//    地址: [__________]                       ← 支持 十六进制 / 模块+偏移 / 模块!符号
//    访问: [读取/写入 v] 长度: [1 字节 v]  [开始定位][停止][清空][复制]
//    <提示行：断点状态 / 已命中线程数>
//    ┌ 结果列表：线程ID | 次数 | 命中地址 | 模块+偏移 | 指令 | 访问 ┐
//    └ 更多信息：线程起始地址 / 指令字节 / 首末命中时间 / 寄存器快照 ┘
//
//  命中聚合按 (线程ID, 指令地址) 分组 —— 一个线程可能在多个检查点读同一地址，
//  分开列出来才看得出"哪个检查点是谁在读"。
// ============================================================================
#include "ThreadLocator.h"

#include "CEUtil.h"
#include "Disasm.h"

#include <commctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <uxtheme.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <map>
#include <set>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "uxtheme.lib")

namespace ce {
namespace {

namespace utl = ce::util;

const wchar_t kTlClass[] = L"CEScanThreadLocator";
const ULONG   kThreadQueryWin32StartAddress = 9;   // NtQueryInformationThread 的信息类

// 控件 ID
enum {
  IDC_TL_ADDR = 4400,
  IDC_TL_MODE,
  IDC_TL_LEN,
  IDC_TL_GO,
  IDC_TL_STOP,
  IDC_TL_CLEAR,
  IDC_TL_COPY,
  IDC_TL_LIST,
  IDC_TL_INFO,
  IDC_TL_HINT,
};

// 访问类型下拉项
enum { kModeRW = 0, kModeWrite, kModeExec };
const int kMaxRows = 4000;      // 结果行上限（挡住"高频命中刷爆列表"）

// 寄存器显示名（下标与 ce::HitRegIdx 对齐）
const wchar_t* const kRegNames[kHitRegCount] = {
    L"RSP", L"RBP", L"RAX", L"RBX", L"RCX", L"RDX", L"RSI", L"RDI",
    L"R8",  L"R9",  L"R10", L"R11", L"R12", L"R13", L"R14", L"R15"};

//---------------------------------------------------------------------------
//  状态
//---------------------------------------------------------------------------
struct TlRow {
  DWORD        tid  = 0;
  ptruint      rip  = 0;
  ptruint      insAddr = 0;   // 访问指令地址（数据断点 = RIP 往回找出来的那条）
  bool         insBack = false;  // true = 该指令是回退找出来的（RIP 本身是下一条）
  int          count = 0;
  BpKind       kind = BpKind::HardwareRW;
  ptruint      moduleBase = 0;
  std::wstring mod;        // "ntdll+0x1A124"
  std::wstring ins;        // 反汇编文本
  std::wstring bytes;      // 指令字节
  std::wstring firstSeen, lastSeen;
  ptruint      regs[kHitRegCount] = {};
  bool         hasRegs = false;
  ULONGLONG    lastUiMs = 0;   // 列表单元格刷新节流
};

TlHost    g_host;
HWND      g_wnd = nullptr;
HWND      g_hLblAddr = nullptr, g_hLblMode = nullptr, g_hLblLen = nullptr, g_hLblInfo = nullptr;
HWND      g_hAddr = nullptr, g_hMode = nullptr, g_hLen = nullptr;
HWND      g_hGo = nullptr, g_hStop = nullptr, g_hClear = nullptr, g_hCopy = nullptr;
HWND      g_hList = nullptr, g_hInfo = nullptr, g_hHint = nullptr;
HFONT     g_fUi = nullptr, g_fMono = nullptr, g_fBold = nullptr;
HBRUSH    g_brBg = nullptr, g_brEdit = nullptr;
bool      g_classReg = false;
bool      g_listDark = false;      // 列表是否按深色主题配过色

bool      g_monitoring = false;
ptruint   g_addr = 0;
BpKind    g_kind = BpKind::HardwareRW;
int       g_len  = 1;
std::wstring g_addrText;           // 本次定位的地址原文（显示用）

std::vector<TlRow> g_rows;
std::map<std::pair<DWORD, ptruint>, int> g_index;   // (tid,rip) -> 行号
std::map<DWORD, int> g_tidHits;                     // tid -> 命中次数合计
int       g_totalHits = 0;
bool      g_overflow = false;

HANDLE    g_hProc = nullptr;       // 只为 ReadProcessMemory 用（读被命中的指令字节）
DWORD     g_hProcPid = 0;

// 落盘记录（线程定位_YYYYMMDD_HHMMSS.txt，放在 exe 同目录）；实现见下方工具函数之后
FILE*        g_hitFile = nullptr;
std::wstring g_hitPath;

//---------------------------------------------------------------------------
//  字符串 / 时间小工具
//---------------------------------------------------------------------------
std::wstring W(const std::string& s) { return utl::Utf8ToWide(s); }
std::string  N(const std::wstring& s) { return utl::WideToUtf8(s); }

std::wstring TrimW(std::wstring s) {
  const wchar_t* ws = L" \t\r\n";
  const size_t b = s.find_first_not_of(ws);
  if (b == std::wstring::npos) return L"";
  const size_t e = s.find_last_not_of(ws);
  return s.substr(b, e - b + 1);
}

std::wstring GetWinText(HWND h) {
  wchar_t b[1024] = L"";
  if (h) ::GetWindowTextW(h, b, 1024);
  return b;
}

std::wstring NowStamp() {
  SYSTEMTIME st{};
  ::GetLocalTime(&st);
  wchar_t b[32];
  std::swprintf(b, 32, L"%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond,
                st.wMilliseconds);
  return b;
}

std::wstring HexAddr(ptruint v) {
  wchar_t b[32];
  std::swprintf(b, 32, L"%012llX", (unsigned long long)v);
  return b;
}

// 模块+偏移：拿不到模块就退化成纯地址（并把模块名留空）
std::wstring FmtModOff(const std::string& mod, ptruint base, ptruint addr) {
  if (mod.empty()) return HexAddr(addr);
  wchar_t b[256];
  std::swprintf(b, 256, L"%s+0x%llX", W(mod).c_str(),
                (unsigned long long)(addr - base));
  return b;
}

const wchar_t* KindLabel(BpKind k) {
  switch (k) {
    case BpKind::HardwareRW:    return L"读取/写入";
    case BpKind::HardwareWrite: return L"写入";
    case BpKind::HardwareExec:  return L"执行";
    case BpKind::Access:        return L"访问";
    case BpKind::Write:         return L"写入";
    default:                    return L"访问";
  }
}

// 硬件断点监视长度（DR7 的 LEN 位）：1 / 2 / 4 / 8 字节
const wchar_t* LenLabel(int len) {
  switch (len) {
    case 1: return L"1 字节";
    case 2: return L"2 字节";
    case 4: return L"4 字节";
    case 8: return L"8 字节";
    default: return L"?";
  }
}

// 列表里的紧凑写法（列宽有限；完整说法在提示行和「更多信息」里）
const wchar_t* KindShort(BpKind k) {
  switch (k) {
    case BpKind::HardwareRW:    return L"R/W";
    case BpKind::HardwareWrite: return L"W";
    case BpKind::HardwareExec:  return L"E";
    default:                    return L"?";
  }
}

bool IsHwKind(BpKind k) {
  return k == BpKind::HardwareExec || k == BpKind::HardwareWrite ||
         k == BpKind::HardwareRW;
}

//---------------------------------------------------------------------------
//  落盘记录（线程定位_YYYYMMDD_HHMMSS.txt，放 exe 同目录）
//  两个作用：
//    1) 定位结果要留档：哪个线程、从哪条指令、命中多少次、当时的寄存器是什么；
//    2) 自动化回归只能靠它断言 —— 跨进程读 ListView 单元格内容不可靠
//       （LVM_GETITEMTEXTW 之类带指针的消息会把 GUI 弄崩，见项目记忆）。
//---------------------------------------------------------------------------
void HitLogRaw(const std::string& utf8) {
  if (!g_hitFile) return;
  std::fwrite(utf8.data(), 1, utf8.size(), g_hitFile);
  std::fputc('\n', g_hitFile);
  std::fflush(g_hitFile);
}

void HitLog(const std::wstring& s) { HitLogRaw(N(s)); }

void HitLogClose() {
  if (!g_hitFile) return;
  HitLog(L"");
  std::fclose(g_hitFile);
  g_hitFile = nullptr;
}

void HitLogOpen(DWORD pid, const std::wstring& addrText, ptruint addr, BpKind kind,
                int len, int applied) {
  HitLogClose();
  wchar_t exe[MAX_PATH] = {};
  ::GetModuleFileNameW(nullptr, exe, MAX_PATH);
  std::wstring dir(exe);
  const size_t sl = dir.find_last_of(L"\\/");
  if (sl != std::wstring::npos) dir.resize(sl);
  SYSTEMTIME st{};
  ::GetLocalTime(&st);
  wchar_t name[160];
  std::swprintf(name, 160, L"\\线程定位_%04d%02d%02d_%02d%02d%02d.txt", st.wYear, st.wMonth,
                st.wDay, st.wHour, st.wMinute, st.wSecond);
  g_hitPath = dir + name;
  g_hitFile = ::_wfopen(g_hitPath.c_str(), L"ab");
  if (!g_hitFile) { g_hitPath.clear(); return; }
  wchar_t h[512];
  std::swprintf(h, 512, L"===== 线程定位（硬件访问断点）  %04d-%02d-%02d %02d:%02d:%02d =====",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
  HitLog(h);
  std::swprintf(h, 512, L"目标 PID     : %u", pid);
  HitLog(h);
  std::swprintf(h, 512, L"断点地址     : %012llX   原文: %s", (unsigned long long)addr,
                addrText.c_str());
  HitLog(h);
  std::swprintf(h, 512, L"访问类型     : %s   长度: %d 字节   DR 写入线程数: %d",
                KindLabel(kind), len, applied);
  HitLog(h);
  HitLog(L"说明         : 命中按 (线程ID, 指令地址) 分组；每个新分组带一行寄存器快照");
  HitLog(L"");
}

//---------------------------------------------------------------------------
//  目标进程句柄 / 模块 / 线程
//---------------------------------------------------------------------------
HANDLE TargetProc(DWORD pid) {
  if (g_hProc && g_hProcPid == pid) return g_hProc;
  if (g_hProc) { ::CloseHandle(g_hProc); g_hProc = nullptr; g_hProcPid = 0; }
  g_hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  g_hProcPid = g_hProc ? pid : 0;
  return g_hProc;
}

struct ModInfo {
  ptruint      base = 0;
  ptruint      size = 0;
  std::wstring name;      // 不含扩展名（比较用小写）
  std::wstring file;      // 完整路径
};

// 枚举目标进程模块（64 位调试器看 32 位目标也能用；取不到就返回空表）
std::vector<ModInfo> TargetModules(DWORD pid) {
  std::vector<ModInfo> out;
  HANDLE h = TargetProc(pid);
  if (!h) return out;
  HMODULE mods[1024];
  DWORD need = 0;
  if (!::EnumProcessModulesEx(h, mods, sizeof(mods), &need, LIST_MODULES_ALL)) return out;
  const size_t n = std::min<size_t>(need / sizeof(HMODULE), 1024);
  for (size_t i = 0; i < n; ++i) {
    if (!mods[i]) continue;
    ModInfo mi;
    mi.base = (ptruint)(size_t)mods[i];
    MODULEINFO info{};
    if (::GetModuleInformation(h, mods[i], &info, sizeof(info)))
      mi.size = (ptruint)info.SizeOfImage;
    wchar_t base[MAX_PATH] = L"", full[MAX_PATH] = L"";
    ::GetModuleBaseNameW(h, mods[i], base, MAX_PATH);
    ::GetModuleFileNameExW(h, mods[i], full, MAX_PATH);
    mi.name = utl::ToLower(base);
    mi.file = full;
    out.push_back(mi);
  }
  return out;
}

// 去掉扩展名，只留主名（"tp3shell.exe" → "tp3shell"）
std::wstring BareModName(const std::wstring& n) {
  const size_t dot = n.find_last_of(L'.');
  return (dot == std::wstring::npos) ? n : n.substr(0, dot);
}

// 按名字找目标进程里的模块。名字可带也可不带扩展名 —— WinDbg 的 `module+offset`
// 就是这么用的（用户截图里的 TP3Shell+0x920af7 没有扩展名，而 TP3Shell 是主 exe）。
// 旧实现不带扩展名时一律补 ".dll"，于是 **主 exe 永远引用不到**，只能写全
// "xxx.exe" 才行，跟 WinDbg 习惯不一致。
bool FindTargetModule(DWORD pid, std::wstring name, ptruint* base, ptruint* size) {
  name = utl::ToLower(name);
  const std::vector<ModInfo> mods = TargetModules(pid);
  // 1) 先精确匹配（带了扩展名就按全名算）
  for (const ModInfo& m : mods) {
    if (m.name == name) {
      if (base) *base = m.base;
      if (size) *size = m.size;
      return true;
    }
  }
  // 2) 退化为主名匹配：hwbp_target / hwbp_target.exe / hwbp_target.dll 都能命中
  const std::wstring want = BareModName(name);
  for (const ModInfo& m : mods) {
    if (BareModName(m.name) == want) {
      if (base) *base = m.base;
      if (size) *size = m.size;
      return true;
    }
  }
  return false;
}

// 找不到模块时提示里带几个候选，免得用户对着模块名猜
std::wstring ModSuggest(DWORD pid) {
  const std::vector<ModInfo> mods = TargetModules(pid);
  std::wstring s;
  for (size_t i = 0; i < mods.size() && i < 8; ++i) {
    if (i) s += L", ";
    s += mods[i].name;
  }
  if (mods.size() > 8) s += L", ...";
  return s;
}

// 线程起始地址：THREADENTRY32 里没有这个字段（tpStartAddress 是内部结构的），
// 只能拿线程句柄走 NtQueryInformationThread(ThreadQuerySetWin32StartAddress)。
// 它非常有用：能一眼看出命中的是主线程还是某个模块起的 worker
// （反作弊的校验线程通常就以自身模块内的地址为起点）。
bool ThreadStartAddress(DWORD pid, DWORD tid, ptruint* start) {
  using PfnNtQueryInformationThread = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
  static PfnNtQueryInformationThread pfn = nullptr;
  static bool tried = false;
  if (!tried) {
    tried = true;
    HMODULE nt = ::GetModuleHandleW(L"ntdll.dll");
    if (nt)
      pfn = (PfnNtQueryInformationThread)::GetProcAddress(nt, "NtQueryInformationThread");
  }
  if (!pfn) return false;

  HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return false;
  bool found = false;
  THREADENTRY32 te{};
  te.dwSize = sizeof(te);
  if (::Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID == pid && te.th32ThreadID == tid) { found = true; break; }
    } while (::Thread32Next(snap, &te));
  }
  ::CloseHandle(snap);
  if (!found) return false;

  HANDLE th = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
  if (!th) th = ::OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
  if (!th) return false;
  ptruint sa = 0;
  const LONG st = pfn(th, kThreadQueryWin32StartAddress, &sa, sizeof(sa), nullptr);
  ::CloseHandle(th);
  if (st < 0) return false;
  if (start) *start = sa;
  return true;
}

//---------------------------------------------------------------------------
//  反汇编一段目标内存（只在新行出现时做一次）
//---------------------------------------------------------------------------
bool ReadDisasm(DWORD pid, ptruint rip, std::wstring* text, std::wstring* bytes,
                int* outLen = nullptr) {
  HANDLE h = TargetProc(pid);
  if (!h) return false;
  ubyte code[16] = {};
  SIZE_T got = 0;
  // 目标地址可能贴在页尾（后面就是未映射页），整 16 字节读会整个失败。
  // 逐级缩小读取长度，能拿到几个字节就先解码几个。
  for (size_t want = sizeof(code); want >= 1; want >>= 1) {
    if (::ReadProcessMemory(h, (LPCVOID)rip, code, want, &got) && got > 0) break;
    got = 0;
  }
  if (got == 0) return false;
  DisasmResult dr;
  Disassemble(code, (size_t)got, rip, &dr);
  const int n = dr.length > 0 ? dr.length : 1;
  if (outLen) *outLen = n;
  if (text) *text = W(dr.text.empty() ? std::string("db ??") : dr.text);
  if (bytes) {
    std::wstring s;
    wchar_t b[8];
    for (int i = 0; i < n && i < 12; ++i) {
      std::swprintf(b, 8, L"%02X ", code[i]);
      s += b;
    }
    if (!s.empty() && s.back() == L' ') s.pop_back();
    *bytes = s;
  }
  return true;
}

//---------------------------------------------------------------------------
//  访问指令定位（回答"到底是从哪条指令访问的"）
//
//  硬件 **数据** 断点（读/写，ba r / ba w）触发的是"陷阱"：#DB 报告时那条访问
//  指令已经执行完，所以线程 RIP 指向的是 **访问指令的下一条**——WinDbg 里
//  ba r1 命中时显示的 RIP 也是这个值（用户截图里的 TP3Shell+0x920af7 同理）。
//
//  想知道"哪条指令读了它"，就从 RIP 逐字节往回退 1..15，各解码一条指令，谁的
//  「起点 + 长度 == RIP」谁就是访问指令。取回退距离**最大**的候选：越靠后的
//  边界越可能是真指令开头，短的容易在长指令中间撞出巧合。
//
//  硬件 **执行** 断点（ba e）不适用该回退：它是"故障"，RIP 就是断点指令本身。
//---------------------------------------------------------------------------
bool ResolveAccessInsn(DWORD pid, ptruint rip, bool isData, ptruint* insAddr,
                       std::wstring* ins, std::wstring* bytes) {
  if (!isData) {
    if (insAddr) *insAddr = rip;
    return ReadDisasm(pid, rip, ins, bytes);
  }
  for (int back = 15; back >= 1; --back) {
    const ptruint start = rip - (ptruint)back;
    std::wstring t, by;
    int len = 0;
    if (!ReadDisasm(pid, start, &t, &by, &len)) continue;
    if (len == back) {
      if (insAddr) *insAddr = start;
      if (ins) *ins = t;
      if (bytes) *bytes = by;
      return true;
    }
  }
  // 回退不出结果（跨页 / 花指令 / 取指失败）：退回按 RIP 解一条，能看总比空着强
  if (insAddr) *insAddr = rip;
  return ReadDisasm(pid, rip, ins, bytes);
}

//---------------------------------------------------------------------------
//  画刷 / 字体
//---------------------------------------------------------------------------
void EnsureBrushes() {
  if (!g_brBg)   g_brBg   = ::CreateSolidBrush(g_host.bg);
  if (!g_brEdit) g_brEdit = ::CreateSolidBrush(g_host.editBg);
}

void DestroyBrushes() {
  if (g_brBg)   { ::DeleteObject(g_brBg);   g_brBg = nullptr; }
  if (g_brEdit) { ::DeleteObject(g_brEdit); g_brEdit = nullptr; }
}

void CreateFonts() {
  g_fUi = ::CreateFontW(g_host.uiFontH, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                        DEFAULT_PITCH | FF_DONTCARE, g_host.uiFont);
  g_fMono = ::CreateFontW(g_host.monoFontH, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                          OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                          FIXED_PITCH | FF_MODERN, g_host.monoFont);
  g_fBold = ::CreateFontW(g_host.uiFontH, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
                          OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                          DEFAULT_PITCH | FF_DONTCARE, g_host.uiFont);
}

void DestroyFonts() {
  if (g_fUi)   { ::DeleteObject(g_fUi);   g_fUi = nullptr; }
  if (g_fMono) { ::DeleteObject(g_fMono); g_fMono = nullptr; }
  if (g_fBold) { ::DeleteObject(g_fBold); g_fBold = nullptr; }
}

void SetCtlFont(HWND h, HFONT f) { if (h && f) ::SendMessageW(h, WM_SETFONT, (WPARAM)f, TRUE); }

//---------------------------------------------------------------------------
//  剪贴板
//---------------------------------------------------------------------------
void CopyTextToClipboard(HWND owner, const std::wstring& text) {
  if (text.empty()) return;
  if (!::OpenClipboard(owner)) return;
  ::EmptyClipboard();
  const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
  if (HGLOBAL mem = ::GlobalAlloc(GMEM_MOVEABLE, bytes)) {
    if (void* dst = ::GlobalLock(mem)) {
      std::memcpy(dst, text.c_str(), bytes);
      ::GlobalUnlock(mem);
      ::SetClipboardData(CF_UNICODETEXT, mem);
    }
  }
  ::CloseClipboard();
}

//---------------------------------------------------------------------------
//  提示行
//---------------------------------------------------------------------------
void SetHint(const std::wstring& s) {
  if (g_hHint) ::SetWindowTextW(g_hHint, s.c_str());
}

void RefreshHint() {
  if (!g_monitoring) return;
  wchar_t b[512];
  std::swprintf(b, 512,
                L"%s @ %s（访问长度 %s）\r\n"
                L"命中线程 %zu 个 · 不同指令 %zu 条 · 总命中 %d 次%s",
                KindLabel(g_kind), g_addrText.empty() ? HexAddr(g_addr).c_str()
                                                      : g_addrText.c_str(),
                LenLabel(g_len), g_tidHits.size(), g_rows.size(), g_totalHits,
                g_overflow ? L"（已达上限，后面的命中只计数）" : L"");
  SetHint(b);
}

//---------------------------------------------------------------------------
//  结果列表
//---------------------------------------------------------------------------
void AddColumn(int i, const wchar_t* text, int w) {
  LVCOLUMNW c{};
  c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
  c.iSubItem = i;
  c.cx = w;
  c.pszText = const_cast<LPWSTR>(text);
  ::SendMessageW(g_hList, LVM_INSERTCOLUMNW, i, (LPARAM)&c);
}

void InsertRow(int row, const TlRow& r) {
  wchar_t c0[24], c1[32], c2[24], c3[512], c4[640], c5[64];
  std::swprintf(c0, 24, L"%u", r.tid);
  std::swprintf(c1, 32, L"%d", r.count);
  std::swprintf(c2, 24, L"%012llX", (unsigned long long)r.rip);
  std::swprintf(c3, 512, L"%s", r.mod.c_str());
  // 数据断点：把回退找出来的**访问指令**连地址一起显示，避免用户盯着 RIP 看下一条
  if (r.insBack)
    std::swprintf(c4, 640, L"%012llX  %s", (unsigned long long)r.insAddr, r.ins.c_str());
  else
    std::swprintf(c4, 640, L"%s", r.ins.c_str());
  std::swprintf(c5, 64, L"%s", KindShort(r.kind));

  LVITEMW it{};
  it.mask = LVIF_TEXT;
  it.iItem = row;
  it.pszText = c0;
  const int idx = (int)::SendMessageW(g_hList, LVM_INSERTITEMW, 0, (LPARAM)&it);
  LPWSTR cols[5] = {c1, c2, c3, c4, c5};
  for (int k = 0; k < 5; ++k) {
    LVITEMW s{};
    s.mask = LVIF_TEXT;
    s.iItem = idx;
    s.iSubItem = k + 1;
    s.pszText = cols[k];
    ::SendMessageW(g_hList, LVM_SETITEMW, idx, (LPARAM)&s);
  }
}

void UpdateCountCell(int row, int count) {
  wchar_t b[24];
  std::swprintf(b, 24, L"%d", count);
  LVITEMW s{};
  s.mask = LVIF_TEXT;
  s.iItem = row;
  s.iSubItem = 1;
  s.pszText = b;
  ::SendMessageW(g_hList, LVM_SETITEMW, row, (LPARAM)&s);
}

void ClearRows() {
  g_rows.clear();
  g_index.clear();
  g_tidHits.clear();
  g_totalHits = 0;
  g_overflow = false;
  if (g_hList) ::SendMessageW(g_hList, LVM_DELETEALLITEMS, 0, 0);
  if (g_hInfo) ::SetWindowTextW(g_hInfo, L"");
}

int SelectedRow() {
  if (!g_hList) return -1;
  return (int)::SendMessageW(g_hList, LVM_GETNEXTITEM, (WPARAM)-1,
                             MAKELPARAM(LVNI_SELECTED, 0));
}

// 「更多信息」面板
void ShowInfo(int row) {
  if (!g_hInfo) return;
  if (row < 0 || row >= (int)g_rows.size()) { ::SetWindowTextW(g_hInfo, L""); return; }
  const TlRow& r = g_rows[row];

  ptruint startAddr = 0;
  std::wstring startMod = L"(取不到)";
  if (g_host.dbg && ThreadStartAddress(g_host.dbg->Pid(), r.tid, &startAddr)) {
    const std::vector<ModInfo> mods = TargetModules(g_host.dbg->Pid());
    for (const ModInfo& m : mods) {
      if (m.size && startAddr >= m.base && startAddr < m.base + m.size) {
        wchar_t b[256];
        std::swprintf(b, 256, L"%s+0x%llX", m.file.empty() ? m.name.c_str() : m.file.c_str(),
                      (unsigned long long)(startAddr - m.base));
        startMod = b;
        break;
      }
    }
  } else {
    startAddr = 0;
  }

  std::wstring s;
  {
    wchar_t b[512];
    std::swprintf(b, 512, L"线程 ID   : %u\r\n", r.tid);
    s += b;
    if (startAddr) {
      std::swprintf(b, 512, L"线程起始  : %012llX  %s\r\n",
                    (unsigned long long)startAddr, startMod.c_str());
    } else {
      std::swprintf(b, 512, L"线程起始  : (无法查询)\r\n");
    }
    s += b;
    std::swprintf(b, 512, L"命中地址  : %012llX  %s\r\n", (unsigned long long)r.rip,
                  r.mod.c_str());
    s += b;
    if (r.insBack) {
      std::swprintf(b, 512, L"访问指令  : %012llX  %-24s %s\r\n",
                    (unsigned long long)r.insAddr, r.bytes.c_str(), r.ins.c_str());
      s += b;
      s += L"            （数据断点是「陷阱」：#DB 时该指令已执行完，"
           L"RIP 指向的是它的下一条）\r\n";
    } else {
      std::swprintf(b, 512, L"命中指令  : %-24s %s\r\n", r.bytes.c_str(), r.ins.c_str());
      s += b;
    }
    std::swprintf(b, 512, L"命中次数  : %d   首次 %s   最近 %s\r\n", r.count,
                  r.firstSeen.c_str(), r.lastSeen.c_str());
    s += b;
  }
  if (r.hasRegs) {
    s += L"命中时寄存器：\r\n";
    for (int i = 0; i < kHitRegCount; i += 4) {
      wchar_t b[256] = L"";
      wchar_t part[64];
      for (int k = 0; k < 4 && i + k < kHitRegCount; ++k) {
        std::swprintf(part, 64, L" %-4s=%012llX", kRegNames[i + k],
                      (unsigned long long)r.regs[i + k]);
        wcscat_s(b, 256, part);
      }
      s += b;
      s += L"\r\n";
    }
  } else {
    s += L"命中时寄存器：未采集（仅硬件断点命中会记录）\r\n";
  }
  ::SetWindowTextW(g_hInfo, s.c_str());
}

//---------------------------------------------------------------------------
//  地址解析
//---------------------------------------------------------------------------
bool ParseHex(const std::wstring& t, ptruint* out) {
  std::wstring s = TrimW(t);
  if (s.empty()) return false;
  if (s.size() > 2 && s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) s = s.substr(2);
  for (wchar_t c : s) {
    const bool ok = (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
                    (c >= L'A' && c <= L'F');
    if (!ok) return false;
  }
  *out = (ptruint)_wcstoui64(s.c_str(), nullptr, 16);
  return true;
}

// 支持三种写法：
//   77CB0124 / 0x77CB0124                 → 直接当地址
//   ntdll+0x1A124 / ntdll+1A124           → 目标进程该模块基址 + 偏移
//   ntdll!KiUserExceptionDispatcher        → 用**本进程**同名模块求出符号在模块内的
//                                           偏移，再加到目标进程该模块的基址上
//                                           （ASLR 只改基址，符号偏移是一样的）
bool ResolveAddress(const std::wstring& raw, DWORD pid, ptruint* out, std::wstring* err) {
  const std::wstring t = TrimW(raw);
  if (t.empty()) { if (err) *err = L"请输入要定位的地址"; return false; }

  const size_t bang = t.find(L'!');
  if (bang != std::wstring::npos) {
    const std::wstring mod = TrimW(t.substr(0, bang));
    const std::wstring sym = TrimW(t.substr(bang + 1));
    if (mod.empty() || sym.empty()) { if (err) *err = L"符号写法应为 模块!符号"; return false; }
    // 本进程里同名模块的符号偏移
    HMODULE hm = ::GetModuleHandleW(mod.c_str());
    if (!hm) {
      if (err) *err = L"本进程没有加载 " + mod + L"，无法解析该符号的偏移";
      return false;
    }
    std::string symA = N(sym);
    FARPROC p = ::GetProcAddress(hm, symA.c_str());
    if (!p) {
      if (err) *err = L"模块 " + mod + L" 里找不到导出符号 " + sym;
      return false;
    }
    const ptruint off = (ptruint)(size_t)p - (ptruint)(size_t)hm;
    ptruint tb = 0;
    if (!FindTargetModule(pid, mod, &tb, nullptr)) {
      if (err) *err = L"目标进程里没有找到模块 " + mod + L"\n\n该进程的模块有：\n" + ModSuggest(pid);
      return false;
    }
    *out = tb + off;
    return true;
  }

  const size_t plus = t.find(L'+');
  if (plus != std::wstring::npos && plus > 0) {
    const std::wstring mod = TrimW(t.substr(0, plus));
    const std::wstring offS = TrimW(t.substr(plus + 1));
    ptruint off = 0;
    if (!ParseHex(offS, &off)) { if (err) *err = L"偏移不是合法的十六进制：" + offS; return false; }
    ptruint tb = 0;
    if (!FindTargetModule(pid, mod, &tb, nullptr)) {
      if (err) *err = L"目标进程里没有找到模块 " + mod + L"\n\n该进程的模块有：\n" + ModSuggest(pid);
      return false;
    }
    *out = tb + off;
    return true;
  }

  ptruint a = 0;
  if (!ParseHex(t, &a)) {
    if (err) *err = L"地址写法无法识别（支持 十六进制 / 模块+偏移 / 模块!符号）";
    return false;
  }
  *out = a;
  return true;
}

//---------------------------------------------------------------------------
//  开始 / 停止定位
//---------------------------------------------------------------------------
void StopMonitor(const wchar_t* why) {
  if (!g_monitoring) return;
  g_monitoring = false;
  if (g_host.dbg) {
    // 摘断点必须连目标线程的 DR 一起清，否则每次访问照样产生单步异常、
    // 目标被反复打断（"点了停止但游戏还是卡"）。RemoveBp 里已经处理；
    // 万一表里已经没有（例如在断点窗口被删过），再整体重写一次兜底。
    if (!g_host.dbg->RemoveBp(g_addr)) g_host.dbg->ReapplyHardware();
  }
  if (g_hitFile) {
    HitLog(L"");
    HitLog(L"[" + NowStamp() + L"] ---- 已摘除硬件断点，停止定位 ----");
    HitLogClose();
  }
  if (why) SetHint(why);
  if (g_host.status) g_host.status(why ? why : L"已停止线程定位");
}

void StartMonitor() {
  if (!g_host.dbg || !g_host.dbg->IsAttached()) {
    ::MessageBoxW(g_wnd,
                  L"请先「文件 - 附加进程」选择目标进程。\n\n"
                  L"线程定位靠目标的 DR0-DR3 寄存器实现，没有调试会话就写不进去。",
                  L"线程定位", MB_OK | MB_ICONINFORMATION);
    return;
  }
  const std::wstring in = TrimW(GetWinText(g_hAddr));
  std::wstring err;
  ptruint addr = 0;
  if (!ResolveAddress(in, g_host.dbg->Pid(), &addr, &err)) {
    ::MessageBoxW(g_wnd, err.c_str(), L"线程定位", MB_OK | MB_ICONWARNING);
    return;
  }

  const int mi = (int)::SendMessageW(g_hMode, CB_GETCURSEL, 0, 0);
  const BpKind kind = (mi == kModeWrite) ? BpKind::HardwareWrite
                     : (mi == kModeExec)  ? BpKind::HardwareExec
                                          : BpKind::HardwareRW;
  const int li = (int)::SendMessageW(g_hLen, CB_GETCURSEL, 0, 0);
  const int len = (li == 1) ? 2 : (li == 2) ? 4 : (li == 3) ? 8 : 1;

  StopMonitor(nullptr);       // 同一时刻只保留一个定位（DR 槽一共只有 4 个）
  ClearRows();

  int applied = 0;
  std::string e;
  if (!g_host.dbg->SetHardware(addr, kind, &e, len, &applied)) {
    const std::wstring msg = e.empty() ? L"下硬件断点失败" : W(e);
    ::MessageBoxW(g_wnd, msg.c_str(), L"线程定位", MB_OK | MB_ICONWARNING);
    SetHint(L"下断失败：" + msg);
    return;
  }

  g_monitoring = true;
  g_addr = addr;
  g_kind = kind;
  g_len = len;
  g_addrText = in;
  HitLogOpen(g_host.dbg->Pid(), g_addrText, g_addr, g_kind, g_len, applied);
  if (g_host.log && !g_hitPath.empty())
    g_host.log("[线程定位] 记录文件: " + N(g_hitPath));
  RefreshHint();

  wchar_t title[256];
  std::swprintf(title, 256, L"线程定位 - 访问断点 @ %012llX", (unsigned long long)addr);
  ::SetWindowTextW(g_wnd, title);

  if (applied == 0) {
    // DR 没写进任何线程：目标线程句柄可能没拿到（附加刚发生/权限不足），最靠谱的
    // 办法是让调试循环在下一个事件里重写一次，这里直接给它一次机会。
    g_host.dbg->ReapplyHardware();
    SetHint(L"警告：DR 尚未写进任何线程（可能是刚附加，线程表还没建立）。\r\n"
            L"请让目标稍微动一下（切一下焦点），或点「开始定位」重试。");
  }

  char lb[256];
  std::snprintf(lb, sizeof(lb), "[线程定位] %s 断点 @ %012llX 长度 %d → DR 写入 %d 个线程",
                N(KindLabel(kind)).c_str(), (unsigned long long)addr, len, applied);
  if (g_host.log) g_host.log(lb);
  if (g_host.status) g_host.status(L"正在定位访问该地址的线程...");
}

//---------------------------------------------------------------------------
//  布局
//---------------------------------------------------------------------------
void TlLayout(int W, int H) {
  if (!g_wnd) return;
  const int m = 8, rowH = 26, btnH = 26;
  int y = m;
  ::MoveWindow(g_hLblAddr, m, y + 5, 44, 20, TRUE);
  ::MoveWindow(g_hAddr, m + 46, y, W - 2 * m - 46, rowH, TRUE);
  y += rowH + 6;

  int x = m;
  ::MoveWindow(g_hLblMode, x, y + 5, 44, 20, TRUE); x += 46;
  ::MoveWindow(g_hMode, x, y, 168, 200, TRUE);      x += 168 + 10;
  ::MoveWindow(g_hLblLen, x, y + 5, 38, 20, TRUE);  x += 40;
  ::MoveWindow(g_hLen, x, y, 84, 200, TRUE);        x += 84 + 16;
  int bw = 88;
  ::MoveWindow(g_hGo, x, y, bw, btnH, TRUE);    x += bw + 6;
  bw = 66;
  ::MoveWindow(g_hStop, x, y, bw, btnH, TRUE);  x += bw + 6;
  ::MoveWindow(g_hClear, x, y, bw, btnH, TRUE); x += bw + 6;
  bw = 88;
  ::MoveWindow(g_hCopy, x, y, bw, btnH, TRUE);
  y += rowH + 6;

  ::MoveWindow(g_hHint, m, y, W - 2 * m, 40, TRUE);
  y += 44;

  // 「更多信息」面板要放得下：5 行摘要 + 陷阱说明 + 命中次数 + 寄存器快照（16 个
  // 寄存器，每行 4 个 = 4 行）≈ 11 行，给足高度免得用户还要滚。
  const int infoH = 220;
  int listH = H - y - infoH - m - 6;
  if (listH < 60) listH = 60;
  ::MoveWindow(g_hList, m, y, W - 2 * m, listH, TRUE);
  const int y2 = y + listH + 4;
  ::MoveWindow(g_hLblInfo, m, y2, 200, 18, TRUE);
  ::MoveWindow(g_hInfo, m, y2 + 18, W - 2 * m,
               (infoH - 22) > 40 ? (infoH - 22) : 40, TRUE);

  // 窗口变宽时把多出来的宽度全给「访问指令」列 —— 它最长（带地址前缀 + 字节 +
  // 反汇编），默认宽度下常被截断，而这条恰恰是用户最需要看清的。
  if (g_hList) {
    const int fixedw = 78 + 52 + 108 + 170 + 52;   // 除「访问指令」外的列宽合计
    const int avail = (W - 2 * m) - fixedw;
    ::SendMessageW(g_hList, LVM_SETCOLUMNWIDTH, 4,
                   MAKELPARAM(avail > 300 ? avail : 300, 0));
  }
}

//---------------------------------------------------------------------------
//  窗口过程
//---------------------------------------------------------------------------
void ApplyListTheme() {
  if (!g_hList) return;
  ::SendMessageW(g_hList, LVM_SETBKCOLOR, 0, (LPARAM)g_host.listBg);
  ::SendMessageW(g_hList, LVM_SETTEXTCOLOR, 0, (LPARAM)g_host.listFg);
  ::SendMessageW(g_hList, LVM_SETTEXTBKCOLOR, 0, (LPARAM)g_host.listBg);
  ::SendMessageW(g_hList, LVM_SETEXTENDEDLISTVIEWSTYLE,
                 LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER,
                 LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
  const int dark = ((GetRValue(g_host.listBg) + GetGValue(g_host.listBg) +
                     GetBValue(g_host.listBg)) < 380) ? 1 : 0;
  g_listDark = dark != 0;
  if (g_listDark) {
    // 深色主题下给列表头也套上暗色（否则表头是系统亮色，很跳）
    ::SetWindowTheme(g_hList, L"DarkMode_Explorer", nullptr);
  }
  ::InvalidateRect(g_hList, nullptr, TRUE);
}

LRESULT CALLBACK TlProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE: {
      g_wnd = hwnd;
      EnsureBrushes();
      CreateFonts();

      auto mkText = [&](const wchar_t* text) {
        HWND h = ::CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFT,
                                   0, 0, 10, 10, hwnd, nullptr, g_host.inst, nullptr);
        SetCtlFont(h, g_fUi);
        return h;
      };
      g_hLblAddr = mkText(L"地址:");
      g_hLblMode = mkText(L"访问:");
      g_hLblLen  = mkText(L"长度:");
      g_hLblInfo = mkText(L"更多信息（选中一行查看）");
      SetCtlFont(g_hLblInfo, g_fBold);

      g_hHint = ::CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                  0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)IDC_TL_HINT,
                                  g_host.inst, nullptr);
      SetCtlFont(g_hHint, g_fUi);

      g_hAddr = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"ntdll!KiUserExceptionDispatcher",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                  0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)IDC_TL_ADDR,
                                  g_host.inst, nullptr);
      SetCtlFont(g_hAddr, g_fMono);

      g_hMode = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"COMBOBOX", L"",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL |
                                      CBS_DROPDOWNLIST,
                                  0, 0, 10, 200, hwnd, (HMENU)(INT_PTR)IDC_TL_MODE,
                                  g_host.inst, nullptr);
      SetCtlFont(g_hMode, g_fUi);
      const wchar_t* modes[] = {L"读取 / 写入（= ba r1）", L"仅写入（= ba w1）",
                                L"执行（= ba e1）"};
      for (const wchar_t* s : modes) ::SendMessageW(g_hMode, CB_ADDSTRING, 0, (LPARAM)s);
      ::SendMessageW(g_hMode, CB_SETCURSEL, kModeRW, 0);

      g_hLen = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"COMBOBOX", L"",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL |
                                     CBS_DROPDOWNLIST,
                                 0, 0, 10, 200, hwnd, (HMENU)(INT_PTR)IDC_TL_LEN,
                                 g_host.inst, nullptr);
      SetCtlFont(g_hLen, g_fUi);
      const wchar_t* lens[] = {L"1 字节", L"2 字节", L"4 字节", L"8 字节"};
      for (const wchar_t* s : lens) ::SendMessageW(g_hLen, CB_ADDSTRING, 0, (LPARAM)s);
      ::SendMessageW(g_hLen, CB_SETCURSEL, 0, 0);

      auto mkBtn = [&](int id, const wchar_t* text) {
        HWND h = ::CreateWindowExW(0, L"BUTTON", text,
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)id, g_host.inst,
                                   nullptr);
        SetCtlFont(h, g_fUi);
        return h;
      };
      g_hGo    = mkBtn(IDC_TL_GO,    L"开始定位");
      g_hStop  = mkBtn(IDC_TL_STOP,  L"停止");
      g_hClear = mkBtn(IDC_TL_CLEAR, L"清空");
      g_hCopy  = mkBtn(IDC_TL_COPY,  L"复制");

      g_hList = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT |
                                      LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                  0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)IDC_TL_LIST,
                                  g_host.inst, nullptr);
      SetCtlFont(g_hList, g_fMono);
      AddColumn(0, L"线程ID", 78);
      AddColumn(1, L"次数", 52);
      AddColumn(2, L"命中RIP", 108);
      AddColumn(3, L"RIP 模块+偏移", 170);
      AddColumn(4, L"访问指令", 300);
      AddColumn(5, L"访问", 52);
      ApplyListTheme();

      g_hInfo = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                  WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
                                      WS_VSCROLL | ES_AUTOVSCROLL,
                                  0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)IDC_TL_INFO,
                                  g_host.inst, nullptr);
      SetCtlFont(g_hInfo, g_fMono);

      RECT rc{};
      ::GetClientRect(hwnd, &rc);
      TlLayout(rc.right, rc.bottom);
      SetHint(L"未开始定位。填地址 → 选访问类型 → 「开始定位」；命中后列表里就是访问它的线程。");
      return 0;
    }

    case WM_SIZE:
      TlLayout(LOWORD(lp), HIWORD(lp));
      return 0;

    case WM_GETMINMAXINFO: {
      MINMAXINFO* mm = (MINMAXINFO*)lp;
      mm->ptMinTrackSize.x = 620;
      mm->ptMinTrackSize.y = 380;
      return 0;
    }

    case WM_ERASEBKGND: {
      RECT rc{};
      ::GetClientRect(hwnd, &rc);
      ::FillRect((HDC)wp, &rc, g_brBg ? g_brBg : (HBRUSH)(COLOR_BTNFACE + 1));
      return 1;
    }

    case WM_CTLCOLORSTATIC: {
      HDC dc = (HDC)wp;
      HWND c = (HWND)lp;
      ::SetBkMode(dc, TRANSPARENT);
      if (c == g_hHint) {
        ::SetTextColor(dc, g_monitoring ? (g_totalHits ? g_host.hot : g_host.fg)
                                        : g_host.dim);
      } else {
        ::SetTextColor(dc, g_host.fg);
      }
      if (c == g_hInfo) {   // 只读多行 EDIT 走的是 STATIC 分支
        ::SetBkMode(dc, OPAQUE);
        ::SetBkColor(dc, g_host.editBg);
        ::SetTextColor(dc, g_host.editFg);
        return (LRESULT)(g_brEdit ? g_brEdit : (HBRUSH)(COLOR_WINDOW + 1));
      }
      return (LRESULT)(g_brBg ? g_brBg : (HBRUSH)(COLOR_BTNFACE + 1));
    }

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
      HDC dc = (HDC)wp;
      ::SetBkColor(dc, g_host.editBg);
      ::SetTextColor(dc, g_host.editFg);
      return (LRESULT)(g_brEdit ? g_brEdit : (HBRUSH)(COLOR_WINDOW + 1));
    }

    case WM_COMMAND: {
      switch (LOWORD(wp)) {
        case IDC_TL_GO:    StartMonitor(); return 0;
        case IDC_TL_STOP:  StopMonitor(L"已停止定位（硬件断点已摘除）"); return 0;
        case IDC_TL_CLEAR: ClearRows(); RefreshHint(); return 0;
        case IDC_TL_COPY: {
          const int row = SelectedRow();
          if (row >= 0 && row < (int)g_rows.size()) {
            const TlRow& r = g_rows[row];
            wchar_t b[1024];
            std::swprintf(b, 1024,
                          L"线程ID=%u\t次数=%d\t命中RIP=%012llX\t%s\t访问指令=%012llX\t%s\t%s",
                          r.tid, r.count, (unsigned long long)r.rip, r.mod.c_str(),
                          (unsigned long long)r.insAddr, r.ins.c_str(), r.bytes.c_str());
            CopyTextToClipboard(hwnd, b);
          } else {
            std::wstring all = L"线程ID\t次数\t命中RIP\tRIP 模块+偏移\t访问指令\t指令字节\t访问\r\n";
            for (const TlRow& r : g_rows) {
              wchar_t b[1024];
              std::swprintf(b, 1024, L"%u\t%d\t%012llX\t%s\t%012llX  %s\t%s\t%s\r\n",
                            r.tid, r.count, (unsigned long long)r.rip, r.mod.c_str(),
                            (unsigned long long)r.insAddr, r.ins.c_str(), r.bytes.c_str(),
                            KindLabel(r.kind));
              all += b;
            }
            CopyTextToClipboard(hwnd, all);
          }
          if (g_host.status) g_host.status(L"已复制到剪贴板");
          return 0;
        }
        default: break;
      }
      break;
    }

    case WM_NOTIFY: {
      NMHDR* nh = (NMHDR*)lp;
      if (nh && nh->idFrom == IDC_TL_LIST) {
        if (nh->code == LVN_ITEMCHANGED) {
          ShowInfo(SelectedRow());
          return 0;
        }
        if (nh->code == NM_DBLCLK) {
          const int row = SelectedRow();
          if (row >= 0 && row < (int)g_rows.size()) {
            // 数据断点双击复制的是**访问指令**的地址（要跳过去看的就是它），
            // 执行断点没有回退，两者相等。
            const TlRow& r = g_rows[row];
            CopyTextToClipboard(hwnd, HexAddr(r.insAddr ? r.insAddr : r.rip));
            if (g_host.status)
              g_host.status(r.insBack ? L"已复制访问指令地址（可粘到 CPU 窗口跳转）"
                                      : L"已复制命中地址（可粘到 CPU 窗口跳转）");
          }
          return 0;
        }
      }
      break;
    }

    case WM_CLOSE:
      // 隐藏前一定要停：DR 断点挂在热点代码上，每次访问都是一次异常往返，
      // 会明显拖慢目标。留着不停才是真正的隐患。
      StopMonitor(L"窗口已隐藏，定位已停止");
      ::ShowWindow(hwnd, SW_HIDE);
      return 0;

    case WM_DESTROY:
      StopMonitor(nullptr);
      DestroyBrushes();
      g_wnd = nullptr;
      return 0;

    default: break;
  }
  return ::DefWindowProcW(hwnd, msg, wp, lp);
}

bool RegisterTlClass() {
  if (g_classReg) return true;
  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = TlProc;
  wc.hInstance = g_host.inst;
  wc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = nullptr;    // 背景由 WM_ERASEBKGND 画
  wc.lpszClassName = kTlClass;
  wc.hIcon = ::LoadIcon(nullptr, IDI_APPLICATION);
  if (!::RegisterClassExW(&wc)) {
    if (::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;
  }
  g_classReg = true;
  return true;
}

}  // namespace

//===========================================================================
//  对外接口
//===========================================================================
void TlInit(const TlHost& host) {
  g_host = host;
  EnsureBrushes();
}

bool TlIsOpen() { return g_wnd && ::IsWindow(g_wnd); }

bool TlOpen() {
  if (!g_host.frame || !g_host.inst) return false;
  if (!RegisterTlClass()) return false;
  if (!g_wnd || !::IsWindow(g_wnd)) {
    RECT fr{};
    ::GetWindowRect(g_host.frame, &fr);
    // 宽度给足：「访问指令」列要放得下"地址 + 指令字节 + 反汇编"
    int w = 900, h = 640;
    HDC dc = ::GetDC(nullptr);
    if (dc) {
      const int scrH = ::GetDeviceCaps(dc, VERTRES);
      const int scrW = ::GetDeviceCaps(dc, HORZRES);
      ::ReleaseDC(nullptr, dc);
      if (h > scrH - 120) h = scrH - 120;
      if (h < 380) h = 380;
      if (fr.left + w > scrW - 20) w = scrW - 20 - fr.left;
      if (w < 700) w = 700;
    }
    g_wnd = ::CreateWindowExW(WS_EX_TOOLWINDOW, kTlClass, L"线程定位 - 访问断点",
                              WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME |
                                  WS_MINIMIZEBOX,
                              fr.left + 56, fr.top + 84, w, h, g_host.frame, nullptr,
                              g_host.inst, nullptr);
    if (!g_wnd) return false;
  }
  ::ShowWindow(g_wnd, SW_SHOW);
  ::SetForegroundWindow(g_wnd);
  return true;
}

bool TlOnHit(const HitReport& hit) {
  if (!g_monitoring || !g_wnd || !::IsWindow(g_wnd)) return false;
  if (!IsHwKind(hit.kind)) return false;
  if (hit.address != g_addr) return false;   // 不是本次定位的地址（同会话里可能有别的硬件断点）

  ++g_totalHits;
  const std::pair<DWORD, ptruint> key(hit.tid, hit.rip);
  auto it = g_index.find(key);
  const ULONGLONG now = ::GetTickCount64();

  if (it == g_index.end()) {
    if ((int)g_rows.size() >= kMaxRows) {
      g_overflow = true;
      // 仍然累计线程命中次数，只是不再新增行
      ++g_tidHits[hit.tid];
      return true;
    }
    TlRow r;
    r.tid  = hit.tid;
    r.rip  = hit.rip;
    r.count = 1;
    r.kind = hit.kind;
    r.moduleBase = hit.moduleBase;
    r.mod = FmtModOff(hit.module, hit.moduleBase, hit.rip);
    // 访问指令只在新行出现时解析一次（高频命中下这是唯一的重活）。
    // 数据断点的 RIP 是"下一条指令"，这里往回退找真正访问内存的那条。
    const DWORD pid = g_host.dbg ? g_host.dbg->Pid() : 0;
    const bool isData = (hit.kind == BpKind::HardwareRW || hit.kind == BpKind::HardwareWrite);
    if (!hit.disasm.empty()) {
      r.ins = W(hit.disasm);
      r.insAddr = hit.rip;
    } else {
      ResolveAccessInsn(pid, hit.rip, isData, &r.insAddr, &r.ins, &r.bytes);
      r.insBack = isData && r.insAddr != hit.rip;
    }
    if (r.bytes.empty()) {
      wchar_t b[8];
      for (size_t i = 0; i < hit.bytes.size() && i < 12; ++i) {
        std::swprintf(b, 8, L"%02X ", hit.bytes[i]);
        r.bytes += b;
      }
      if (!r.bytes.empty() && r.bytes.back() == L' ') r.bytes.pop_back();
    }
    r.firstSeen = r.lastSeen = NowStamp();
    for (int i = 0; i < kHitRegCount; ++i) r.regs[i] = hit.regs[i];
    r.hasRegs = true;
    r.lastUiMs = now;

    const int row = (int)g_rows.size();
    g_rows.push_back(r);
    g_index[key] = row;
    InsertRow(row, r);
    ++g_tidHits[hit.tid];
    // 落盘：每个新分组写一行（含寄存器快照）—— 后续同一分组的命中只累加计数，
    // 不再写文件，否则高频命中会把记录文件刷爆。
    {
      wchar_t b[1024];
      // 数据断点要把"RIP"和"真正访问内存的那条指令"分两行写清楚：
      // 否则一行里印着 RIP 却跟着前一条指令的字节，读的人会以为是 RIP 处的指令。
      if (r.insBack) {
        std::swprintf(b, 1024, L"[%s] 新命中分组  TID %u  RIP %012llX  %s",
                      r.firstSeen.c_str(), r.tid, (unsigned long long)r.rip, r.mod.c_str());
        HitLog(b);
        std::swprintf(b, 1024,
                      L"            访问指令   @ %012llX  %s  %s"
                      L"   (RIP 是下一条：数据断点属陷阱语义)",
                      (unsigned long long)r.insAddr, r.bytes.c_str(), r.ins.c_str());
        HitLog(b);
      } else {
        std::swprintf(b, 1024, L"[%s] 新命中分组  TID %u  RIP %012llX  %s  %s  %s",
                      r.firstSeen.c_str(), r.tid, (unsigned long long)r.rip, r.mod.c_str(),
                      r.bytes.c_str(), r.ins.c_str());
        HitLog(b);
      }
      std::wstring regs = L"             regs:";
      for (int i = 0; i < kHitRegCount; ++i) {
        std::swprintf(b, 1024, L" %s=%012llX", kRegNames[i], (unsigned long long)r.regs[i]);
        regs += b;
        if ((i % 4) == 3) { HitLog(regs); regs.clear(); }
      }
      if (!regs.empty()) HitLog(regs);
    }
    RefreshHint();
    // 第一行自动选中 → 「更多信息」立刻有内容可看
    if (row == 0) {
      LVITEMW sel{};
      sel.mask = LVIF_STATE;
      sel.state = LVIS_SELECTED | LVIS_FOCUSED;
      sel.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
      ::SendMessageW(g_hList, LVM_SETITEMSTATE, 0, (LPARAM)&sel);
      ShowInfo(0);
    }
    return true;
  }

  TlRow& r = g_rows[it->second];
  if (r.count < 99999999) ++r.count;
  r.lastSeen = NowStamp();
  ++g_tidHits[hit.tid];
  // 列表单元格刷新节流：高频命中时别把 UI 线程淹了
  if (now - r.lastUiMs >= 150) {
    r.lastUiMs = now;
    UpdateCountCell(it->second, r.count);
    if (SelectedRow() == it->second) ShowInfo(it->second);
  }
  return true;
}

void TlStopMonitor() { StopMonitor(L"已停止定位（硬件断点已摘除）"); }

void TlShutdown() {
  StopMonitor(nullptr);
  if (g_wnd && ::IsWindow(g_wnd)) {
    ::DestroyWindow(g_wnd);
    g_wnd = nullptr;
  }
  if (g_hProc) { ::CloseHandle(g_hProc); g_hProc = nullptr; g_hProcPid = 0; }
  DestroyFonts();
  DestroyBrushes();
}

}  // namespace ce
