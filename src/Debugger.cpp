// ============================================================================
//  Debugger.cpp —— x64 调试器核心实现
//  对应 OllyDbg 调试引擎：附加 / INT3 / 硬件断点 / 页面守卫 / 单步
// ============================================================================
#include "Debugger.h"
#include "CEUtil.h"
#include "ProcessMemory.h"

#include <psapi.h>
#include <tlhelp32.h>   // Toolhelp 枚举目标线程（附加前就存在的线程也要写 DR）
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <set>

namespace ce {

// ============================================================================
//  驱动强制附加（\\.\JfDebug）
//  流程（对应 驱动附加/forcetest.c）：
//    1) IOCTL_TEST_FORCEOPEN    内核构造 PROCESS_ALL_ACCESS 进程句柄
//    2) DbgUiConnectToDbg       建立当前【调试线程】的 TEB 调试对象
//    3) 读 ntdll 桩取 NtDebugActiveProcess 的 SSDT 服务号
//    4) IOCTL_TEST_FORCEATTACH  内核态执行 NtDebugActiveProcess(hProc, hDbg)
//  关键区别于 forcetest.c：事件必须投递到 WaitForDebugEvent 所等待的 TEB
//  调试对象，否则附加"成功"却收不到任何调试事件。
// ============================================================================
namespace {

constexpr ULONG IOCTL_JF_FORCEOPEN   = 0x222000;
constexpr ULONG IOCTL_JF_FORCEATTACH = 0x222008;

#pragma pack(push, 8)
struct JF_OBJECT_ATTRIBUTES {
  ULONG  Length;
  HANDLE RootDirectory;
  PWSTR  ObjectName;
  ULONG  Attributes;
  PVOID  SecurityDescriptor;
  PVOID  SecurityQualityOfService;
};
#pragma pack(pop)

using PFN_NtCreateDebugObject  = LONG (NTAPI*)(PHANDLE, ACCESS_MASK, JF_OBJECT_ATTRIBUTES*, ULONG);
using PFN_NtRemoveProcessDebug = LONG (NTAPI*)(HANDLE, HANDLE);
using PFN_DbgUiConnectToDbg    = LONG (NTAPI*)();
using PFN_DbgUiGetThreadDebugObject = HANDLE (NTAPI*)();

// x64 ntdll 系统调用桩: 4C 8B D1 B8 xx xx xx xx 0F 05 C3 —— 取 "mov eax, imm32"
ULONG ReadSyscallNumber(PVOID pfn) {
  const UCHAR* p = (const UCHAR*)pfn;
  for (int i = 0; i < 16; ++i)
    if (p[i] == 0xB8) return *(const ULONG*)(p + i + 1);
  return 0;
}

} // anonymous namespace

bool JfDriverLoaded() {
  HANDLE h = ::CreateFileW(L"\\\\.\\JfDebug", GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING, 0, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;
  ::CloseHandle(h);
  return true;
}

bool Debugger::TryDriverAttach(std::string* errOut) {
  auto bail = [&](const std::string& why) {
    if (errOut) *errOut = why;
    if (driverDev_)    { ::CloseHandle(driverDev_);    driverDev_ = nullptr; }
    if (driverDbgObj_) { driverDbgObj_ = nullptr; }  // TEB 对象随线程销毁，不 Close
    return false;
  };

  // 1. 打开驱动设备（驱动没加载 → 直接走常规附加路径）
  HANDLE hDev = ::CreateFileW(L"\\\\.\\JfDebug", GENERIC_READ | GENERIC_WRITE,
                              0, nullptr, OPEN_EXISTING, 0, nullptr);
  if (hDev == INVALID_HANDLE_VALUE) return bail("");
  driverDev_ = hDev;

  // 2. 内核强制打开目标进程，拿全权限句柄（绕 OpenProcess 被拒）
  HANDLE hProc = nullptr; DWORD dwRet = 0;
  if (!::DeviceIoControl(hDev, IOCTL_JF_FORCEOPEN, &pid_, sizeof(pid_),
                         &hProc, sizeof(hProc), &dwRet, nullptr) || !hProc)
    return bail("驱动 FORCEOPEN 失败, GLE=" + std::to_string(::GetLastError()));
  process_ = hProc;

  // 3. 建立【当前调试线程】的 TEB 调试对象（WaitForDebugEvent 等的就是它）
  HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
  auto pConnect = (PFN_DbgUiConnectToDbg)::GetProcAddress(ntdll, "DbgUiConnectToDbg");
  auto pGetObj  = (PFN_DbgUiGetThreadDebugObject)::GetProcAddress(ntdll, "DbgUiGetThreadDebugObject");
  auto pRemove  = (PFN_NtRemoveProcessDebug)::GetProcAddress(ntdll, "NtRemoveProcessDebug");
  if (!pConnect || !pGetObj || !pRemove)
    return bail("ntdll 缺少 DbgUi 导出");
  if (pConnect() < 0) return bail("DbgUiConnectToDbg 失败");
  driverDbgObj_ = pGetObj();
  if (!driverDbgObj_) return bail("DbgUiGetThreadDebugObject 返回空");

  // 4. 取 NtDebugActiveProcess 的 SSDT 服务号，内核态直接附加
  auto pActive = ::GetProcAddress(ntdll, "NtDebugActiveProcess");
  if (!pActive) return bail("ntdll 缺少 NtDebugActiveProcess");
  ULONGLONG in[4] = { pid_, ReadSyscallNumber(pActive),
                      (ULONGLONG)(ULONG_PTR)hProc,
                      (ULONGLONG)(ULONG_PTR)driverDbgObj_ };
  ULONGLONG out[2] = {};
  if (!::DeviceIoControl(hDev, IOCTL_JF_FORCEATTACH, in, sizeof(in),
                         out, sizeof(out), &dwRet, nullptr))
    return bail("驱动 FORCEATTACH 失败, GLE=" + std::to_string(::GetLastError()));
  LONG st = (LONG)out[0];
  if (st < 0) {
    std::string why = "内核态附加失败: 0x" + [] (LONG s) {
      char b[16]; std::snprintf(b, sizeof(b), "%08lX", (unsigned long)s); return std::string(b);
    }(st);
    if (st == (LONG)0xC00000B0) why += " (目标已被其他调试器附加)";
    if (st == (LONG)0xC0000022) why += " (ACCESS_DENIED: PPL 保护或服务号错误)";
    if (st == (LONG)0xC000000D) why += " (SSDT 服务号无效)";
    return bail(why);
  }

  driverAttach_ = true;
  return true;
}

// 调试循环跟踪开关（设环境变量 CE_DBG_TRACE=1 打开，仅用于排障）
static bool TraceOn() {
  static int v = -1;
  if (v < 0) { const char* e = ::getenv("CE_DBG_TRACE"); v = (e && *e == '1') ? 1 : 0; }
  return v != 0;
}

Debugger::Debugger() = default;

Debugger::~Debugger() {
  StopLoop();
  Detach();
}

//-----------------------------------------------------------------------------
//  附加 / 脱离
//-----------------------------------------------------------------------------
bool Debugger::Attach(DWORD pid, std::string* error) {
  if (attached_) return true;
  pid_ = pid;
  {
    // 新会话：清掉上一会话遗留的"已撤守卫页"记录
    std::lock_guard<std::mutex> g(mtx_);
    deadGuardBases_.clear();
    deadGuardSizes_.clear();
  }
  {
    std::lock_guard<std::mutex> lk(loopMtx_);
    loopStarted_ = false;
    attachOk_ = false;
    attachErr_.clear();
  }
  // 关键：DebugActiveProcess 与 WaitForDebugEvent 必须在同一线程，
  // 否则 WaitForDebugEvent 永远收不到事件（调试器形同虚设）。
  // CE 的 TDebuggerThread.Execute / x64dbg 的 DebugLoopThread 也是这么做的。
  running_ = true;
  loopThread_ = std::thread([this] { Loop(); });

  std::unique_lock<std::mutex> lk(loopMtx_);
  if (!loopCv_.wait_for(lk, std::chrono::seconds(15), [this] { return loopStarted_; })) {
    if (error) *error = "附加超时（调试循环线程未就绪）";
    running_ = false;
    lk.unlock();
    if (loopThread_.joinable()) loopThread_.join();
    return false;
  }
  if (!attachOk_) {
    if (error) *error = attachErr_.empty() ? "调试器附加失败" : attachErr_;
    running_ = false;
    lk.unlock();
    if (loopThread_.joinable()) loopThread_.join();
    return false;
  }
  return true;
}

bool Debugger::Detach() {
  if (!attached_) return true;
  StopFind();
  RemoveAllBp();

  // ------------------------------------------------------------------
  //  分离收尾：把每个线程的单步标志 TF 清掉，并清空待重新武装的守卫记录。
  //
  //  「谁访问/谁写入」在页面守卫命中的瞬间会给出错线程置 TF=1，靠一次单步
  //  越过被守卫拦住的那条访问指令，随后在单步事件里重新武装守卫。
  //  如果在单步尚未完成时就 Detach，会出现两种致命情况：
  //    (1) 线程带着 TF=1 继续运行 → CPU 抛出 STATUS_SINGLE_STEP，此时已无调试器
  //        接管 → 变成未处理异常，目标进程直接崩掉；
  //    (2) #DB 事件已排队但还没被 WaitForDebugEvent 取走 → 该线程被系统挂起，
  //        DebugActiveProcessStop 会把这次挂起的异常视为未处理，目标同样退出。
  //  这里先清 TF（阻止产生新 #DB），再让调试循环把已排队事件处理干净
  //  （见 Loop() 的收尾排水逻辑），最后才真正分离。
  // ------------------------------------------------------------------
  {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& kv : threads_) {
      if (!kv.second) continue;
      CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_CONTROL;
      if (::GetThreadContext(kv.second, &ctx)) {
        if (ctx.EFlags & 0x100u) {
          ctx.EFlags &= ~0x100u;
          ::SetThreadContext(kv.second, &ctx);
        }
      }
    }
    guardRearm_.clear();
    stepRestore_.clear();
  }

  running_ = false;                                  // 请求调试循环收尾（会先排空事件）
  if (loopThread_.joinable()) loopThread_.join();
  if (driverAttach_) {
    // 驱动强制附加：用 NtRemoveProcessDebug 分离（不能走 DebugActiveProcessStop，
    // 它内部引用的是用户态 OpenProcess 路径，对受保护进程会失败）
    auto pRemove = (LONG (NTAPI*)(HANDLE, HANDLE))
                   ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtRemoveProcessDebug");
    if (pRemove && process_ && driverDbgObj_) pRemove(process_, driverDbgObj_);
    driverAttach_ = false;
    driverDbgObj_ = nullptr;
    if (driverDev_) { ::CloseHandle(driverDev_); driverDev_ = nullptr; }
  } else {
    ::DebugActiveProcessStop(pid_);
  }
  attached_ = false;
  paused_ = false;
  if (process_) { ::CloseHandle(process_); process_ = nullptr; }
  std::lock_guard<std::mutex> lk(mtx_);
  for (auto& kv : threads_) if (kv.second) ::CloseHandle(kv.second);
  threads_.clear();
  return true;
}

HANDLE Debugger::ThreadOf(DWORD tid) {
  std::lock_guard<std::mutex> lk(mtx_);
  return ThreadOfLocked(tid);
}
HANDLE Debugger::ThreadOfLocked(DWORD tid) {
  auto it = threads_.find(tid);
  if (it != threads_.end()) return it->second;
  HANDLE h = ::OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
  threads_[tid] = h;
  return h;
}

void Debugger::RefreshModules() {
  std::lock_guard<std::mutex> lk(mtx_);
  RefreshModulesLocked();
}
void Debugger::RefreshModulesLocked() {
  modules_.clear();
  HMODULE mods[1024]; DWORD needed = 0;
  if (::EnumProcessModulesEx(process_, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
    int n = std::min<DWORD>(needed / sizeof(HMODULE), 1024);
    for (int i = 0; i < n; ++i) {
      MODULEINFO mi{};
      if (::GetModuleInformation(process_, mods[i], &mi, sizeof(mi)))
        modules_.push_back({reinterpret_cast<ptruint>(mods[i]), mi.SizeOfImage});
    }
  }
}

std::string Debugger::ModuleOf(ptruint address, ptruint* base) const {
  std::lock_guard<std::mutex> lk(mtx_);
  return ModuleOfLocked(address, base);
}
std::string Debugger::ModuleOfLocked(ptruint address, ptruint* base) const {
  for (auto& m : modules_) {
    if (address >= m.first && address < m.first + m.second) {
      if (base) *base = m.first;
      return util::FormatHex(m.first); // 简化：以模块基址表示，上层可查名
    }
  }
  if (base) *base = 0;
  return "";
}

//-----------------------------------------------------------------------------
//  断点：INT3
//-----------------------------------------------------------------------------
bool Debugger::SetInt3(ptruint address, std::string* error) {
  std::lock_guard<std::mutex> lk(mtx_);
  if (bps_.count(address)) return true;
  Breakpoint bp; bp.address = address; bp.kind = BpKind::Int3;
  SIZE_T rd = 0;
  if (!::ReadProcessMemory(process_, LPCVOID(address), &bp.originalByte, 1, &rd)) {
    if (error) *error = "读内存失败: " + ProcessMemory::Win32ErrorString(0);
    return false;
  }
  ubyte cc = 0xCC;
  SIZE_T wr = 0;
  DWORD oldProt = 0;
  ::VirtualProtectEx(process_, LPVOID(address), 1, PAGE_EXECUTE_READWRITE, &oldProt);
  if (!::WriteProcessMemory(process_, LPVOID(address), &cc, 1, &wr)) {
    if (error) *error = "写内存失败: " + ProcessMemory::Win32ErrorString(0);
    ::VirtualProtectEx(process_, LPVOID(address), 1, oldProt, &oldProt);
    return false;
  }
  ::FlushInstructionCache(process_, LPCVOID(address), 1);
  ::VirtualProtectEx(process_, LPVOID(address), 1, oldProt, &oldProt);
  bp.active = true;
  bps_[address] = bp;
  return true;
}

//-----------------------------------------------------------------------------
//  断点：硬件 DR0-3
//
//  DR7 编码（Intel SDM）：
//    Ln   = bit 2n        本地启用位
//    RWn  = bit (16+4n)   R/W：00=执行 01=写入 11=读写（x86 **没有纯读**，
//                         WinDbg 的 ba r1 落到硬件上就是 11）
//    LENn = bit (18+4n)   长度：00=1 01=2 11=4 10=8 字节（不是字节数的二进制！）
//  这几位的编码只允许出现在下面 CtxSetDr / CtxClearDr 里。
//  早期实现有两处踩坑：ApplyHwBps 用 ctx.Dr7 = 0 整体重建，把 R/W 与 LEN 一起
//  抹掉（新线程上的读/写型断点被当成"执行"断点，永不触发）；以及命中判定只认
//  HardwareExec。两者叠加的结果就是：`ba r1` 这种访问断点在 CEScanVC 里从来没
//  报过任何命中，线程自然也就无从定位。
//-----------------------------------------------------------------------------
static DWORD64 Dr7Encode(int slot, BpKind kind, int len) {
  DWORD64 bits = (1ULL << (slot * 2));                    // Ln：本地启用
  if (kind == BpKind::HardwareExec) return bits;          // 执行断点：R/W=LEN=00
  const DWORD64 rw = (kind == BpKind::HardwareWrite) ? 1ULL : 3ULL;
  const DWORD64 lenBits = (len == 2) ? 1ULL : (len == 8) ? 2ULL : (len == 4) ? 3ULL : 0ULL;
  const int sh = slot * 4 + 16;
  return bits | (rw << sh) | (lenBits << (sh + 2));
}

// 往某个 DR 槽写"地址 + 类型 + 长度"（保留其它槽的设置）
static void CtxSetDr(CONTEXT& ctx, int slot, ptruint addr, BpKind kind, int len) {
  if (slot < 0 || slot > 3) return;
  (&ctx.Dr0)[slot] = addr;
  const int sh = slot * 4 + 16;
  ctx.Dr7 &= ~(0xFULL << sh);                             // 清 RWn + LENn
  ctx.Dr7 |= Dr7Encode(slot, kind, len);
}

// 摘掉某个 DR 槽（地址清零 + 关启用位 + 清 R/W·LEN）
static void CtxClearDr(CONTEXT& ctx, int slot) {
  if (slot < 0 || slot > 3) return;
  (&ctx.Dr0)[slot] = 0;
  ctx.Dr7 &= ~(1ULL << (slot * 2));                       // 关 Ln
  ctx.Dr7 &= ~(0xFULL << (slot * 4 + 16));                // 清 RWn + LENn
}

// 按断点表整体重建某个线程的 DR0-3/DR7（要求调用者已持有 mtx_）
//   suspend=true：先挂起线程。SetThreadContext 对"正在运行"的线程可能失败，也可能
//   被目标自己随后恢复的上下文覆盖回去，所以线程在跑的时候必须先挂起（CE 写 DR 同理）。
//   无论成败都要把挂起计数还回去 —— 漏掉 ResumeThread 会把目标线程永久挂住，
//   表现就是"一改断点游戏就死"。
//   suspend=false：只用于调试循环处理"新线程创建"事件的场合（此时该线程已被系统挂起）。
static void RewriteThreadDrs(HANDLE h, const std::map<ptruint, Breakpoint>& bps, bool suspend) {
  if (!h) return;
  DWORD prev = 0;
  if (suspend) {
    prev = ::SuspendThread(h);
    if (prev == (DWORD)-1) return;            // 挂不上就别动，免得写了个半截状态
  }
  CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (::GetThreadContext(h, &ctx)) {
    for (int i = 0; i < 4; ++i) CtxClearDr(ctx, i);
    for (auto& kv : bps) {
      const Breakpoint& bp = kv.second;
      if (bp.hwSlot < 0 || bp.hwSlot > 3) continue;
      CtxSetDr(ctx, bp.hwSlot, bp.address, bp.kind, bp.len ? bp.len : 1);
    }
    ::SetThreadContext(h, &ctx);
  }
  if (suspend) ::ResumeThread(h);
}

// 收集目标的全部线程句柄（须持 mtx_）：
//   * threads_ 里缓存过句柄的线程，直接用现成句柄；
//   * 其余线程（**附加之前就已存在**、调试器从没见过 CREATE_THREAD 事件的）
//     通过 Toolhelp 枚举 TID 再现开句柄。
// 这一步对「线程定位」是决定性的：反作弊/校验线程几乎都在附加之前就起来了。
// 如果只往 threads_ 里那几个线程写 DR，断点永远等不到它，界面会一直空白，
// 而使用者只会以为是"没人在访问"。
// owned[i] 为真表示该句柄是本次新开的，调用方用完必须关。
static void CollectTargetThreads(DWORD pid, const std::map<DWORD, HANDLE>& cached,
                                 std::vector<HANDLE>* hs, std::vector<char>* owned) {
  hs->clear();
  owned->clear();
  if (!pid) return;
  std::set<DWORD> have;
  for (auto& kv : cached) {
    if (!kv.second) continue;
    hs->push_back(kv.second);
    owned->push_back(0);
    have.insert(kv.first);
  }
  HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return;
  THREADENTRY32 te{};
  te.dwSize = sizeof(te);
  if (::Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID != pid || have.count(te.th32ThreadID)) continue;
      HANDLE h = ::OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                  THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                              FALSE, te.th32ThreadID);
      if (!h) continue;
      hs->push_back(h);
      owned->push_back(1);
      have.insert(te.th32ThreadID);
    } while (::Thread32Next(snap, &te));
  }
  ::CloseHandle(snap);
}

static void CloseOwnedThreads(const std::vector<HANDLE>& hs, const std::vector<char>& owned) {
  for (size_t i = 0; i < hs.size() && i < owned.size(); ++i)
    if (owned[i] && hs[i]) ::CloseHandle(hs[i]);
}

// 把某个 DR 槽写进目标的所有线程（须持 mtx_），返回成功写入的线程数
int Debugger::WriteDrSlotAllThreads(int slot, ptruint addr, BpKind kind, int len) {
  std::vector<HANDLE> hs;
  std::vector<char> owned;
  CollectTargetThreads(pid_, threads_, &hs, &owned);
  int ok = 0;
  for (size_t i = 0; i < hs.size(); ++i) {
    HANDLE h = hs[i];
    if (!h) continue;
    const DWORD prev = ::SuspendThread(h);
    if (prev == (DWORD)-1) continue;
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (::GetThreadContext(h, &ctx)) {
      CtxSetDr(ctx, slot, addr, kind, len);
      if (::SetThreadContext(h, &ctx)) ++ok;
    }
    ::ResumeThread(h);
  }
  CloseOwnedThreads(hs, owned);
  return ok;
}

// 从目标的所有线程摘掉某个 DR 槽（须持 mtx_）
void Debugger::ClearDrSlotAllThreads(int slot) {
  std::vector<HANDLE> hs;
  std::vector<char> owned;
  CollectTargetThreads(pid_, threads_, &hs, &owned);
  for (size_t i = 0; i < hs.size(); ++i) {
    HANDLE h = hs[i];
    if (!h) continue;
    const DWORD prev = ::SuspendThread(h);
    if (prev == (DWORD)-1) continue;
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (::GetThreadContext(h, &ctx)) {
      CtxClearDr(ctx, slot);
      ::SetThreadContext(h, &ctx);
    }
    ::ResumeThread(h);
  }
  CloseOwnedThreads(hs, owned);
}

bool Debugger::SetHardware(ptruint address, BpKind kind, std::string* error,
                           int len, int* applied) {
  if (applied) *applied = 0;
  if (len != 1 && len != 2 && len != 4 && len != 8) len = 1;
  // DR 长度有对齐要求（2/4/8 字节必须按长度对齐）。不满足就退化成 1 字节，
  // 否则 DR7 上是个非法组合，断点永远不触发（WinDbg 遇到这种会直接拒绝下断）。
  if (len == 2 && (address & 1)) len = 1;
  if ((len == 4 || len == 8) && (address & 3)) len = 1;

  std::lock_guard<std::mutex> lk(mtx_);
  if (!attached_) { if (error) *error = "尚未附加到目标进程"; return false; }

  // 同一地址重复下断：先回收旧槽。否则每下一次就吃掉一个 DR 槽，
  // 连着下 4 次就报"槽位已满"——「线程定位」窗口反复调参数必然撞上。
  auto old = bps_.find(address);
  if (old != bps_.end()) {
    const int oldSlot = old->second.hwSlot;
    bps_.erase(old);
    if (oldSlot >= 0) ClearDrSlotAllThreads(oldSlot);
  }

  bool slotUsed[4] = {false, false, false, false};
  for (auto& kv : bps_) {
    const int s = kv.second.hwSlot;
    if (s >= 0 && s < 4) slotUsed[s] = true;
  }
  int slot = -1;
  for (int i = 0; i < 4; ++i) if (!slotUsed[i]) { slot = i; break; }
  if (slot < 0) {
    if (error) *error = "硬件断点已满（DR0-DR3 最多 4 个，请先停止其它定位）";
    return false;
  }

  Breakpoint bp;
  bp.address = address; bp.kind = kind; bp.len = len;
  bp.hwSlot = slot; bp.active = true;
  bps_[address] = bp;

  const int n = WriteDrSlotAllThreads(slot, address, kind, len);
  if (applied) *applied = n;
  if (error) error->clear();
  if (TraceOn())
    std::fprintf(stderr, "[dbg] SetHardware addr=%016llX kind=%d len=%d slot=%d 命中线程数=%d\n",
                 (unsigned long long)address, (int)kind, len, slot, n);
  return true;
}

void Debugger::ReapplyHardware() {
  std::lock_guard<std::mutex> lk(mtx_);
  for (auto& kv : threads_) RewriteThreadDrs(kv.second, bps_, true);
}

//-----------------------------------------------------------------------------
//  断点：页面守卫（谁访问 / 谁写入）—— CE 同款 PAGE_NOACCESS 方案
//-----------------------------------------------------------------------------
void Debugger::ArmGuard(Guard& g, bool keepOldProt) {
  DWORD old = 0;
  ::VirtualProtectEx(process_, LPVOID(g.base), g.size,
                     g.kind == BpKind::Access ? PAGE_NOACCESS : PAGE_EXECUTE_READ,
                     keepOldProt ? &g.oldProt : &old);
}

bool Debugger::SetPageGuard(ptruint address, BpKind kind, size_t rangeSize, std::string* error) {
  SYSTEM_INFO si{}; ::GetSystemInfo(&si);
  const ptruint pageSize = si.dwPageSize;
  const ptruint base = address & ~(pageSize - 1);
  const size_t  size = ((address + rangeSize + pageSize - 1) & ~(pageSize - 1)) - base;

  Guard g{}; g.base = base; g.size = size; g.kind = kind;
  g.target = address; g.reqSize = rangeSize ? rangeSize : 1;
  g.oldProt = 0;
  if (!::VirtualProtectEx(process_, LPVOID(base), size,
                          kind == BpKind::Access ? PAGE_NOACCESS : PAGE_EXECUTE_READ,
                          &g.oldProt)) {
    if (error) *error = "VirtualProtectEx 失败: " + ProcessMemory::Win32ErrorString(0);
    return false;
  }
  std::lock_guard<std::mutex> lk(mtx_);
  guards_.push_back(g);
  return true;
}

bool Debugger::RemoveBp(ptruint address) {
  std::lock_guard<std::mutex> lk(mtx_);
  auto it = bps_.find(address);
  if (it == bps_.end()) return false;
  Breakpoint bp = it->second;
  bps_.erase(it);
  if (bp.kind == BpKind::Int3 && bp.active) {
    SIZE_T wr = 0;
    ::WriteProcessMemory(process_, LPVOID(address), &bp.originalByte, 1, &wr);
    ::FlushInstructionCache(process_, LPCVOID(address), 1);
  }
  // 硬件断点：只从表里删记录是不够的 —— 目标线程的 DR7 里那个槽仍然启用着，
  // 每次访问照样产生 STATUS_SINGLE_STEP，调试循环空转、目标被反复中断。
  // 表现就是"点了停止，可目标还是卡"。必须把 DR 也一起摘掉。
  if (bp.hwSlot >= 0) ClearDrSlotAllThreads(bp.hwSlot);
  return true;
}

bool Debugger::RemoveAllBp() {
  std::lock_guard<std::mutex> lk(mtx_);
  bool hwSlotUsed[4] = {false, false, false, false};
  for (auto& kv : bps_) {
    if (kv.second.kind == BpKind::Int3 && kv.second.active) {
      SIZE_T wr = 0;
      ::WriteProcessMemory(process_, LPVOID(kv.first), &kv.second.originalByte, 1, &wr);
      ::FlushInstructionCache(process_, LPCVOID(kv.first), 1);
    }
    const int s = kv.second.hwSlot;
    if (s >= 0 && s < 4) hwSlotUsed[s] = true;
  }
  // 与 RemoveBp 同理：硬件断点必须连 DR 一起摘，否则"清除全部断点"后目标仍在被断
  for (int i = 0; i < 4; ++i) if (hwSlotUsed[i]) ClearDrSlotAllThreads(i);
  bps_.clear();
  // 注意：最后一个参数必须是 dummy，不能是 &g.oldProt —— 否则会把"原始保护"
  // 覆盖成当前的守卫态保护(PAGE_NOACCESS / PAGE_EXECUTE_READ)，
  // 之后再撤守卫就等于没撤，页永远不可访问。
  for (auto& g : guards_) {
    DWORD dummy = 0;
    ::VirtualProtectEx(process_, LPVOID(g.base), g.size, g.oldProt, &dummy);
    RememberDeadGuard(g.base, g.size);
  }
  guards_.clear();
  return true;
}

std::vector<Breakpoint> Debugger::ListBp() const {
  std::lock_guard<std::mutex> lk(mtx_);
  std::vector<Breakpoint> v;
  for (auto& kv : bps_) v.push_back(kv.second);
  return v;
}

//-----------------------------------------------------------------------------
//  执行控制
//-----------------------------------------------------------------------------
bool Debugger::Run() {
  // 恢复所有被调试线程
  std::lock_guard<std::mutex> lk(mtx_);
  for (auto& kv : threads_) ::ContinueDebugEvent(pid_, kv.first, DBG_CONTINUE);
  paused_ = false;
  return true;
}

bool Debugger::Pause() {
  // 枚举所有线程并 Suspend（近似 OllyDbg F12）
  std::lock_guard<std::mutex> lk(mtx_);
  for (auto& kv : threads_) ::SuspendThread(kv.second);
  paused_ = true;
  return true;
}

//-----------------------------------------------------------------------------
//  跟踪引擎：单步 / 步过 / 运行到返回（OllyDbg F7/F8/Ctrl+F9 完整循环）
//  核心思想：挂起除主线程外的所有线程 → 对主线程设 TF → ContinueDebugEvent
//  → 收到 STATUS_SINGLE_STEP → 检查停止条件 → 未满足则继续单步
//-----------------------------------------------------------------------------
bool Debugger::StepInto() {
  // 一次性单步：挂起其他线程，主线程设 TF
  return SingleStepThread(0, TraceMode::Into);
}

bool Debugger::StepOver() {
  return SingleStepThread(0, TraceMode::Over);
}

bool Debugger::ExecuteUntilReturn() {
  return SingleStepThread(0, TraceMode::UntilReturn);
}

// 内部：对指定线程执行一次受控单步
// mode: Into=遇到 call 就进去；Over=call 设临时断点跳过；UntilReturn=step 循环直到栈返回
bool Debugger::SingleStepThread(DWORD tid, TraceMode mode) {
  std::lock_guard<std::mutex> lk(mtx_);
  if (!attached_) return false;

  // 1) 选定步进线程（tid=0 → 取第一个线程）
  DWORD target = tid;
  if (target == 0) {
    if (threads_.empty()) return false;
    target = threads_.begin()->first;
  }
  traceTid_ = target;
  traceMode_ = mode;

  // 2) 挂起其他线程（避免它们跑飞）
  for (auto& kv : threads_) {
    if (kv.first != target && kv.second) ::SuspendThread(kv.second);
  }

  // 3) 取当前 RIP，为 Over / UntilReturn 做准备
  HANDLE h = threads_[target];
  CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_CONTROL;
  if (!::GetThreadContext(h, &ctx)) return false;
  traceStartRip_ = ctx.Rip;

  if (mode == TraceMode::Over) {
    // 读出当前指令，若是 call/jmp far 则在下一指令处下一次性 INT3，再 Run
    // 简化：直接用 TF 单步 + 跳过 call 内部（读到 call 就把 RIP 推到下条指令后单步）
    SIZE_T rd = 0; ubyte code[16] = {};
    ::ReadProcessMemory(process_, LPCVOID(ctx.Rip), code, sizeof(code), &rd);
    DisasmResult dr;
    int n = Disassemble(code, rd, ctx.Rip, &dr);
    if (dr.isCall && n > 0) {
      // 步过：在 call 之后设 one-shot INT3，然后继续运行
      ptruint next = ctx.Rip + n;
      Breakpoint bp; bp.address = next; bp.kind = BpKind::Int3; bp.oneShot = true;
      SIZE_T r2 = 0;
      ::ReadProcessMemory(process_, LPCVOID(next), &bp.originalByte, 1, &r2);
      ubyte cc = 0xCC; SIZE_T wr = 0;
      ::WriteProcessMemory(process_, LPVOID(next), &cc, 1, &wr);
      ::FlushInstructionCache(process_, LPCVOID(next), 1);
      bps_[next] = bp;
      paused_ = false;
      return true;  // 调试循环收到命中后自动继续
    }
  }
  if (mode == TraceMode::UntilReturn) {
    // 记录当前 RSP，step 循环中：若单步落在 ret 且 RSP > 记录值 → 停
    traceStartRsp_ = ctx.Rsp;
  }

  // 4) 设置 TF 并继续
  ctx.EFlags |= 0x100;
  ::SetThreadContext(h, &ctx);
  debugActive_ = true;
  paused_ = false;
  return true;
}

//-----------------------------------------------------------------------------
//  跟踪循环推进：在 STATUS_SINGLE_STEP 事件里调用
//  返回 true 表示继续单步；false 表示条件满足、停止跟踪
//-----------------------------------------------------------------------------
bool Debugger::TraceContinue(ptruint rip, ptruint rsp) {
  if (traceMode_ == TraceMode::None) return false;

  if (traceMode_ == TraceMode::UntilReturn) {
    // 读当前指令：若是 ret 且 rsp 已经越过入口 rsp → 停
    ubyte code[16] = {}; SIZE_T rd = 0;
    ::ReadProcessMemory(process_, LPCVOID(rip), code, sizeof(code), &rd);
    DisasmResult dr;
    Disassemble(code, rd, rip, &dr);
    if (dr.isRet && rsp > traceStartRsp_) {
      traceMode_ = TraceMode::None;
      return false;  // 停下（保持挂起）
    }
  }

  // 其他模式（Into / Over 的循环跟踪）：继续单步
  return true;
}

//-----------------------------------------------------------------------------
//  循环跟踪（OllyDbg Trace into / Trace over 窗口）：同步阻塞循环
//  每一步：设置 TF → ContinueDebugEvent 由 Loop() 处理 → 收到单步事件后
//  回调 traceStep_ 让上层显示；到达 maxSteps 或用户 Stop 时停止。
//  这里实现为：驱动 N 次 SingleStepThread + 等待事件完成
//-----------------------------------------------------------------------------
void Debugger::TraceStepCallback(std::function<void(ptruint rip)> cb) {
  traceStepCb_ = cb;
}

bool Debugger::TraceInto(int maxSteps) {
  for (int i = 0; i < maxSteps && attached_ && running_; ++i) {
    if (!SingleStepThread(traceTid_ ? traceTid_ : 0, TraceMode::Into)) return false;
    // 等待调试循环处理完这个单步事件
    if (!WaitTraceStep()) return false;
  }
  return true;
}

bool Debugger::TraceOver(int maxSteps) {
  for (int i = 0; i < maxSteps && attached_ && running_; ++i) {
    if (!SingleStepThread(traceTid_ ? traceTid_ : 0, TraceMode::Over)) return false;
    if (!WaitTraceStep()) return false;
  }
  return true;
}

// 等待调试循环完成一次单步（内部用条件变量）
bool Debugger::WaitTraceStep() {
  std::unique_lock<std::mutex> lk(mtx_);
  if (!traceCv_.wait_for(lk, std::chrono::milliseconds(500), [this] { return traceStepDone_; }))
    return false;  // 超时
  traceStepDone_ = false;
  return true;
}

void Debugger::NotifyTraceStep(ptruint rip) {
  std::lock_guard<std::mutex> lk(mtx_);
  NotifyTraceStepLocked(rip);
}
void Debugger::NotifyTraceStepLocked(ptruint rip) {
  traceStepDone_ = true;
  lastTraceRip_ = rip;
  traceCv_.notify_all();
  if (traceStepCb_) traceStepCb_(rip);
}

//-----------------------------------------------------------------------------
//  谁访问 / 谁写入
//-----------------------------------------------------------------------------
bool Debugger::FindWhatAccesses(ptruint address, std::string* error) {
  return SetPageGuard(address, BpKind::Access, sizeof(dword), error);
}
bool Debugger::FindWhatWrites(ptruint address, std::string* error) {
  return SetPageGuard(address, BpKind::Write, sizeof(dword), error);
}
// 记住"已经撤掉守卫"的页：这些页上可能还有在守卫期间就已排队、
// 尚未被 WaitForDebugEvent 取走的 AV，必须吞掉而不能交还目标。
void Debugger::RememberDeadGuard(ptruint base, size_t size) {
  for (size_t i = 0; i < deadGuardBases_.size(); ++i)
    if (deadGuardBases_[i] == base) { deadGuardSizes_[i] = size; return; }
  deadGuardBases_.push_back(base);
  deadGuardSizes_.push_back(size);
}

void Debugger::StopFind() {
  std::lock_guard<std::mutex> lk(mtx_);
  // 注意：这里**不能**一上来就 clear deadGuardBases_。
  // StopFind 常与 Detach 成对出现（Detach 内部还会再调一次 StopFind），
  // 若第二次把"已撤守卫页"记录清掉，那些在页还被守卫时就已排队的"迟到 AV"
  // 将无人接管，被 DBG_EXCEPTION_NOT_HANDLED 交还目标 → 目标 0xC0000005 崩溃。
  for (auto& g : guards_) {
    DWORD dummy = 0;
    ::VirtualProtectEx(process_, LPVOID(g.base), g.size, g.oldProt, &dummy);
    RememberDeadGuard(g.base, g.size);   // 迟到 AV 的兜底名单（去重，不清空）
  }
  if (guards_.empty()) return;           // 已经撤过了：幂等，别动兜底名单
  guards_.clear();
  // 关键：撤掉守卫的同时，绝不允许已经排队的单步再把它"重新武装"回来。
  // 否则页会在收尾阶段又变成不可写，而我们马上就要 Detach —— 目标必崩。
  guardRearm_.clear();
}

//-----------------------------------------------------------------------------
//  调试循环
//-----------------------------------------------------------------------------
void Debugger::StartLoop() {
  if (running_) return;
  running_ = true;
  loopThread_ = std::thread([this] { Loop(); });
}
void Debugger::StopLoop() {
  running_ = false;
  if (loopThread_.joinable()) loopThread_.join();
}

bool Debugger::GetContext(HANDLE hThread, CONTEXT* ctx) {
  ctx->ContextFlags = CONTEXT_FULL;
  return ::GetThreadContext(hThread, ctx) != 0;
}
bool Debugger::SetContext(HANDLE hThread, CONTEXT* ctx) {
  return ::SetThreadContext(hThread, ctx) != 0;
}

bool Debugger::RestoreByteAndStep(DWORD tid, ptruint ip, const Breakpoint& bp) {
  // 1) 恢复原字节
  SIZE_T wr = 0;
  ::WriteProcessMemory(process_, LPVOID(bp.address), &bp.originalByte, 1, &wr);
  ::FlushInstructionCache(process_, LPCVOID(bp.address), 1);
  // 2) 回退 RIP 到断点地址，设 TF 单步
  //    注意：本函数只被 STATUS_BREAKPOINT 分支调用，而那里已经持有 mtx_，
  //    所以这里必须用 *Locked 版本，否则会二次加锁（std::mutex 不可重入）→
  //    整条调试循环死锁，表现为「一命中断点，谁访问/谁写入就再也不出结果」。
  HANDLE h = ThreadOfLocked(tid);
  CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_CONTROL;
  if (!::GetThreadContext(h, &ctx)) return false;
  ctx.Rip = bp.address;
  ctx.EFlags |= 0x100;
  ::SetThreadContext(h, &ctx);
  // 3) 记录：单步完成后重写 0xCC
  stepRestore_[tid] = bp.address;
  return true;
}

void Debugger::ReportHit(const HitReport& r) {
  if (hitCb_) hitCb_(r);
}

bool Debugger::HandleException(DEBUG_EVENT& ev) {
  const EXCEPTION_DEBUG_INFO& edi = ev.u.Exception;
  const ptruint addr = reinterpret_cast<ptruint>(edi.ExceptionRecord.ExceptionAddress);

  switch (edi.ExceptionRecord.ExceptionCode) {
    case STATUS_BREAKPOINT: { // 0x80000003 INT3
      std::lock_guard<std::mutex> lk(mtx_);
      auto it = bps_.find(addr);
      if (it != bps_.end() && it->second.kind == BpKind::Int3) {
        HitReport r; r.address = it->second.address; r.rip = addr; r.tid = ev.dwThreadId;
        r.kind = BpKind::Int3; r.module = ModuleOfLocked(addr); 
        r.bytes.assign({0xCC});
        ReportHit(r);
        // 首次异常是系统投递的，恢复字节+回退RIP+单步
        RestoreByteAndStep(ev.dwThreadId, addr, it->second);
        return true;
      }
      // 附加成功后系统会投递一次 ntdll!DbgBreakPoint（attach 断点）。
      // 必须由调试器吞掉（DBG_CONTINUE）；若交给目标自己处理，
      // 目标会因"未处理断点异常"直接崩掉。
      if (!attachBpSeen_) {
        attachBpSeen_ = true;
        return true;
      }
      break;
    }
    case STATUS_SINGLE_STEP: { // 0x80000004 硬件断点/单步
      HANDLE h = ThreadOf(ev.dwThreadId);
      // CONTROL 给 RSP/RBP/RIP/EFLAGS，INTEGER 给 RAX..R15 —— 硬件断点命中时
      // 顺手把它们冻进 HitReport，界面才有"命中瞬间的上下文"可看
      CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL | CONTEXT_INTEGER;
      ::GetThreadContext(h, &ctx);
      // 判断 DR6 触发源
      std::lock_guard<std::mutex> lk(mtx_);
      // 单步恢复：重写 0xCC
      if (stepRestore_.count(ev.dwThreadId)) {
        ptruint bpAddr = stepRestore_[ev.dwThreadId];
        stepRestore_.erase(ev.dwThreadId);
        auto it = bps_.find(bpAddr);
        if (it != bps_.end() && it->second.kind == BpKind::Int3) {
          ubyte cc = 0xCC; SIZE_T wr = 0;
          ::WriteProcessMemory(process_, LPVOID(bpAddr), &cc, 1, &wr);
          ::FlushInstructionCache(process_, LPCVOID(bpAddr), 1);
        }
      }
      // 通知跟踪循环：这一步已完成（已在锁内，用 Locked 版本避免自死锁）
      NotifyTraceStepLocked(addr);

      // 页面守卫重新武装：谁访问/谁写入命中后撤了保护，单步越过再重新挂上
      // （CE 的 DR 断点每次命中后同样要重新配置，否则只能抓到第一次）
      {
        auto gr = guardRearm_.find(ev.dwThreadId);
        if (gr != guardRearm_.end()) {
          const ptruint gbase = gr->second;
          guardRearm_.erase(gr);
          for (auto& gg : guards_) {
            if (gg.base == gbase) { ArmGuard(gg, false); break; }
          }
        }
      }

      // ---- 硬件断点命中判定 ----
      // DR6 的 B0..B3（bit0..3）标明这次是哪个 DR 槽触发的：数据/执行断点命中都会
      // 置对应位。BS(bit14) 是 TF 单步（TraceInto / 页守卫重武装都在用）、
      // BD(bit13) 是"调试寄存器被读写"，两者都**不是**断点命中。
      // 旧实现只判 HardwareExec，而且把 BS 当命中 → 两处都错：
      //   1) ba r1 这类读/写型断点永远不上报（线程定位功能的全部价值就在这）；
      //   2) 单步跟踪时会把每条指令都误报成硬件断点命中。
      DWORD64 dr6 = ctx.Dr6;
      for (auto& kv : bps_) {
        Breakpoint& bp = kv.second;
        if (bp.hwSlot < 0 || bp.hwSlot > 3) continue;
        if (bp.kind != BpKind::HardwareExec && bp.kind != BpKind::HardwareWrite &&
            bp.kind != BpKind::HardwareRW) continue;
        if (((dr6 >> bp.hwSlot) & 1) == 0) continue;              // 触发源不是这个槽
        if ((&ctx.Dr0)[bp.hwSlot] != bp.address) continue;         // 槽里已不是本断点
        HitReport r;
        r.address = bp.address;
        r.rip = addr;
        r.tid = ev.dwThreadId;
        r.kind = bp.kind;
        r.module = ModuleOfLocked(addr, &r.moduleBase);
        r.regs[kHitRsp] = ctx.Rsp;   r.regs[kHitRbp] = ctx.Rbp;
        r.regs[kHitRax] = ctx.Rax;   r.regs[kHitRbx] = ctx.Rbx;
        r.regs[kHitRcx] = ctx.Rcx;   r.regs[kHitRdx] = ctx.Rdx;
        r.regs[kHitRsi] = ctx.Rsi;   r.regs[kHitRdi] = ctx.Rdi;
        r.regs[kHitR8]  = ctx.R8;    r.regs[kHitR9]  = ctx.R9;
        r.regs[kHitR10] = ctx.R10;   r.regs[kHitR11] = ctx.R11;
        r.regs[kHitR12] = ctx.R12;   r.regs[kHitR13] = ctx.R13;
        r.regs[kHitR14] = ctx.R14;   r.regs[kHitR15] = ctx.R15;
        ReportHit(r);
      }
      // 清 DR6（不清的话下一次单步会对同一槽重复上报）
      if (dr6) {
        ctx.Dr6 = 0;
        ::SetThreadContext(h, &ctx);
      }
      return true;
    }
    case STATUS_ACCESS_VIOLATION: { // 页面守卫（谁访问/谁写入）
      std::lock_guard<std::mutex> lk(mtx_);
      // 访问地址在 EXCEPTION_RECORD 的 ExceptionInformation[1]
      const ptruint faultAddr =
          static_cast<ptruint>(edi.ExceptionRecord.ExceptionInformation[1]);
      for (size_t i = 0; i < guards_.size(); ++i) {
        Guard& g = guards_[i];
        if (faultAddr < g.base || faultAddr >= g.base + g.size) continue;
        bool isWrite = edi.ExceptionRecord.ExceptionInformation[0] == 1;
        if (g.kind == BpKind::Write && !isWrite) continue;

        // 只报用户真正要监视的那几个字节（守卫是整页的，同页其它变量不报）
        const bool inRange = (faultAddr >= g.target && faultAddr < g.target + g.reqSize);
        if (inRange) {
          HitReport r; r.address = g.target; r.rip = addr; r.tid = ev.dwThreadId;
          // 谁访问模式下进一步区分读/写，便于界面显示
          r.kind = (g.kind == BpKind::Access && isWrite) ? BpKind::Write : g.kind;
          r.module = ModuleOfLocked(addr);
          ptruint fa = faultAddr;        // 局部可变副本：assign 需要 ubyte*
          r.bytes.assign(reinterpret_cast<ubyte*>(&fa),
                         reinterpret_cast<ubyte*>(&fa) + sizeof(ptruint));
          ReportHit(r);
        }

        // 撤掉保护 → 让出错指令执行 → 单步（TF）→ 单步事件里再重新武装
        DWORD dummy = 0;
        ::VirtualProtectEx(process_, LPVOID(g.base), g.size, g.oldProt, &dummy);
        guardRearm_[ev.dwThreadId] = g.base;
        HANDLE h = ThreadOfLocked(ev.dwThreadId);
        CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_CONTROL;
        if (::GetThreadContext(h, &ctx)) {
          ctx.EFlags |= 0x100;           // TF=1，单步越过这条访问指令
          ::SetThreadContext(h, &ctx);
        }
        return true;
      }
      // 竞态兜底：StopFind 刚撤掉守卫，但这个 AV 已在队列里。
      // 页保护已恢复，重执行该指令即可成功；若交还目标(SEH)必崩。
      // 注意：这里**不能**把命中的表项删掉 —— 收尾时可能连续到达多个"迟到 AV"
      // （两个线程同时卡在被守卫拦住的写指令上），删掉第一条后第二条就会
      // 落到下面的"交还目标"分支，目标必崩（0xC0000005）。
      for (size_t i = 0; i < deadGuardBases_.size(); ++i) {
        const ptruint base = deadGuardBases_[i];
        const size_t span = (i < deadGuardSizes_.size()) ? deadGuardSizes_[i] : (size_t)4096;
        if (faultAddr >= base && faultAddr < base + span) {
          if (TraceOn())
            std::fprintf(stderr, "[dbg] 吞掉迟到AV fault=%llX rip=%llX tid=%u\n",
                         (unsigned long long)faultAddr, (unsigned long long)addr,
                         (unsigned)ev.dwThreadId);
          return true;                  // DBG_CONTINUE：重新执行，页已可访问
        }
      }
      if (TraceOn())
        std::fprintf(stderr,
                     "[dbg] AV 交还目标 fault=%llX rip=%llX tid=%u guards=%zu dead=%zu\n",
                     (unsigned long long)faultAddr, (unsigned long long)addr,
                     (unsigned)ev.dwThreadId, guards_.size(), deadGuardBases_.size());
      break;
    }
    default:
      break;
  }
  return false;
}

void Debugger::Loop() {
  DEBUG_EVENT ev{};

  // —— 附加握手 ——
  // DebugActiveProcess 必须与 WaitForDebugEvent 在同一线程（Windows 硬性要求），
  // 否则 WaitForDebugEvent 永远超时、收不到任何调试事件。
  auto fail = [this](const std::string& why) {
    std::lock_guard<std::mutex> lk(loopMtx_);
    loopStarted_ = true;
    attachOk_ = false;
    attachErr_ = why;
    loopCv_.notify_all();
  };
  // 优先走驱动强制附加（\\.\JfDebug 未加载 / 失败则回退常规路径）
  std::string drvErr;
  if (TryDriverAttach(&drvErr)) {
    if (TraceOn()) std::fprintf(stderr, "[dbg] 驱动强制附加成功 pid=%u hProc=%p\n",
                                pid_, (void*)process_);
  } else {
    if (!drvErr.empty())
      std::fprintf(stderr, "[dbg] 驱动附加不可用，回退常规路径: %s\n", drvErr.c_str());
    if (!process_) {
      process_ = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid_);
      if (!process_) { fail("OpenProcess 失败: " + ProcessMemory::Win32ErrorString(0)); return; }
    }
    if (!::DebugActiveProcess(pid_)) {
      fail("DebugActiveProcess 失败: " + ProcessMemory::Win32ErrorString(0));
      ::CloseHandle(process_); process_ = nullptr;
      return;
    }
  }
  ::DebugSetProcessKillOnExit(FALSE);
  attached_ = true;
  attachBpSeen_ = false;
  RefreshModules();
  {
    std::lock_guard<std::mutex> lk(loopMtx_);
    loopStarted_ = true;
    attachOk_ = true;
    attachErr_.clear();
  }
  loopCv_.notify_all();

  if (TraceOn()) std::fprintf(stderr, "[dbg] 调试循环启动 running=%d attached=%d pid=%u\n",
                              (int)running_.load(), (int)attached_.load(), pid_);
  int quietRounds = 0;   // 停止排水模式：连续 8 轮(约320ms)无事件才认为真正排空
  while (attached_) {
    // running_ 为 false 时进入"收尾排水"模式：用更短的超时把已经排队的调试
    // 事件处理干净，直到一次超时都没有事件为止，再安全退出。
    // （「谁访问/谁写入」命中瞬间会给线程置 TF，可能遗留一个 #DB 单步事件；
    //   若不等它处理完就分离，目标会因未处理的单步异常而崩溃。）
    const DWORD waitMs = running_ ? 200 : 40;
    if (!::WaitForDebugEvent(&ev, waitMs)) {
      if (!running_) {
        // 已请求停止：要连续多轮超时（约320ms完全没有事件）才安全离开，
        // 否则一个"已置TF但线程还没被调度"的单步可能恰好在离开后才冒出来。
        if (++quietRounds >= 8) break;
        continue;
      }
      if (TraceOn()) {
        static int n = 0;
        if (n++ < 3) std::fprintf(stderr, "[dbg] 等待事件超时(当前无事件) err=%lu\n",
                                  (unsigned long)::GetLastError());
      }
      continue;
    }
    quietRounds = 0;   // 收到任何事件都重新计数
    if (TraceOn()) std::fprintf(stderr, "[dbg] 事件 code=%u tid=%u\n",
                                ev.dwDebugEventCode, ev.dwThreadId);
    bool handled = false;
    DWORD continueStatus = DBG_CONTINUE;
    try {

    switch (ev.dwDebugEventCode) {
      case CREATE_THREAD_DEBUG_EVENT:
        ThreadOf(ev.dwThreadId); ApplyHwBps(ev.dwThreadId);
        break;
      case EXIT_THREAD_DEBUG_EVENT: {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = threads_.find(ev.dwThreadId);
        if (it != threads_.end()) { if (it->second) ::CloseHandle(it->second); threads_.erase(it); }
        break;
      }
      case LOAD_DLL_DEBUG_EVENT:
        RefreshModules();
        if (ev.u.LoadDll.hFile) ::CloseHandle(ev.u.LoadDll.hFile);
        break;
      case UNLOAD_DLL_DEBUG_EVENT: RefreshModules(); break;
      case EXCEPTION_DEBUG_EVENT:
        handled = HandleException(ev);
        if (!handled) {
          // 未处理异常交给目标自身 SEH：使用 DBG_EXCEPTION_NOT_HANDLED
          continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        }
        if (eventCb_) eventCb_(ev);
        break;
      case EXIT_PROCESS_DEBUG_EVENT:
        attached_ = false; running_ = false;
        if (eventCb_) eventCb_(ev);
        ::ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
        return;
      default: break;
    }
    ::ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus);
    } catch (const std::exception& e) {
      // 调试循环绝不因单个事件处理异常而整体挂掉（否则目标会一直被挂起）
      std::fprintf(stderr, "[dbg] 事件处理异常: %s\n", e.what());
      ::ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
    } catch (...) {
      std::fprintf(stderr, "[dbg] 事件处理未知异常\n");
      ::ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
    }
  }
}

void Debugger::ApplyHwBps(DWORD tid) {
  HANDLE h = ThreadOf(tid);
  if (!h) return;
  std::lock_guard<std::mutex> lk(mtx_);
  // 新线程创建事件到达时该线程已被系统挂起，所以这里不需要再 SuspendThread。
  // 关键是不能像旧版那样 ctx.Dr7 = 0 再只置 Ln —— R/W 与 LEN 会被一起抹掉，
  // 读/写型断点在新线程上会退化成"执行"断点，永远不触发。
  RewriteThreadDrs(h, bps_, false);
}

} // namespace ce
