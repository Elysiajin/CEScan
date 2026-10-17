#pragma once
// ============================================================================
//  Debugger.h —— x64 调试器核心（对应 OllyDbg 调试引擎 / CE 调试器）
//  功能：附加进程 / INT3 断点 / 硬件断点(DR0-3) / 单步 / 谁访问·谁写入
// ============================================================================
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <chrono>

#include "CETypes.h"
#include "Disasm.h"

namespace ce {

// 前向声明
struct ThreadContext;

// 探测 JfDebug 驱动是否已加载（能否打开 \\.\JfDebug 设备）
bool JfDriverLoaded();

// ---------------------------------------------------------------------------
//  断点类型（对应 CE 的 bpUnderflow / OllyDbg 断点菜单）
// ---------------------------------------------------------------------------
enum class BpKind {
  None = 0,
  Int3,          // INT3 指令断点（执行）
  HardwareExec,  // 硬件执行断点 DR0-3 (R/W=00, LEN=1)
  HardwareWrite, // 硬件写入断点 (R/W=01)
  HardwareRW,    // 硬件读/写断点 (R/W=11)
  Access,        // 页面异常守卫（谁访问了这个值：PAGE_NOACCESS 方式）
  Write,         // 页面异常守卫（谁写入：PAGE_EXECUTE_READ 方式）
};

// ---------------------------------------------------------------------------
//  断点记录
// ---------------------------------------------------------------------------
struct Breakpoint {
  ptruint      address = 0;
  BpKind       kind    = BpKind::Int3;
  ubyte        originalByte = 0;      // INT3: 被覆盖的原字节
  int          hwSlot  = -1;          // 硬件断点占用的 DR 槽位 0-3
  int          len     = 1;           // 硬件断点监视长度：1/2/4/8（对应 WinDbg `ba r1/r4`）
  bool         oneShot = false;       // 命中后自动移除
  bool         active  = false;
};

// 命中瞬间抓到的寄存器（下标即 kHit*；只对硬件断点命中填充）
// 为什么必须"当场抓"：定位到线程之后第一件事就是看它在拿这个地址算什么，
// 而目标此刻早已继续执行，事后再去读寄存器已经读不到了。
enum HitRegIdx {
  kHitRsp = 0, kHitRbp, kHitRax, kHitRbx, kHitRcx, kHitRdx, kHitRsi, kHitRdi,
  kHitR8, kHitR9, kHitR10, kHitR11, kHitR12, kHitR13, kHitR14, kHitR15,
  kHitRegCount
};

// ---------------------------------------------------------------------------
//  一次断点命中的报告（"谁访问/写入" 的结果行）
// ---------------------------------------------------------------------------
struct HitReport {
  ptruint  address;      // 被访问/写入的地址（调试寄存器场景=触发地址）
  ptruint  rip;          // 触发指令的 RIP
  dword    tid;          // 触发线程
  BpKind   kind;         // 访问类型
  std::string module;    // 模块名（可能为空）
  ptruint  moduleBase;
  std::string disasm;    // 反汇编文本（由外部引擎填充）
  std::vector<ubyte> bytes; // 指令字节
  ptruint  regs[kHitRegCount] = {};  // 命中瞬间的寄存器快照（见 HitRegIdx）
};

// ---------------------------------------------------------------------------
//  调试器类
// ---------------------------------------------------------------------------
class Debugger {
public:
  Debugger();
  ~Debugger();

  //--- 生命周期 -----------------------------------------------------------
  bool Attach(DWORD pid, std::string* error = nullptr);   // DebugActiveProcess
  bool Detach();                                          // DebugSetProcessKillOnExit(false)+Continue
  bool IsAttached() const { return attached_; }
  bool DriverAttachUsed() const { return driverAttach_; } // 本次附加是否走了驱动(R0)
  DWORD Pid() const { return pid_; }
  void SetEventCallback(std::function<void(const DEBUG_EVENT&)> cb) { eventCb_ = std::move(cb); }
  void SetHitCallback(std::function<void(const HitReport&)> cb) { hitCb_ = std::move(cb); }

  //--- 断点管理 -----------------------------------------------------------
  bool SetInt3(ptruint address, std::string* error = nullptr);           // 执行断点
  // 硬件断点（DR0-DR3，最多 4 个）
  //   len     监视长度 1/2/4/8（执行断点忽略；地址不满足对齐时自动退化为 1）
  //   applied 出参：DR 实际写入成功的目标线程数（未挂起写入可能失败，用于界面提示）
  bool SetHardware(ptruint address, BpKind kind, std::string* error = nullptr,
                   int len = 1, int* applied = nullptr);
  // 把全部硬件断点重新写进某个线程的 DR（新线程创建时由调试循环调用）
  void ReapplyHardware();
  bool SetPageGuard(ptruint address, BpKind kind, size_t rangeSize, std::string* error = nullptr);
  bool RemoveBp(ptruint address);
  bool RemoveAllBp();
  std::vector<Breakpoint> ListBp() const;

  //--- 执行控制（OllyDbg 调试菜单对应项）-----------------------------------
  bool Run();               // F9 继续运行
  bool Pause();             // F12 暂停（对主线程注入 break）
  bool StepInto();          // F7 单步进入 (TF=1)
  bool StepOver();          // F8 单步跳过（call 处设一次性 INT3）
  bool ExecuteUntilReturn(); // Ctrl+F9 执行到返回（step 循环）
  // 循环跟踪：TrueTrace 模式（上层驱动 N 次单步）
  bool TraceInto(int maxSteps);   // 连续步入 maxSteps 次
  bool TraceOver(int maxSteps);   // 连续步过 maxSteps 次

private:
  enum class TraceMode { None, Into, Over, UntilReturn };
  bool SingleStepThread(DWORD tid, TraceMode mode);
  bool TraceContinue(ptruint rip, ptruint rsp);
  TraceMode traceMode_ = TraceMode::None;
  DWORD traceTid_ = 0;
  ptruint traceStartRip_ = 0;
  ptruint traceStartRsp_ = 0;
  std::condition_variable traceCv_;
  bool traceStepDone_ = false;
  ptruint lastTraceRip_ = 0;
  std::function<void(ptruint)> traceStepCb_;
public:
  void TraceStepCallback(std::function<void(ptruint rip)> cb);
  bool WaitTraceStep();
  void NotifyTraceStep(ptruint rip);
  void NotifyTraceStepLocked(ptruint rip);   // 调用者须已持有 mtx_
private:
public:

  //--- "谁访问/谁写入了这个地址" ------------------------------------------
  //  mode: true=监控到有访问即回调；返回是否成功建立监控
  bool FindWhatAccesses(ptruint address, std::string* error = nullptr);
  bool FindWhatWrites(ptruint address, std::string* error = nullptr);
  void StopFind();  // 停止监控

  //--- 线程/上下文 ---------------------------------------------------------
  static bool GetContext(HANDLE hThread, CONTEXT* ctx);
  static bool SetContext(HANDLE hThread, CONTEXT* ctx);

  //--- 调试循环（内部线程驱动；UI 线程通过回调收事件）-----------------------
  void StartLoop();
  void StopLoop();

private:
  void Loop();                                    // WaitForDebugEvent 循环
  // 驱动强制附加（\\.\JfDebug）：内核态 NtDebugActiveProcess，
  // 绕过反作弊对用户态句柄的 ObCallback 剥权。失败返回 false 走常规路径。
  // 必须在调试循环线程里调用（TEB 调试对象是线程相关的）。
  bool TryDriverAttach(std::string* errOut);
  bool HandleException(DEBUG_EVENT& ev);          // 返回是否已处理
  void ApplyHwBps(DWORD tid);                     // 把 DR0-3 应用到新线程
  // 下面两个要求调用者**已持有 mtx_**（与其它 *Locked 同理，否则自死锁）
  int  WriteDrSlotAllThreads(int slot, ptruint addr, BpKind kind, int len); // 返回成功线程数
  void ClearDrSlotAllThreads(int slot);
  bool RestoreByteAndStep(DWORD tid, ptruint ip, const Breakpoint& bp); // INT3 命中处理
  void ReportHit(const HitReport& r);
  // 注意：以下 *Locked 版本要求调用者已持有 mtx_（异常处理路径里已持锁，
  //       再调带锁版本会因 std::mutex 非递归而自死锁）
  std::string ModuleOfLocked(ptruint address, ptruint* base = nullptr) const;
  void RefreshModulesLocked();
  HANDLE ThreadOfLocked(DWORD tid);
  std::string ModuleOf(ptruint address, ptruint* base = nullptr) const;
  void RefreshModules();
  HANDLE ThreadOf(DWORD tid);                     // 查/开线程句柄

  DWORD pid_ = 0;
  HANDLE process_ = nullptr;
  // 驱动强制附加状态（driverAttach_ 为 true 时 Detach 走 NtRemoveProcessDebug）
  bool   driverAttach_ = false;
  HANDLE driverDev_    = nullptr;   // \\.\JfDebug 设备句柄
  HANDLE driverDbgObj_ = nullptr;   // 调试线程的 TEB 调试对象句柄
  std::atomic<bool> attached_{false};
  std::atomic<bool> running_{false};
  std::atomic<bool> paused_{false};
  std::thread  loopThread_;

  // 附加握手：DebugActiveProcess 必须与 WaitForDebugEvent 同线程（Windows 硬性要求），
  // 所以真正的附加动作放在调试循环线程里做，Attach() 只负责等结果
  std::mutex              loopMtx_;
  std::condition_variable loopCv_;
  bool                    loopStarted_ = false;
  bool                    attachOk_ = false;
  std::string             attachErr_;

  // 断点表（address -> bp）
  mutable std::mutex mtx_;
  std::map<ptruint, Breakpoint> bps_;
  std::map<DWORD, HANDLE> threads_;
  std::vector<std::pair<ptruint, ptruint>> modules_; // base, size

  // 页面守卫（谁访问/写入）：记录守卫页区间与原保护
  //   base/size = 页对齐后的实际保护区间；target/reqSize = 用户真正要监视的精确区间
  struct Guard {
    ptruint base; size_t size; DWORD oldProt;
    BpKind  kind; ptruint target; size_t reqSize;
  };
  std::vector<Guard> guards_;
  // 守卫"重新武装"：命中后先撤保护→单步→再上保护（CE 同样需要反复重挂，否则只能抓第一次）
  std::map<DWORD, ptruint> guardRearm_;   // tid -> 待重新武装的守卫页基址
  // 已经撤掉守卫的页（迟到 AV 的兜底名单）。
  // 只在新会话 Attach 时清空，StopFind/RemoveAllBp 只能追加，绝不能清 ——
  // 否则 Detach 里第二次 StopFind 会把名单抹掉，迟到 AV 被交还目标 → 目标必崩。
  std::vector<ptruint> deadGuardBases_;
  std::vector<size_t>  deadGuardSizes_;  // 与 deadGuardBases_ 一一对应的区域大小
  void RememberDeadGuard(ptruint base, size_t size);   // 去重追加
  void ArmGuard(Guard& g, bool keepOldProt);
  // INT3 单步恢复状态：tid -> (地址，原字节已恢复待单步重写)
  std::map<DWORD, ptruint> stepRestore_;

  std::function<void(const DEBUG_EVENT&)> eventCb_;
  std::function<void(const HitReport&)>   hitCb_;

  bool debugActive_ = false; // 当前处于单步 TF 模式
  bool attachBpSeen_ = false; // 附加后 ntdll 的首次断点异常（必须由调试器吞掉）
};

} // namespace ce
