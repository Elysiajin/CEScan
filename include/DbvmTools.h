#pragma once
// ============================================================================
//  DbvmTools.h —— DBVM 断点 + 保护（CE 侧 dbvmdebuggerinterface.pas 的 C++ 移植）
//
//  对应 CE 的两个环节：
//    · TDBVMDebugInterface 的 DBVM 级断点：SetBreakpoint 这里做成
//      WatchExecutes + kEptoDbvmBp（命中即冻结线程并把 RIP 改到 int3 自旋，
//      这就是"DBVM 下断"，目标端完全不可见）。
//    · TDBVMResumerThread：后台线程周期读 DBVM 破线程表——凡是冻结的是我们
//      CE 自己的线程（cr3 == CE 进程 cr3），自动续跑让它继续工作；冻结的是
//      目标进程线程，就冻结住（= 命中断点）并通过回调通知界面，等用户"续跑"。
//
//  DBVM 断点与普通断点的区别：不写目标任何字节（无 INT3）、不占 DR0-3、
//  不靠页守卫（页属性对目标完全正常）。命中记录落在 DBVM 里，被监视进程
//  完全感知不到 —— 这正是过检测的关键。
//
//  线程纪律：本模块内部只有 resumerThread 这一个线程接触 DBvm 通道，
//  Dbvm 自带 CRITICAL_SECTION 串行，界面侧设置/删除断点也经同一实例调用，
//  但都遵守"同一时刻单线程驱动 vmcall"即可（Dbvm 内部已串行化）。
// ============================================================================
#include <windows.h>

#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "DBVM.h"

namespace ce {

// DBVM 断点命中时上报给界面的信息（对应 CE 的 setBreakEvent → DEBUG_EVENT）
struct DbvmBpHit {
  ptruint va;         // 断点虚拟地址（监视目标）
  ptruint rip;        // 命中时被冻结线程的指令指针
  uint32_t watchId;   // 命中的监视 ID
  uint64_t cr3;       // 命中进程的 CR3（用于分辨是不是目标）
  DbvmBrokenThreadShort shortState;  // 冻结线程短状态快照
};

class DbvmTools {
 public:
  static DbvmTools& Instance();

  // --- 生命周期 -----------------------------------------------------------
  // 启动/停止破线程续跑线程。Start() 幂等；Stop() 在程序退出 / 卸载 DBVM 调用。
  void Start();
  void Stop();

  // --- DBVM 断点 ----------------------------------------------------------
  // 对目标进程的虚拟地址 va 下 DBVM 断点。需要 DBVM 在场。
  // 实现：VirtualToPhysical 换算物理地址 → WatchExecutes(pa, 1, kEptoDbvmBp)。
  // 返回监视 ID（>0 成功），失败返回 -1 并填 err。
  int SetBreakpoint(DWORD targetPid, ptruint va, std::string* err = nullptr);
  // 删除某地址的 DBVM 断点；删除=WatchDelete（停止冻结该页的执行命中）。
  bool RemoveBreakpoint(ptruint va);
  // 清掉全部 DBVM 断点（WatchDelete 逐个 + EptReset 兜底）。
  void ClearAllBreakpoints();
  // 当前已下的 DBVM 断点数量
  size_t BreakpointCount() const;

  // 把 DBVM 当前冻结的目标线程全部续跑（用户"继续运行"）。
  // CE 恢复时用"直接跑"（kDbvmContinueRun），DBVM 会把冻结的线程放回。
  int ResumeAllFrozen(bool run);

  // --- DBVM 保护（cloak + 隐藏）------------------------------------------
  // 隐藏目标内存：对应 CE 的 cloak 一族。让目标读到的是原始副本，
  // 而我们通过 ReadOriginal/WriteOriginal 操作真实内容 —— 改动不被目标自检发现。
  // va 需为有效虚拟地址；内部换算物理页再 CloakActivate。
  int CloakProtect(DWORD targetPid, ptruint va, std::string* err = nullptr);
  bool CloakUnprotect(DWORD targetPid, ptruint va);
  // 隐藏 DBVM 自己的物理内存（防止反作弊扫到 hypervisor）。
  bool HideDbvmMemory();

  // --- 便捷封装（把 VA→PA 的换算收进来，GUI 不碰物理地址）----------------
  // 命中目标页即把寄存器改为指定值（如 RAX=0）。返回 0 成功。
  int  ChangeRegOnBpAt(DWORD pid, ptruint va, const DbvmChangeRegInfo& info,
                       std::string* err = nullptr);
  // 取消某地址的改寄存器断点。返回 0 成功。
  int  RemoveChangeRegAt(DWORD pid, ptruint va);
  // 命中跟踪：对目标页下 EBV(execute-before-view) 命中跟踪。返回 0 成功。
  int  TraceOnBpAt(DWORD pid, ptruint va, uint32_t count, uint32_t options,
                   std::string* err = nullptr);
  // 停止命中跟踪。返回 0 成功。
  int  TraceOnBpStop();
  // 取回命中跟踪日志。返回 0 成功，missed 给出丢包数。
  int  TraceOnBpReadLog(std::vector<DbvmPageEvent>* out, uint32_t* missed = nullptr);
  // 读取隐藏态（cloak）下的真实副本。size 为要读的字节数，返回实际读到的字节数。
  size_t ReadOriginalAt(DWORD pid, ptruint va, void* dst, size_t size,
                        std::string* err = nullptr);
  // 写入隐藏态（cloak）下的真实副本。返回实际写入的字节数。
  size_t WriteOriginalAt(DWORD pid, ptruint va, const void* src, size_t size,
                         std::string* err = nullptr);
  // 直接物理读目标进程 va 所在地址（绕过页保护/反读）。
  size_t PhysicalReadAt(DWORD pid, ptruint va, void* dst, size_t size,
                        std::string* err = nullptr);
  // 直接物理写目标进程 va 所在地址。
  size_t PhysicalWriteAt(DWORD pid, ptruint va, const void* src, size_t size,
                         std::string* err = nullptr);

  // 界面回调：DBVM 断点命中（目标线程被冻结）时触发。
  void SetHitCallback(std::function<void(const DbvmBpHit&)> cb) { hitCb_ = std::move(cb); }

  bool Running() const { return running_.load(); }

 private:
  DbvmTools() = default;
  ~DbvmTools();
  DbvmTools(const DbvmTools&) = delete;
  DbvmTools& operator=(const DbvmTools&) = delete;

  void ResumerLoop();

  // 状态
  std::atomic<bool> running_{false};
  std::thread resumerThread_;

  mutable std::mutex mtx_;
  // watchid -> (va, pa)  已生效的 DBVM 断点
  std::map<int, std::pair<ptruint, ptruint>> watches_;
  // 当前已上报的冻结话情形（避免同一断点反复上报）：
  // 组合键 watchId 的 cr3/rip 首次出现时上报一次
  std::vector<std::pair<uint64_t, uint64_t>> reported_;

  std::function<void(const DbvmBpHit&)> hitCb_;
};

}  // namespace ce