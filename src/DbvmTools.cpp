// ============================================================================
//  DbvmTools.cpp —— DBVM 断点 + 保护实现（见 DbvmTools.h 头注释）
//
//  关键设计（对齐 CE dbvmdebuggerinterface.pas 的 TDBVMResumerThread）：
//    · ResumerThread 轮询 dbvm_bp_getBrokenThreadListSize 拿冻结线程数；
//    · 对每个 inuse==1 且未决定续跑方式(incontinue==0) 的冻结项，看它是谁：
//        cr3 == 本 CE 进程 cr3  → 是我们自己的线程（比如 DBVM 读物理内存时
//          恰好踩着被监视页），必须自动续跑，否则 CE 自己会卡死；
//        cr3 == 目标进程 cr3     → 命中断点，冻结住等用户处理并上报界面。
//    · 轮询间隔按 CE 的退避：工作时减半，空闲翻倍封顶 1000ms。
// ============================================================================
#include "DbvmTools.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <thread>

namespace ce {

DbvmTools& DbvmTools::Instance() {
  static DbvmTools inst;
  return inst;
}

DbvmTools::~DbvmTools() { Stop(); }

void DbvmTools::Start() {
  bool expected = false;
  if (!running_.compare_exchange_strong(expected, true)) return;  // 已在跑
  resumerThread_ = std::thread([this] { ResumerLoop(); });
}

void DbvmTools::Stop() {
  running_.store(false);
  if (resumerThread_.joinable()) resumerThread_.join();
}

// ---------------------------------------------------------------------------
//  DBVM 断点
// ---------------------------------------------------------------------------
int DbvmTools::SetBreakpoint(DWORD targetPid, ptruint va, std::string* err) {
  Dbvm& dbvm = Dbvm::Instance();
  if (!dbvm.Available()) {
    if (err) *err = "DBVM 不在场，请先 加载并启动 DBVM";
    return -1;
  }

  // 已存在同地址断点：幂等，直接返回原 ID
  {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& kv : watches_)
      if (kv.second.first == va) return kv.first;
  }

  const uint64_t pa = dbvm.VirtualToPhysical(targetPid, va);
  if (pa == 0) {
    if (err) *err = "虚拟地址转物理地址失败（目标可能已退出或地址无效）";
    return -1;
  }

  // 监视目标物理页基址，命中即冻结线程（kEptoDbvmBp）
  const int id = dbvm.WatchExecutes(pa & ~0xFFFULL, 1, kEptoDbvmBp, 0x1000);
  if (id <= 0) {
    if (err) *err = "WatchExecutes 失败：" + dbvm.LastError();
    return -1;
  }

  {
    std::lock_guard<std::mutex> lk(mtx_);
    watches_[id] = {va, pa & ~0xFFFULL};
  }
  Start();  // 有断点了，确保续跑线程在工作
  return id;
}

bool DbvmTools::RemoveBreakpoint(ptruint va) {
  Dbvm& dbvm = Dbvm::Instance();
  std::lock_guard<std::mutex> lk(mtx_);
  for (auto it = watches_.begin(); it != watches_.end(); ++it) {
    if (it->second.first == va) {
      const int id = it->first;
      watches_.erase(it);
      dbvm.WatchDelete(id);
      return true;
    }
  }
  return false;
}

void DbvmTools::ClearAllBreakpoints() {
  Dbvm& dbvm = Dbvm::Instance();
  std::lock_guard<std::mutex> lk(mtx_);
  for (auto& kv : watches_) dbvm.WatchDelete(kv.first);
  watches_.clear();
  dbvm.EptReset();  // 兜底：把 DBVM 里所有监视/隐藏/断点状态复位
}

size_t DbvmTools::BreakpointCount() const {
  std::lock_guard<std::mutex> lk(mtx_);
  return watches_.size();
}

int DbvmTools::ResumeAllFrozen(bool run) {
  Dbvm& dbvm = Dbvm::Instance();
  const int n = dbvm.BrokenThreadCount();
  int resumed = 0;
  for (int i = 0; i < n; ++i) {
    DbvmBrokenThreadShort st{};
    if (!dbvm.GetBrokenThreadShort(i, &st)) continue;
    if ((st.status & 0xFF) != kDbvmBpWait) continue;   // 不是"等待处理"的冻结
    if (dbvm.ResumeBrokenThread(i, run ? kDbvmContinueRun : kDbvmContinueStep))
      ++resumed;
  }
  std::lock_guard<std::mutex> lk(mtx_);
  reported_.clear();  // 续跑后再冻结当作新一轮，重新上报
  return resumed;
}

// ---------------------------------------------------------------------------
//  DBVM 保护
// ---------------------------------------------------------------------------
int DbvmTools::CloakProtect(DWORD targetPid, ptruint va, std::string* err) {
  Dbvm& dbvm = Dbvm::Instance();
  if (!dbvm.Available()) {
    if (err) *err = "DBVM 不在场，请先 加载并启动 DBVM";
    return -1;
  }
  const uint64_t pa = dbvm.VirtualToPhysical(targetPid, va);
  if (pa == 0) {
    if (err) *err = "虚拟地址转物理地址失败";
    return -1;
  }
  return dbvm.CloakActivate(pa & ~0xFFFULL, va, 1);
}

bool DbvmTools::CloakUnprotect(DWORD targetPid, ptruint va) {
  Dbvm& dbvm = Dbvm::Instance();
  if (!dbvm.Available()) return false;
  const uint64_t pa = dbvm.VirtualToPhysical(targetPid, va);
  if (pa == 0) return false;
  return dbvm.CloakDeactivate(pa & ~0xFFFULL);
}

bool DbvmTools::HideDbvmMemory() { return Dbvm::Instance().HideDbvmPhysicalMemory(); }

// ---------------------------------------------------------------------------
//  破线程续跑线程（对齐 CE TDBVMResumerThread.Execute）
// ---------------------------------------------------------------------------
void DbvmTools::ResumerLoop() {
  Dbvm& dbvm = Dbvm::Instance();

  // 我们 CE 自己的进程 CR3（用它分辨"被冻结的是不是自家线程"）。
  // CR3 每个进程固定，启动时算一次即可。
  const uint64_t myCr3 = dbvm.Available()
                             ? dbvm.FindCr3(::GetCurrentProcessId())
                             : 0;

  int sleepMs = 1000;  // CE 起始 1 秒
  while (running_.load()) {
    const int n = dbvm.Available() ? dbvm.BrokenThreadCount() : 0;
    bool hadFrozen = false;

    std::vector<std::pair<uint64_t, uint64_t>> curSignatures;

    for (int i = 0; i < n; ++i) {
      DbvmBrokenThreadShort st{};
      if (!dbvm.GetBrokenThreadShort(i, &st)) continue;
      const int inuse = st.status & 0xFF;
      const int cont = (st.status >> 8) & 0xFF;
      if (inuse != kDbvmBpWait) continue;      // 只处理"等待"的冻结项
      if (cont != 0) continue;                 // 已决定续跑方式则跳过

      hadFrozen = true;
      const bool isOurThread = (myCr3 != 0 && st.cr3 == myCr3);
      if (isOurThread) {
        // 自家 CE 线程被冻结（多半是 DBVM 读写时踩着被监视页）：立即续跑，
        // 否则 CE 的物理读写/界面会卡死 —— 这就是 CE resumer 的核心动作。
        dbvm.ResumeBrokenThread(i, kDbvmContinueRun);
        continue;
      }

      // 目标进程线程命中我们下的 DBVM 断点 —— 冻结住（这就是"断"），上报界面。
      const uint64_t sig0 = st.cr3;
      const uint64_t sig1 = st.rip;
      curSignatures.push_back({sig0, sig1});

      // 只上报一次（同一冻结话情形，除非被续跑后再冻才重新上报）
      bool already = false;
      for (auto& r : reported_)
        if (r.first == sig0 && r.second == sig1) { already = true; break; }
      if (already) continue;

      // 由 watchid -> va 反查断点地址
      ptruint va = 0;
      {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = watches_.find(st.watchId);
        if (it != watches_.end()) va = it->second.first;
      }
      DbvmBpHit hit;
      hit.va = va;
      hit.rip = st.rip;
      hit.watchId = st.watchId;
      hit.cr3 = st.cr3;
      hit.shortState = st;
      reported_.push_back({sig0, sig1});
      if (hitCb_) hitCb_(hit);
    }

    // 收尾：把已消失的冻结情形从 reported_ 摘掉（避免累积泄漏）
    if (!reported_.empty()) {
      std::lock_guard<std::mutex> lk(mtx_);
      reported_.erase(
          std::remove_if(reported_.begin(), reported_.end(),
                         [&](const std::pair<uint64_t, uint64_t>& r) {
                           return std::find(curSignatures.begin(),
                                            curSignatures.end(), r) ==
                                  curSignatures.end();
                         }),
          reported_.end());
    }

    // CE 的退避：有冻结就加快轮询，空闲则放慢，封顶 1000ms
    sleepMs = hadFrozen ? (std::max)(1, sleepMs / 2)
                        : (std::min)(1000, sleepMs * 2 + 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
  }
}

// ---------------------------------------------------------------------------
//  便捷封装：把 VA→PA 的换算收进来，GUI 只传进程 + 虚拟地址
// ---------------------------------------------------------------------------
// 统一处理 DBVM 在场 + 虚拟→物理换算，成功返回 pa，失败填 err 返回 0
static uint64_t ResolvePa(DWORD pid, ptruint va, std::string* err) {
  Dbvm& dbvm = Dbvm::Instance();
  if (!dbvm.Available()) {
    if (err) *err = "DBVM 不在场，请先 加载并启动 DBVM";
    return 0;
  }
  const uint64_t pa = dbvm.VirtualToPhysical(pid, va);
  if (pa == 0) {
    if (err) *err = "虚拟地址转物理地址失败（目标可能已退出或地址无效）";
    return 0;
  }
  return pa;
}

int DbvmTools::ChangeRegOnBpAt(DWORD pid, ptruint va, const DbvmChangeRegInfo& info,
                               std::string* err) {
  const uint64_t pa = ResolvePa(pid, va, err);
  if (pa == 0) return -1;
  const int r = Dbvm::Instance().CloakChangeRegOnBp(pa & ~0xFFFULL, info, va);
  if (r != 0 && err) *err = "CloakChangeRegOnBp 失败: " + Dbvm::Instance().LastError();
  return r;
}

int DbvmTools::RemoveChangeRegAt(DWORD pid, ptruint va) {
  const uint64_t pa = ResolvePa(pid, va, nullptr);
  if (pa == 0) return -1;
  return Dbvm::Instance().CloakRemoveChangeRegOnBp(pa & ~0xFFFULL);
}

int DbvmTools::TraceOnBpAt(DWORD pid, ptruint va, uint32_t count, uint32_t options,
                           std::string* err) {
  const uint64_t pa = ResolvePa(pid, va, err);
  if (pa == 0) return -1;
  const int r = Dbvm::Instance().CloakTraceOnBp(pa & ~0xFFFULL, count, options, va);
  if (r != 0 && err) *err = "CloakTraceOnBp 失败: " + Dbvm::Instance().LastError();
  return r;
}

int DbvmTools::TraceOnBpStop() { return Dbvm::Instance().CloakTraceOnBpStop(); }

int DbvmTools::TraceOnBpReadLog(std::vector<DbvmPageEvent>* out, uint32_t* missed) {
  return Dbvm::Instance().CloakTraceOnBpReadLog(out, missed);
}

size_t DbvmTools::ReadOriginalAt(DWORD pid, ptruint va, void* dst, size_t size,
                                 std::string* err) {
  const uint64_t pa = ResolvePa(pid, va, err);
  if (pa == 0) return 0;
  return Dbvm::Instance().CloakReadOriginal(pa & ~0xFFFULL, dst, size);
}

size_t DbvmTools::WriteOriginalAt(DWORD pid, ptruint va, const void* src, size_t size,
                                  std::string* err) {
  const uint64_t pa = ResolvePa(pid, va, err);
  if (pa == 0) return 0;
  return Dbvm::Instance().CloakWriteOriginal(pa & ~0xFFFULL, src, size);
}

size_t DbvmTools::PhysicalReadAt(DWORD pid, ptruint va, void* dst, size_t size,
                                 std::string* err) {
  const uint64_t pa = ResolvePa(pid, va, err);
  if (pa == 0) return 0;
  return Dbvm::Instance().ReadPhysical(pa & ~0xFFFULL, dst, size);
}

size_t DbvmTools::PhysicalWriteAt(DWORD pid, ptruint va, const void* src, size_t size,
                                  std::string* err) {
  const uint64_t pa = ResolvePa(pid, va, err);
  if (pa == 0) return 0;
  return Dbvm::Instance().WritePhysical(pa & ~0xFFFULL, src, size);
}

}  // namespace ce