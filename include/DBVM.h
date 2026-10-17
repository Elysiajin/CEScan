#pragma once
// ============================================================================
//  DBVM.h —— DBVM 通道（CE 的 DBVM 功能 C++ 移植）
//
//  对应 CE 侧实现：Cheat Engine/dbk32/vmxfunctions.pas + DBKKernel/vmxoffload.c
//  + dbvm/vmm/vmcall.c（hypervisor 本体，本仓库 dbvm/ 目录即为源码）。
//
//  为什么需要 DBVM：
//    · 页守卫（PAGE_NOACCESS）只能抓「谁访问了这块数据」，抓不了代码地址，
//      而且命中要撤保护→单步→重挂，高频访问时成本极高、还会被目标自己
//      读页保护的代码（反调试）察觉；
//    · 硬件断点只有 4 个槽，且 DR 寄存器本身就被反作弊扫描；
//    · DBVM 在 VMX root 下用 EPT 的访问权限位做监视 —— 被监视的进程看到
//      的内存和保护属性一切正常（读得到、写得进），命中记录落在 DBVM 的
//      内存里由我们取回。这正是 CE「过检测」用法的基础：
//      监视、隐藏（cloak）、按命中改寄存器，目标端全部不可见。
//
//  通道：vmcall（Intel）/ vmmcall（AMD）
//    rax = 指向参数结构（首字段 size，第二字段 password2）
//    rdx = password1, rcx = password3
//    密码不对 → 直接 UD 异常（这也是「DBVM 是否在场」的判据）。
//
//  注意：DBVM 是 hypervisor，加载后必须给它留出物理页；本模块只做
//  「通道 + 命令封装 + 结果解析」，加载/卸载由 dbvm/ 与 DBKKernel 负责。
// ============================================================================
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "CETypes.h"

namespace ce {

// ---------------------------------------------------------------------------
//  密码（与 dbvm/vmm/main.c 的默认值一致；CE 侧 configure_vmx 会改掉它）
// ---------------------------------------------------------------------------
struct DbvmPassword {
  uint64_t p1 = 0x76543210;
  uint32_t p2 = 0xfedcba98;
  uint64_t p3 = 0x90909090;   // CE 侧的第三密码，默认 0x90909090
};

// ---------------------------------------------------------------------------
//  VMCALL 命令号（取自 dbvm/vmm/vmcall.h 与 vmxfunctions.pas，两边必须一致）
// ---------------------------------------------------------------------------
enum DbvmCommand : uint32_t {
  kVmcallGetVersion            = 0,
  kVmcallChangePassword        = 1,
  kVmcallReadPhysicalMemory    = 3,
  kVmcallWritePhysicalMemory   = 4,
  kVmcallGetCr3                = 19,
  kVmcallWatchWrites           = 41,
  kVmcallWatchReads            = 42,
  kVmcallWatchRetrieveLog      = 43,
  kVmcallWatchDelete           = 44,
  kVmcallCloakActivate         = 45,
  kVmcallCloakDeactivate       = 46,
  kVmcallCloakReadOriginal     = 47,
  kVmcallCloakWriteOriginal    = 48,
  kVmcallCloakChangeRegOnBp    = 49,
  kVmcallCloakRemoveChangeReg  = 50,
  kVmcallEptReset              = 51,
  kVmcallLogCr3ValuesStart     = 52,   // 供 FindCr3 使用：开始记录所有 CR3 切换
  kVmcallLogCr3ValuesStop      = 53,   // 停止记录并把 4096 字节 CR3 日志拷回
  kVmcallWatchExecutes         = 60,
  kVmcallWatchGetStatus        = 68,
  kVmcallCloakTraceOnBp        = 69,
  kVmcallCloakTraceOnBpRemove  = 70,
  kVmcallCloakTraceOnBpReadLog = 71,
  kVmcallCloakTraceOnBpStatus  = 72,
  kVmcallCloakTraceOnBpStop    = 73,
  kVmcallGetBrokenThreadListSize = 74,
  kVmcallGetBrokenThreadShort    = 75,
  kVmcallGetBrokenThreadFull     = 76,
  kVmcallSetBrokenThreadFull     = 77,
  kVmcallResumeBrokenThread      = 78,
  kVmcallHideDbvmPhysicalAddr    = 79,
  kVmcallHideDbvmPhysicalAddrAll = 80,
};

// VMCALL 返回值的「不是这个功能」标记（dbvm/vmm/vmcall.c 里到处是它）
constexpr uint64_t kDbvmDead = 0xcedead;

// 监视选项（对应 vmxfunctions.pas 的 EPTO_*）
enum DbvmWatchOption : uint32_t {
  kEptoMultipleRip  = 1u << 0,   // 同 RIP 不同寄存器也分别记录
  kEptoLogAll       = 1u << 1,   // 记录整页访问（不只是目标地址）
  kEptoSaveFxsave   = 1u << 2,   // 每条命中附带 FPU/XMM 快照
  kEptoSaveStack    = 1u << 3,   // 每条命中附带 4KB 栈快照
  kEptoGrowWhenFull = 1u << 5,   // 缓冲满时自动扩容（DBVM 内存耗尽会整机崩，慎用）
  kEptoInterrupt    = 1u << 6,   // 不记录，命中即中断（配合破线程表用）
  kEptoDbvmBp       = 1u << 7,   // 命中即冻结线程并改 RIP 到 int3 自旋（调试器用法）
};

// 破线程表里一条记录的 status 字段（低字节=状态，高字节=续跑方式）
//   状态：0=空 1=被冻结等待处理 2=已被放弃
//   续跑：0=尚未决定 1=单步一次后继续 2=直接继续运行
constexpr int kDbvmBpWait      = 1;
constexpr int kDbvmBpAbandoned = 2;
constexpr int kDbvmContinueRun = 2;
constexpr int kDbvmContinueStep = 1;

// ---------------------------------------------------------------------------
//  DBVM 记录的一条页访问事件（= dbvm/vmm/eptstructs.h 的 PageEventBasic）
//  与 Pascal 侧 TPageEventBasic 布局逐字段一致（全是 8 字节字段，packed 无影响）
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct DbvmPageEvent {
  uint64_t virtualAddress;
  uint64_t physicalAddress;
  uint64_t cr3;
  uint64_t fsBase;
  uint64_t gsBase;
  uint64_t gsBaseKernel;
  uint64_t flags;
  uint64_t rax, rbx, rcx, rdx;
  uint64_t rsi, rdi;
  uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
  uint64_t rbp, rsp, rip;
  uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
  uint16_t cs, ds, es, ss, fs, gs;
  uint32_t count;          // 该条记录被重复看到的次数（也用作心跳）
};

// 命中日志头（= PageEventListDescriptor，5 个 DWORD = 20 字节，事件紧跟其后）
struct DbvmEventListHead {
  uint32_t id;
  uint32_t maxSize;
  uint32_t numberOfEntries;
  uint32_t missedEntries;  // 缓冲满时丢掉的条数
  uint32_t entryType;      // 0=Basic 1=Extended 2=BasicWithStack 3=ExtendedWithStack
};

// 被冻结线程的短状态（= TDBVMBPShortState）
struct DbvmBrokenThreadShort {
  int32_t  watchId;
  int32_t  status;
  uint32_t cs;
  uint64_t rip;
  uint64_t cr3;
  uint64_t fsBase;
  uint64_t gsBase;
  uint64_t gsBaseKernel;
  uint64_t heartbeat;
};

// 改寄存器断点的开关位（= CHANGEREGONBPINFO 的 Flags 位域，32 位打包）
struct DbvmChangeRegFlags {
  uint32_t changeRax : 1, changeRbx : 1, changeRcx : 1, changeRdx : 1;
  uint32_t changeRsi : 1, changeRdi : 1, changeRbp : 1, changeRsp : 1;
  uint32_t changeRip : 1, changeR8  : 1, changeR9  : 1, changeR10 : 1;
  uint32_t changeR11 : 1, changeR12 : 1, changeR13 : 1, changeR14 : 1;
  uint32_t changeR15 : 1;
  uint32_t changeCF  : 1, changePF  : 1, changeAF  : 1, changeZF : 1;
  uint32_t changeSF  : 1, changeOF  : 1;
  uint32_t newCF : 1, newPF : 1, newAF : 1, newZF : 1, newSF : 1, newOF : 1;
  uint32_t reserved : 3;
};

// 改寄存器断点的完整参数（= CHANGEREGONBPINFO）
// 注意：changeXMM/changeFP 是「要改哪些寄存器」的位图，new* 才是新值。
struct DbvmChangeRegInfo {
  DbvmChangeRegFlags flags{};
  uint64_t changeXMM = 0;   // 16 个 nibble，每 bit 对应一个 dword
  uint64_t changeFP  = 0;
  uint64_t newRax = 0, newRbx = 0, newRcx = 0, newRdx = 0;
  uint64_t newRsi = 0, newRdi = 0, newRbp = 0, newRsp = 0;
  uint64_t newRip = 0;
  uint64_t newR8 = 0, newR9 = 0, newR10 = 0, newR11 = 0;
  uint64_t newR12 = 0, newR13 = 0, newR14 = 0, newR15 = 0;
  uint64_t newFp[16] = {};   // FP0..FP7（各 2 个 qword 高低半）
  uint64_t newXmm[32] = {};  // XMM0..XMM15（各 2 个 qword）
};
#pragma pack(pop)

// ---------------------------------------------------------------------------
//  DBVM 通道
//
//  用法：
//      Dbvm& d = Dbvm::Instance();
//      d.Detect();                       // 探测（不需要 DBVM 在场）
//      if (d.Available()) { ... }        // 可用才走 DBVM 通道
//
//  线程纪律（与 CE 一致）：vmcall 必须在**当前 CPU** 上执行，而 EPT 监视的
//  生效范围也按 CPU 分。监视/取日志/冻结线程续跑这三类操作都必须在同一线程
//  上发起，本模块内部用一把递归锁串行化，调用方不要跨线程并发调用。
// ---------------------------------------------------------------------------
class Dbvm {
 public:
  static Dbvm& Instance();

  // --- 探测与配置 ---------------------------------------------------------
  // 探测 DBVM 是否在场（vmcall GETVERSION 返回 0xce0000xx 即在场）。
  // 不依赖管理员权限；不在场返回 false 且不会抛异常。
  bool Detect();

  // 上次探测得到的版本号（0 = 不在场）。CE 里是 0xce0000 + version。
  uint32_t Version() const { return version_; }
  bool Available() const { return version_ != 0; }

  // 是否已经确认「CPU 支持并允许执行 vmcall 指令」。
  // 不支持的 CPU 上执行 vmcall 会直接 UD，所以必须先查 CPUID。
  static bool CpuSupportsVmcall();

  // 改密码（CE 的 configure_vmx 用它把默认密码换掉，避免别人直接用 DBVM）
  bool ChangePassword(const DbvmPassword& np, std::string* error = nullptr);

  // --- 物理内存读写（绕过目标进程的页保护/反读，CE 的 PhysicalMemoryHandler）--
  // 返回实际读/写的字节数；0 表示失败。
  size_t ReadPhysical(uint64_t pa, void* buffer, size_t size);
  size_t WritePhysical(uint64_t pa, const void* buffer, size_t size);

  // 虚拟地址 → 物理地址（先取 CR3 再走页表；失败返回 0）
  uint64_t FindCr3(uint32_t pid);
  uint64_t VirtualToPhysical(uint32_t pid, ptruint va);

  // --- EPT 监视（谁访问 / 谁写入 / 谁执行）--------------------------------
  //  物理地址粒度：监视目标页的物理基址。
  //  返回 ID（>0 成功），失败返回 -1。
  int WatchWrites(uint64_t pa, uint32_t size, uint32_t options, uint32_t maxEntries);
  int WatchReads(uint64_t pa, uint32_t size, uint32_t options, uint32_t maxEntries);
  int WatchExecutes(uint64_t pa, uint32_t size, uint32_t options, uint32_t maxEntries);

  // 取回命中日志。entries 会被填成解析后的事件列表，missed 出参给出丢包数。
  // 返回 0 成功，2 表示缓冲太小（已自动扩容重试），其它为失败。
  int RetrieveLog(int id, std::vector<DbvmPageEvent>* entries, uint32_t* missed = nullptr);

  // 停止监视并释放 DBVM 侧缓冲
  bool WatchDelete(int id);

  // 清掉所有监视/隐藏/改寄存器断点（CE 的 ept_reset）
  void EptReset();

  // --- 隐藏（cloak）：让目标读到的内容与我们看到的不一样 --------------------
  //  activate：把该物理页的「原始副本」留一份，之后目标读到的是原始副本，
  //  而我们通过 ReadOriginal/WriteOriginal 操作真实内容 —— 这就是 CE 的
  //  「内存隐藏/过检测」核心：改值不被目标的自检发现。
  //  返回 0 成功、1 表示该页已处于隐藏态、-1 失败。
  int CloakActivate(uint64_t pa, uint64_t va = 0, uint64_t mode = 1);
  bool CloakDeactivate(uint64_t pa);
  size_t CloakReadOriginal(uint64_t pa, void* dst, size_t size);
  size_t CloakWriteOriginal(uint64_t pa, const void* src, size_t size);

  // --- 隐藏 DBVM 自己的物理内存（防止目标/反作弊扫到 hypervisor）------------
  bool HideDbvmPhysicalMemory();

  // --- 破线程表（DBVM 断点命中后冻结的线程，必须由我们续跑）----------------
  int  BrokenThreadCount();
  bool GetBrokenThreadShort(int id, DbvmBrokenThreadShort* out);
  // 取完整状态（含全部寄存器与 FPU/XMM）—— 用 short 版拉全量，见实现注释
  bool GetBrokenThreadFull(int id, DbvmPageEvent* event, int* watchId, int* status);
  // continueMethod：kDbvmContinueRun=直接跑 / kDbvmContinueStep=单步一次
  bool ResumeBrokenThread(int id, int continueMethod);

  // --- 改寄存器断点 / 命中跟踪（CE 的 changereg-on-bp、traceonbp）----------
  int  CloakChangeRegOnBp(uint64_t pa, const DbvmChangeRegInfo& info, uint64_t va = 0);
  int  CloakRemoveChangeRegOnBp(uint64_t pa);
  int  CloakTraceOnBp(uint64_t pa, uint32_t count, uint32_t options, uint64_t va = 0);
  int  CloakTraceOnBpStop();
  int  CloakTraceOnBpRemove(uint64_t pa = 0, bool force = false);
  int  CloakTraceOnBpReadLog(std::vector<DbvmPageEvent>* out, uint32_t* missed = nullptr);

  // --- 诊断 ---------------------------------------------------------------
  const std::string& LastError() const { return lastError_; }
  void SetPassword(const DbvmPassword& p) { password_ = p; }
  const DbvmPassword& Password() const { return password_; }
  // 会话内已经起过的监视 ID（EptReset / Detach 时统一清）
  std::vector<int> ActiveWatchIds() const;

 private:
  Dbvm() = default;
  Dbvm(const Dbvm&) = delete;
  Dbvm& operator=(const Dbvm&) = delete;

  // 真正执行 vmcall：rax=结构地址、rdx=p1、rcx=p3
  // 返回 DBVM 填的 rax；CPU 不支持 / 密码错 / DBVM 不在场（触发 #UD）时返回 0，
  // 并通过 vmcallFailed_ 标记区分「真的返回 0」与「vmcall 没执行成功」。
  uint64_t Invoke(void* paramBlock);
  // 带二级输出（rdx）的版本，AMD/Intel 分派（vmmcall / vmcall）
  uint64_t InvokeRaw(void* paramBlock, uint64_t* secondaryOut);

  // WatchWrites/Reads/Executes 的统一实现（只在命令号上不同）
  int WatchStart(uint32_t command, uint64_t pa, uint32_t size,
                 uint32_t options, uint32_t maxEntries);
  // 日志条目大小（basic / basic+fxsave / basic+stack / basic+fxsave+stack）
  size_t EventEntrySize(uint32_t entryType);

  // 四级页表遍历（支持 1GB/2MB 大页）：
  //   单地址版返回物理地址，失败返回 0；
  //   跨页版把 va 起 size 字节拷进 dst，返回实际拷入字节数。
  uint64_t WalkPageTable(uint64_t cr3, uint64_t va);
  size_t WalkPageTable(uint64_t cr3, uint64_t va, void* dst, size_t size);

  void SetError(const std::string& s) { lastError_ = s; }

  uint32_t version_ = 0;
  DbvmPassword password_{};
  std::string lastError_;
  std::vector<int> watchIds_;
  // 最近一次 vmcall 的结果 / 是否失败（#UD 或不可用）。所有 vmcall 都在
  // cs_ 锁内执行，这两个成员只会在持有锁的线程上读写。
  uint64_t vmcallResult_ = 0;
  bool vmcallFailed_ = true;
  // vmcall 是「本 CPU」语义，且 DBVM 的 EPT 操作不可重入 → 串行化
  CRITICAL_SECTION cs_{};
  bool csInit_ = false;
  void Lock();
  void Unlock();
};

// ---------------------------------------------------------------------------
//  便捷判断：DBVM 在场时，界面上的「谁访问/谁写入」应该优先走 EPT 通道。
//  与 CE 的 isDBVMCapable 对应。
// ---------------------------------------------------------------------------
bool DbvmCapable();

}  // namespace ce
