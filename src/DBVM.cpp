//=============================================================================
//  DBVM.cpp —— DBVM 通道（CE 的 DBVM 功能 C++ 移植实现）
//
//  移植对照：
//      Cheat Engine/dbk32/vmxfunctions.pas   —— 命令结构 / 返回语义（逐条对齐）
//      Cheat Engine/NewKernelHandler.pas     —— isIntel / isAMD / isDBVMCapable
//      dbvm/vmm/vmcall.c + vmcallstructs.h   —— vmcall 协议（rax=参数指针，
//        rdx=password1, rcx=password3；参数头三个 dword: size, password2, command）
//
//  关键点：
//    · MSVC x64 没有内联汇编，vmcall/vmmcall 用一段手写机器码 thunk 执行
//      （VirtualAlloc RWX + 函数指针调用），不需要额外汇编器；
//    · DBVM 不在场 / 密码错 / CPU 不支持时会触发 #UD（EXCEPTION_ILLEGAL_INSTRUCTION），
//      用 __try/__except 捕获，与 CE 的 vmcallexceptiontest 等价；
//    · 所有 vmcall 通过 cs_ 串行化（vmcall 是「本 CPU」语义且 EPT 操作不可重入）。
//=============================================================================
#include "DBVM.h"

#include <windows.h>
#include <intrin.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <tlhelp32.h>

// 所有 vmcall 参数结构都必须与 dbvm/vmm/vmcallstructs.h 的
// __attribute__((__packed__)) 布局逐字节一致 —— 整个 .cpp 里只有这些结构，
// 直接对整个翻译单元开 pack(1)。
#pragma pack(push, 1)

namespace ce {
namespace {

//---------------------------------------------------------------------------
//  CPUID 辅助（对应 NewKernelHandler.pas 的 isIntel / isAMD / isDBVMCapable）
//---------------------------------------------------------------------------
struct CpuIdRegs {
  uint32_t a = 0, b = 0, c = 0, d = 0;
};

CpuIdRegs CpuId(uint32_t leaf, uint32_t sub = 0) {
  int regs[4] = {0, 0, 0, 0};
  __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(sub));
  return {static_cast<uint32_t>(regs[0]), static_cast<uint32_t>(regs[1]),
          static_cast<uint32_t>(regs[2]), static_cast<uint32_t>(regs[3])};
}

bool IsIntel() {
  const CpuIdRegs r = CpuId(0);
  return r.b == 0x756e6547 && r.d == 0x49656e69 && r.c == 0x6c65746e;  // GenuineIntel
}

bool IsAmd() {
  const CpuIdRegs r = CpuId(0);
  return r.b == 0x68747541 && r.d == 0x69746e65 && r.c == 0x444d4163;  // AuthenticAMD
}

//---------------------------------------------------------------------------
//  vmcall thunk（手写机器码，x64）
//
//  目标签名：uint64_t thunk(void* paramBlock, uint64_t p1, uint64_t p3,
//                           uint64_t* secondaryOut)
//    MSVC x64 调用约定：rcx=arg1  rdx=arg2  r8=arg3  r9=arg4
//    DBVM 约定：         rax=参数指针  rdx=password1  rcx=password3
//  汇编（Intel 版）：
//      mov rax, rcx     ; 48 89 C8   paramBlock -> rax
//      mov rcx, r8      ; 4C 89 C1   p3 -> rcx
//      vmcall           ; 0F 01 C1   (AMD: vmmcall = 0F 01 D9)
//      mov [r9], rdx    ; 48 89 11   保存二级输出（DBVM 在 rdx 里回填）
//      ret              ; C3
//---------------------------------------------------------------------------
constexpr uint8_t kThunkIntel[] = {0x48, 0x89, 0xC8, 0x4C, 0x89, 0xC1,
                                   0x0F, 0x01, 0xC1, 0x48, 0x89, 0x11, 0xC3};
constexpr uint8_t kThunkAmd[]   = {0x48, 0x89, 0xC8, 0x4C, 0x89, 0xC1,
                                   0x0F, 0x01, 0xD9, 0x48, 0x89, 0x11, 0xC3};

using VmcallThunkFn = uint64_t (*)(void*, uint64_t, uint64_t, uint64_t*);

VmcallThunkFn g_thunk = nullptr;

bool InitThunk() {
  if (g_thunk != nullptr) return true;

  const uint8_t* src = IsIntel() ? kThunkIntel : kThunkAmd;
  void* mem = ::VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (mem == nullptr) return false;
  std::memcpy(mem, src, 13);
  DWORD oldProt = 0;
  if (!::VirtualProtect(mem, 64, PAGE_EXECUTE_READWRITE, &oldProt)) {
    ::VirtualFree(mem, 0, MEM_RELEASE);
    return false;
  }
  g_thunk = reinterpret_cast<VmcallThunkFn>(mem);
  return true;
}

// 执行一次 vmcall。DBVM 不在场 / 密码错 / CPU 不支持 → 触发 #UD，被 __try 接住，
// 返回 0 且 *udRaised 置 true。注意：DBVM 自己也可能在返回里给 0，所以用
// *udRaised 区分「真的返回 0」与「没执行成」。
uint64_t CallVmcall(void* paramBlock, uint64_t p1, uint64_t p3,
                    uint64_t* secondaryOut, bool* udRaised) {
  if (g_thunk == nullptr) {
    *udRaised = true;
    return 0;
  }
  __try {
    const uint64_t r = g_thunk(paramBlock, p1, p3, secondaryOut);
    *udRaised = false;
    return r;
  }
  __except (::GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH) {
    *udRaised = true;
    return 0;
  }
}

// 物理地址掩码（页基址，去掉低位偏移；CE 的 MAXPHYADDRMASKPB 语义）
constexpr uint64_t kPhysPageMask = ~0xFFFULL;

// 本地小工具：数字转十六进制（避免引入 CEUtil 依赖）。
// 放在匿名命名空间里，保证在下面的类方法使用点之前可见。
std::string CEUtilHex(uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
  return std::string(buf);
}

}  // namespace

//=============================================================================
//  Dbvm 单例 / 锁
//=============================================================================
Dbvm& Dbvm::Instance() {
  static Dbvm inst;
  static std::once_flag once;
  std::call_once(once, [] {
    ::InitializeCriticalSection(&inst.cs_);
    inst.csInit_ = true;
  });
  return inst;
}

void Dbvm::Lock() {
  if (csInit_) ::EnterCriticalSection(&cs_);
}

void Dbvm::Unlock() {
  if (csInit_) ::LeaveCriticalSection(&cs_);
}

//=============================================================================
//  探测与配置
//=============================================================================
bool Dbvm::CpuSupportsVmcall() {
  if (IsIntel()) {
    // CPUID.1:ECX.VMX[bit5]（NewKernelHandler.isDBVMCapable）
    return (CpuId(1).c >> 5) & 1u;
  }
  if (IsAmd()) {
    // CPUID.0x80000001:ECX.SVM[bit2]
    return (CpuId(0x80000001).c >> 2) & 1u;
  }
  return false;
}

bool Dbvm::Detect() {
  version_ = 0;
  if (!InitThunk()) {
    SetError("无法分配 vmcall 执行区");
    return false;
  }
  if (!CpuSupportsVmcall()) {
    SetError("CPU 不支持 VMX/SVM，无法运行 DBVM");
    return false;
  }

  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallGetVersion;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_) {
    SetError("DBVM 不在场（vmcall 触发 #UD，或 CPU 不支持）");
    return false;
  }
  // VMCALL_GETVERSION 返回 0xce000000 + dbvmversion（vmcall.c）
  if (r != 0 && (r >> 24) == 0xce) {
    version_ = static_cast<uint32_t>(r);
    SetError(std::string());
    return true;
  }
  SetError("DBVM 版本校验失败（返回 0x" + CEUtilHex(r) + "）");
  return false;
}

bool Dbvm::ChangePassword(const DbvmPassword& np, std::string* error) {
  if (!Available()) {
    if (error) *error = "DBVM 不在场";
    return false;
  }
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint64_t password1;
    uint32_t password2;
    uint64_t password3;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallChangePassword;
  p.password1 = np.p1;
  p.password2 = np.p2;
  p.password3 = np.p3;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_) {
    if (error) *error = "vmcall 执行失败";
    return false;
  }
  if (r != 0) {
    if (error) *error = "改密码被 DBVM 拒绝（返回 " + CEUtilHex(r) + "）";
    return false;
  }
  password_ = np;  // 与 CE 一致：成功后本地密码立即切换
  return true;
}

//=============================================================================
//  物理内存读写（绕过目标页保护 / 反读）
//=============================================================================
size_t Dbvm::ReadPhysical(uint64_t pa, void* buffer, size_t size) {
  if (buffer == nullptr || size == 0) return 0;
  // 布局 = VMCALL_READPHYSICALMEMORY：sourcePA/bytesToRead(DWORD)/destinationVA/nopagefault
  // DBVM 单次最多映射 1MB（vmcall_readPhysicalMemory），超了按剩余字节返回，这里直接封顶。
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint64_t sourcePA;
    uint32_t size;
    uint64_t destinationVA;
    uint32_t nopagefault;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallReadPhysicalMemory;
  p.sourcePA = pa;
  p.size = static_cast<uint32_t>(std::min<size_t>(size, 0x100000));
  p.destinationVA = reinterpret_cast<uint64_t>(buffer);
  p.nopagefault = 0;

  const uint64_t r = Invoke(&p);  // 返回「还剩多少字节没读」
  if (vmcallFailed_) return 0;
  const uint64_t done = size - std::min<uint64_t>(r, size);
  return static_cast<size_t>(done);
}

size_t Dbvm::WritePhysical(uint64_t pa, const void* buffer, size_t size) {
  if (buffer == nullptr || size == 0) return 0;
  // 布局 = VMCALL_WRITEPHYSICALMEMORY：destinationPA/bytesToWrite(DWORD)/sourceVA/nopagefault
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint64_t destinationPA;
    uint32_t size;
    uint64_t sourceVA;
    uint32_t nopagefault;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallWritePhysicalMemory;
  p.destinationPA = pa;
  p.size = static_cast<uint32_t>(std::min<size_t>(size, 0x100000));
  p.sourceVA = reinterpret_cast<uint64_t>(buffer);
  p.nopagefault = 0;

  const uint64_t r = Invoke(&p);  // 返回「还有多少字节没写」
  if (vmcallFailed_) return 0;
  const uint64_t done = size - std::min<uint64_t>(r, size);
  return static_cast<size_t>(done);
}

//---------------------------------------------------------------------------
//  CR3 日志法（移植 dbvm_findCR3）：
//    1. 开 DBVM 的 CR3 记录（VMCALL_LOG_CR3VALUES_START）
//    2. 用 ReadProcessMemory 读目标主模块首页 + 首线程 TEB 各留一份快照
//    3. 停记录（VMCALL_LOG_CR3VALUES_STOP），取回 4096 字节 CR3 日志
//    4. 对日志里每个 CR3 用 ReadPhysical + 页表遍历重新读快照地址比对
//    5. 内容一致的那个 CR3 就是目标进程的（进程上下文切换造成的）
//---------------------------------------------------------------------------
uint64_t Dbvm::FindCr3(uint32_t pid) {
  if (pid == 0 || !Available()) return 0;

  const HANDLE proc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                    FALSE, pid);
  if (proc == nullptr) return 0;

  // 主模块基址（= PEB 加载的 ImageBase）
  uint64_t moduleBase = 0;
  {
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap != INVALID_HANDLE_VALUE) {
      MODULEENTRY32W me{};
      me.dwSize = sizeof(me);
      if (::Module32FirstW(snap, &me)) moduleBase = reinterpret_cast<uint64_t>(me.modBaseAddr);
      ::CloseHandle(snap);
    }
  }

  // 首线程 TEB（NtQueryInformationThread ThreadBasicInformation）
  uint64_t tebBase = 0;
  {
    using NtQIT = LONG(WINAPI*)(HANDLE, LONG, PVOID, ULONG, PULONG);
    const auto NtQueryInformationThread = reinterpret_cast<NtQIT>(
        ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"),
                         "NtQueryInformationThread"));
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (NtQueryInformationThread && snap != INVALID_HANDLE_VALUE) {
      THREADENTRY32 te{};
      te.dwSize = sizeof(te);
      if (::Thread32First(snap, &te)) {
        do {
          if (te.th32OwnerProcessID == pid) {
            HANDLE th = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (th) {
              struct Tib { PVOID exceptionList; PVOID stackBase; PVOID stackLimit;
                           PVOID subSystemTib; PVOID fiberData; PVOID arbitraryUserPointer;
                           PVOID self; } tbi{};
              ULONG len = 0;
              if (NtQueryInformationThread(th, 0 /*ThreadBasicInformation*/,
                                           &tbi, sizeof(tbi), &len) == 0)
                tebBase = reinterpret_cast<uint64_t>(tbi.self);
              ::CloseHandle(th);
            }
            break;
          }
        } while (::Thread32Next(snap, &te));
      }
      ::CloseHandle(snap);
    }
  }

  // 取快照
  uint8_t moduleSnap[4096]{};
  uint8_t tebSnap[80]{};
  bool haveModuleSnap = moduleBase != 0 &&
                        ::ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(moduleBase),
                                            moduleSnap, sizeof(moduleSnap), nullptr);
  bool haveTebSnap = tebBase != 0 &&
                     ::ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(tebBase),
                                         tebSnap, sizeof(tebSnap), nullptr);

  if (!haveModuleSnap && !haveTebSnap) {
    ::CloseHandle(proc);
    return 0;
  }

  // 开启 / 关闭 CR3 记录
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
  } start{};
  start.structsize = sizeof(start);
  start.level2pass = password_.p2;
  start.command = kVmcallLogCr3ValuesStart;
  Invoke(&start);
  if (vmcallFailed_) {
    ::CloseHandle(proc);
    return 0;
  }

  ::Sleep(20);  // 等一次进程切换把目标 CR3 记进日志

  uint64_t cr3log[512]{};
  {
    struct {
      uint32_t structsize;
      uint32_t level2pass;
      uint32_t command;
      uint64_t destination;  // 4096 字节 CR3 日志缓冲（vmcall.c LOGCR3_STOP）
    } stop{};
    stop.structsize = sizeof(stop);
    stop.level2pass = password_.p2;
    stop.command = kVmcallLogCr3ValuesStop;
    stop.destination = reinterpret_cast<uint64_t>(cr3log);
    Invoke(&stop);
    if (vmcallFailed_) {
      ::CloseHandle(proc);
      return 0;
    }
  }

  // 对每个 CR3 做页表遍历 + 内容比对
  for (int i = 0; i < 512; ++i) {
    const uint64_t cr3 = cr3log[i];
    if (cr3 == 0) break;

    bool ok = true;
    if (haveModuleSnap) {
      uint8_t buf[4096]{};
      if (WalkPageTable(cr3, moduleBase, buf, sizeof(buf)) == sizeof(buf) &&
          std::memcmp(buf, moduleSnap, sizeof(buf)) == 0) {
        ok = true;
      } else {
        ok = false;
      }
    }
    if (ok && haveTebSnap) {
      uint8_t buf[80]{};
      if (WalkPageTable(cr3, tebBase, buf, sizeof(buf)) == sizeof(buf) &&
          std::memcmp(buf, tebSnap, sizeof(buf)) == 0) {
        ok = true;
      } else {
        ok = false;
      }
    }
    if (ok) {
      ::CloseHandle(proc);
      return cr3;
    }
  }

  ::CloseHandle(proc);
  return 0;
}

//---------------------------------------------------------------------------
//  页表遍历：给定 CR3 与虚拟地址，返回物理地址（失败返回 0）
//  支持 4KB 页、2MB 大页、1GB 大页（PML4/PDPT/PD/PT 四级）
//---------------------------------------------------------------------------
uint64_t Dbvm::WalkPageTable(uint64_t cr3, uint64_t va) {
  uint8_t entryBuf[8]{};
  auto readEntry = [&](uint64_t pa, uint8_t* out) -> bool {
    return ReadPhysical(pa, out, 8) == 8;
  };

  // PML4E
  const uint64_t pml4pa = (cr3 & kPhysPageMask) + ((va >> 39) & 0x1FF) * 8;
  if (!readEntry(pml4pa, entryBuf)) return 0;
  uint64_t pml4e;
  std::memcpy(&pml4e, entryBuf, 8);
  if (!(pml4e & 1)) return 0;

  // PDPTE（支持 1GB 大页）
  const uint64_t pdptpa = (pml4e & kPhysPageMask) + ((va >> 30) & 0x1FF) * 8;
  if (!readEntry(pdptpa, entryBuf)) return 0;
  uint64_t pdpte;
  std::memcpy(&pdpte, entryBuf, 8);
  if (!(pdpte & 1)) return 0;
  if (pdpte & (1ULL << 7)) return (pdpte & 0x000FFFFFC0000000ULL) + (va & 0x3FFFFFFF);

  // PDE（支持 2MB 大页）
  const uint64_t pdpa = (pdpte & kPhysPageMask) + ((va >> 21) & 0x1FF) * 8;
  if (!readEntry(pdpa, entryBuf)) return 0;
  uint64_t pde;
  std::memcpy(&pde, entryBuf, 8);
  if (!(pde & 1)) return 0;
  if (pde & (1ULL << 7)) return (pde & 0x000FFFFFFFE00000ULL) + (va & 0x1FFFFF);

  // PTE
  const uint64_t ptpa = (pde & kPhysPageMask) + ((va >> 12) & 0x1FF) * 8;
  if (!readEntry(ptpa, entryBuf)) return 0;
  uint64_t pte;
  std::memcpy(&pte, entryBuf, 8);
  if (!(pte & 1)) return 0;
  return (pte & kPhysPageMask) + (va & 0xFFF);
}

// 跨页读取：先按页遍历出物理地址，再逐页 ReadPhysical 拷贝
size_t Dbvm::WalkPageTable(uint64_t cr3, uint64_t va, void* dst, size_t size) {
  auto* out = static_cast<uint8_t*>(dst);
  size_t done = 0;
  while (done < size) {
    const uint64_t pa = WalkPageTable(cr3, va + done);
    if (pa == 0) break;
    const size_t inPage = 0x1000 - static_cast<size_t>((va + done) & 0xFFF);
    const size_t chunk = (std::min)(inPage, size - done);
    if (ReadPhysical(pa, out + done, chunk) != chunk) break;
    done += chunk;
  }
  return done;
}

uint64_t Dbvm::VirtualToPhysical(uint32_t pid, ptruint va) {
  const uint64_t cr3 = FindCr3(pid);
  if (cr3 == 0) return 0;
  return WalkPageTable(cr3, va);
}

//=============================================================================
//  EPT 监视
//=============================================================================
int Dbvm::WatchWrites(uint64_t pa, uint32_t size, uint32_t options,
                      uint32_t maxEntries) {
  return WatchStart(kVmcallWatchWrites, pa, size, options, maxEntries);
}

int Dbvm::WatchReads(uint64_t pa, uint32_t size, uint32_t options,
                     uint32_t maxEntries) {
  return WatchStart(kVmcallWatchReads, pa, size, options, maxEntries);
}

int Dbvm::WatchExecutes(uint64_t pa, uint32_t size, uint32_t options,
                        uint32_t maxEntries) {
  return WatchStart(kVmcallWatchExecutes, pa, size, options, maxEntries);
}

int Dbvm::WatchStart(uint32_t command, uint64_t pa, uint32_t size,
                     uint32_t options, uint32_t maxEntries) {
  // 结构布局对齐 vmxfunctions.pas 的 watch_writes/reads/executes
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint64_t physicalAddress;
    uint64_t userModeLoop;
    uint64_t kernelModeLoop;
    int32_t  size;
    uint32_t options;
    int32_t  maxEntryCount;
    int32_t  id;  // 返回的监视 ID
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = command;
  p.physicalAddress = pa;
  p.userModeLoop = 0;
  p.kernelModeLoop = 0;
  p.size = static_cast<int32_t>(size);
  p.options = options;
  p.maxEntryCount = static_cast<int32_t>(maxEntries);
  p.id = -1;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_ || r != 0) return -1;
  if (p.id <= 0) return -1;
  watchIds_.push_back(p.id);
  return p.id;
}

int Dbvm::RetrieveLog(int id, std::vector<DbvmPageEvent>* entries,
                      uint32_t* missed) {
  if (entries == nullptr) return -1;
  entries->clear();
  if (missed) *missed = 0;

  // 先取头：结果缓冲 = 头 + 一段事件空间。缓冲太小 DBVM 返回 2，按需求翻倍重试
  constexpr size_t kInitial = sizeof(DbvmEventListHead) + 8 * sizeof(DbvmPageEvent);
  std::vector<uint8_t> buf(kInitial, 0);

  for (int attempt = 0; attempt < 8; ++attempt) {
    struct {
      uint32_t structsize;
      uint32_t level2pass;
      uint32_t command;
      uint32_t id;
      uint64_t results;
      uint32_t resultsize;
      uint32_t copied;
    } p{};
    p.structsize = sizeof(p);
    p.level2pass = password_.p2;
    p.command = kVmcallWatchRetrieveLog;
    p.id = static_cast<uint32_t>(id);
    p.results = reinterpret_cast<uint64_t>(buf.data());
    p.resultsize = static_cast<uint32_t>(buf.size());
    p.copied = 0;

    const uint64_t r = Invoke(&p);
    if (vmcallFailed_) return -1;
    if (r == 2) {
      // 缓冲太小：DBVM 会在 resultssize 里回填需要的大小
      const size_t need = std::max<size_t>(buf.size() * 2, p.resultsize);
      buf.assign(need, 0);
      continue;
    }
    if (r != 0) return static_cast<int>(r);

    DbvmEventListHead head{};
    std::memcpy(&head, buf.data(), sizeof(head));
    if (missed) *missed = head.missedEntries;

    const size_t entrySize = EventEntrySize(head.entryType);
    if (entrySize == 0) return -1;
    const size_t maxEntries =
        (buf.size() - sizeof(DbvmEventListHead)) / entrySize;
    const size_t n = std::min<size_t>(head.numberOfEntries, maxEntries);

    entries->reserve(n);
    const uint8_t* pEvent = buf.data() + sizeof(DbvmEventListHead);
    for (size_t i = 0; i < n; ++i) {
      DbvmPageEvent ev{};
      std::memcpy(&ev, pEvent + i * entrySize, sizeof(ev));
      entries->push_back(ev);
    }
    return 0;
  }
  return 2;  // 翻了 8 倍还不够，放弃
}

size_t Dbvm::EventEntrySize(uint32_t entryType) {
  switch (entryType) {
    case 0: return sizeof(DbvmPageEvent);                // Basic
    case 1: return sizeof(DbvmPageEvent) + 512;          // + FXSAVE64
    case 2: return sizeof(DbvmPageEvent) + 4096;         // + Stack
    case 3: return sizeof(DbvmPageEvent) + 512 + 4096;   // + FXSAVE64 + Stack
    default: return 0;
  }
}

bool Dbvm::WatchDelete(int id) {
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint32_t id;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallWatchDelete;
  p.id = static_cast<uint32_t>(id);

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_) return false;
  // 本地也把这个 ID 从活动列表里摘掉
  watchIds_.erase(std::remove(watchIds_.begin(), watchIds_.end(), id),
                  watchIds_.end());
  return r == 0;
}

void Dbvm::EptReset() {
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallEptReset;
  Invoke(&p);
  watchIds_.clear();
}

//=============================================================================
//  隐藏（cloak）
//=============================================================================
int Dbvm::CloakActivate(uint64_t pa, uint64_t va, uint64_t mode) {
  (void)va;  // CE 的 va 只用于本端 cloakedregions 列表管理，不进 vmcall
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint64_t physicalBase;
    uint64_t mode;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallCloakActivate;
  p.physicalBase = pa & kPhysPageMask;
  p.mode = mode;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_) return -1;
  if (r == 0) return 0;   // 激活成功
  if (r == 1) return 1;   // 该页已处于隐藏态
  return -1;
}

bool Dbvm::CloakDeactivate(uint64_t pa) {
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint64_t physicalBase;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallCloakDeactivate;
  p.physicalBase = pa & kPhysPageMask;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_) return false;
  return r != 0;  // 与 vmxfunctions.pas 一致：非 0 视为成功
}

size_t Dbvm::CloakReadOriginal(uint64_t pa, void* dst, size_t size) {
  if (dst == nullptr || size < 4096) return 0;
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint64_t physicalBase;
    uint64_t destination;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallCloakReadOriginal;
  p.physicalBase = pa & kPhysPageMask;
  p.destination = reinterpret_cast<uint64_t>(dst);

  const uint64_t r = Invoke(&p);  // 成功 0，失败非 0（ept_cloak_readOriginal）
  if (vmcallFailed_ || r != 0) return 0;
  return 4096;
}

size_t Dbvm::CloakWriteOriginal(uint64_t pa, const void* src, size_t size) {
  if (src == nullptr || size < 4096) return 0;
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint64_t physicalBase;
    uint64_t source;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallCloakWriteOriginal;
  p.physicalBase = pa & kPhysPageMask;
  p.source = reinterpret_cast<uint64_t>(src);

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_ || r != 0) return 0;
  return 4096;
}

bool Dbvm::HideDbvmPhysicalMemory() {
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallHideDbvmPhysicalAddr;
  Invoke(&p);
  return !vmcallFailed_;
}

//=============================================================================
//  破线程表（DBVM 断点冻结的线程）
//=============================================================================
int Dbvm::BrokenThreadCount() {
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallGetBrokenThreadListSize;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_) return 0;
  return static_cast<int>(r);
}

bool Dbvm::GetBrokenThreadShort(int id, DbvmBrokenThreadShort* out) {
  if (out == nullptr) return false;
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    int32_t id;
    int32_t watchid;
    int32_t status;
    uint32_t cs;
    uint64_t rip;
    uint64_t cr3;
    uint64_t fsbase;
    uint64_t gsbase;
    uint64_t gsbaseKernel;
    uint64_t heartbeat;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallGetBrokenThreadShort;
  p.id = id;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_ || r != 0) return false;
  out->watchId = p.watchid;
  out->status = p.status;
  out->cs = p.cs;
  out->rip = p.rip;
  out->cr3 = p.cr3;
  out->fsBase = p.fsbase;
  out->gsBase = p.gsbase;
  out->gsBaseKernel = p.gsbaseKernel;
  out->heartbeat = p.heartbeat;
  return true;
}

bool Dbvm::GetBrokenThreadFull(int id, DbvmPageEvent* event, int* watchId,
                               int* status) {
  // VMCALL_GETBROKENTHREADENTRYFULL 的参数结构 = basic + id + watchid + status
  // + PageEventExtended（basic + 512 字节 fxsave），缓冲较大，放堆上
  // （vmxfunctions.pas dbvm_bp_getBrokenThreadEventFull）。
  struct VmcallFullParam {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    int32_t  id;
    int32_t  watchid;
    int32_t  status;
    uint8_t  state[sizeof(DbvmPageEvent) + 512];
  };
  VmcallFullParam p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallGetBrokenThreadFull;
  p.id = id;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_ || r != 0) return false;
  if (event) std::memcpy(event, p.state, sizeof(DbvmPageEvent));
  if (watchId) *watchId = p.watchid;
  if (status) *status = p.status;
  return true;
}

bool Dbvm::ResumeBrokenThread(int id, int continueMethod) {
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    int32_t id;
    int32_t continueMethod;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallResumeBrokenThread;
  p.id = id;
  p.continueMethod = continueMethod;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_) return false;
  return r == 0;
}

//=============================================================================
//  改寄存器断点 / 命中跟踪
//=============================================================================
int Dbvm::CloakChangeRegOnBp(uint64_t pa, const DbvmChangeRegInfo& info,
                             uint64_t va) {
  (void)va;
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint64_t physicalAddress;
    DbvmChangeRegInfo info;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallCloakChangeRegOnBp;
  p.physicalAddress = pa;
  p.info = info;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_) return -1;
  return static_cast<int>(r);  // 0 = 成功（vmcall.c ept_cloak_changeregonbp）
}

int Dbvm::CloakRemoveChangeRegOnBp(uint64_t pa) {
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint64_t physicalAddress;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallCloakRemoveChangeReg;
  p.physicalAddress = pa;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_) return -1;
  return static_cast<int>(r);
}

int Dbvm::CloakTraceOnBp(uint64_t pa, uint32_t count, uint32_t options,
                         uint64_t va) {
  (void)va;
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint64_t physicalAddress;
    uint32_t flags;
    uint32_t tracecount;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallCloakTraceOnBp;
  p.physicalAddress = pa;
  p.flags = options;
  p.tracecount = count;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_) return -1;
  return static_cast<int>(r);
}

int Dbvm::CloakTraceOnBpStop() {
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallCloakTraceOnBpStop;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_) return -1;
  return static_cast<int>(r);
}

int Dbvm::CloakTraceOnBpRemove(uint64_t pa, bool force) {
  (void)pa;  // CE 的 pa 只用于本端 breakpoints 列表，vmcall 只发 force
  struct {
    uint32_t structsize;
    uint32_t level2pass;
    uint32_t command;
    uint32_t forced;
  } p{};
  p.structsize = sizeof(p);
  p.level2pass = password_.p2;
  p.command = kVmcallCloakTraceOnBpRemove;
  p.forced = force ? 1u : 0u;

  const uint64_t r = Invoke(&p);
  if (vmcallFailed_) return -1;
  return static_cast<int>(r);
}

int Dbvm::CloakTraceOnBpReadLog(std::vector<DbvmPageEvent>* out,
                                uint32_t* missed) {
  if (out == nullptr) return -1;
  out->clear();
  if (missed) *missed = 0;

  std::vector<uint8_t> buf(sizeof(DbvmEventListHead) + 8 * sizeof(DbvmPageEvent), 0);
  for (int attempt = 0; attempt < 8; ++attempt) {
    // 布局 = VMCALL_CLOAK_TRACEONBP_READLOG_PARAM：results/resultsize/copied 全是 QWORD
    // （和 WATCH_RETRIEVELOG 的 DWORD 版本不一样，别混用）
    struct {
      uint32_t structsize;
      uint32_t level2pass;
      uint32_t command;
      uint64_t results;
      uint64_t resultsize;
      uint64_t copied;
    } p{};
    p.structsize = sizeof(p);
    p.level2pass = password_.p2;
    p.command = kVmcallCloakTraceOnBpReadLog;
    p.results = reinterpret_cast<uint64_t>(buf.data());
    p.resultsize = static_cast<uint32_t>(buf.size());
    p.copied = 0;

    const uint64_t r = Invoke(&p);
    if (vmcallFailed_) return -1;
    if (r == 2) {
      buf.assign(std::max<size_t>(buf.size() * 2, p.resultsize), 0);
      continue;
    }
    if (r != 0) return static_cast<int>(r);

    DbvmEventListHead head{};
    std::memcpy(&head, buf.data(), sizeof(head));
    if (missed) *missed = head.missedEntries;

    const size_t entrySize = EventEntrySize(head.entryType);
    if (entrySize == 0) return -1;
    const size_t maxEntries = (buf.size() - sizeof(DbvmEventListHead)) / entrySize;
    const size_t n = std::min<size_t>(head.numberOfEntries, maxEntries);

    out->reserve(n);
    const uint8_t* pEvent = buf.data() + sizeof(DbvmEventListHead);
    for (size_t i = 0; i < n; ++i) {
      DbvmPageEvent ev{};
      std::memcpy(&ev, pEvent + i * entrySize, sizeof(ev));
      out->push_back(ev);
    }
    return 0;
  }
  return 2;
}

//=============================================================================
//  内部 vmcall 执行
//=============================================================================
uint64_t Dbvm::Invoke(void* paramBlock) {
  return InvokeRaw(paramBlock, nullptr);
}

uint64_t Dbvm::InvokeRaw(void* paramBlock, uint64_t* secondaryOut) {
  Lock();
  vmcallResult_ = 0;
  vmcallFailed_ = true;
  if (secondaryOut) *secondaryOut = 0;

  if (InitThunk() && CpuSupportsVmcall()) {
    uint64_t sec = 0;
    bool ud = true;
    vmcallResult_ = CallVmcall(paramBlock, password_.p1, password_.p3, &sec, &ud);
    vmcallFailed_ = ud;
    if (secondaryOut) *secondaryOut = sec;
  }
  Unlock();
  return vmcallResult_;
}

std::vector<int> Dbvm::ActiveWatchIds() const { return watchIds_; }

//---------------------------------------------------------------------------
//  DbvmCapable()：界面用的便捷判断（对应 CE 的 isDBVMCapable）
//  只查 CPU 能力（VMX/SVM 标志），不去动 vmcall —— 探测 DBVM 是否真正
//  在场请调用 Detect()。
//---------------------------------------------------------------------------
bool DbvmCapable() { return Dbvm::CpuSupportsVmcall(); }

#pragma pack(pop)

}  // namespace ce
