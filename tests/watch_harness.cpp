// ============================================================================
//  watch_harness.cpp —— 用 CEScanVC 自己的调试引擎跑「谁访问 / 谁写入」验证
//
//  这是一个控制台程序，直接复用主工程的 Debugger / Disasm 引擎，不需要 GUI，
//  方便自动化回归：附加目标 → 下监视 → 收集 N 秒 → 按 CE 那样"计数 | 指令"汇总。
//
//  用法：
//     watchtest.exe <pid> <地址(十六进制)> <access|write> [秒数]
//  例：
//     watchtest.exe 1234 1F0000 access 5
//
//  链接（复用主工程已编译的 obj，除 main_gui.obj）：
//     link /OUT:bin\watchtest.exe /SUBSYSTEM:CONSOLE ...
//          obj\watch_harness.obj obj\CETypes.obj obj\CEUtil.obj obj\ProcessMemory.obj
//          obj\RegionFilter.obj obj\PatternScan.obj obj\ScanEngine.obj
//          obj\Disasm.obj obj\Debugger.obj psapi.lib
// ============================================================================
#include "../include/Debugger.h"
#include "../include/Disasm.h"

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <map>
#include <vector>
#include <string>
#include <mutex>

using namespace ce;

//-----------------------------------------------------------------------------
//  命中聚合（等价于 CE TFoundCodeDialog 的 Count | Instruction 两列）
//-----------------------------------------------------------------------------
struct Agg {
  int         count = 0;
  std::string text;
  std::string module;
  DWORD       tid = 0;
  bool        write = false;
};

static std::mutex          g_mtx;
static std::map<ptruint, Agg> g_agg;      // RIP -> 聚合
static std::vector<std::pair<ptruint, DWORD>> g_order;   // 首次出现顺序

static HANDLE g_proc = nullptr;
static bool   g_watchWrite = false;
static volatile long g_events = 0;      // 收到的事件数（诊断用）
static bool   g_verbose = false;

// 打印目标页当前保护（诊断用：确认守卫真的挂上了）
static void DumpProtection(ptruint addr) {
  MEMORY_BASIC_INFORMATION mbi{};
  if (::VirtualQueryEx(g_proc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
    printf("   [诊断] 页 %016llX 保护 = 0x%08X (%s)\n",
           (unsigned long long)(ptruint)mbi.BaseAddress, (unsigned)mbi.Protect,
           mbi.Protect == PAGE_NOACCESS ? "PAGE_NOACCESS=已挂守卫" :
           mbi.Protect == PAGE_EXECUTE_READ ? "PAGE_EXECUTE_READ=已挂写守卫" :
           mbi.Protect == PAGE_READWRITE ? "PAGE_READWRITE=未挂守卫" : "其它");
  } else {
    printf("   [诊断] VirtualQueryEx 失败 (%lu)\n", (unsigned long)::GetLastError());
  }
}


// 读目标内存里的指令字节并反汇编成一行文本
static void FillDisasm(HitReport& h) {
  if (!g_proc) return;
  ubyte code[16] = {};
  SIZE_T got = 0;
  if (!::ReadProcessMemory(g_proc, (LPCVOID)h.rip, code, sizeof(code), &got) || !got) return;
  DisasmResult dr;
  Disassemble(code, (size_t)got, h.rip, &dr);
  h.disasm = dr.text;
  h.bytes.assign(code, code + (dr.length > 0 ? dr.length : 1));
}

static void OnHit(const HitReport& hit) {
  std::lock_guard<std::mutex> lk(g_mtx);
  auto it = g_agg.find(hit.rip);
  if (it == g_agg.end()) {
    Agg a;
    a.count = 1;
    a.tid = hit.tid;
    a.write = (hit.kind == BpKind::Write || hit.kind == BpKind::HardwareWrite);
    HitReport h2 = hit;
    FillDisasm(h2);
    a.text = h2.disasm;
    if (a.text.empty()) a.text = "(反汇编失败)";
    char b[8];
    for (size_t i = 0; i < h2.bytes.size() && i < 8; ++i) {
      snprintf(b, sizeof(b), "%02X ", h2.bytes[i]);
      a.module += b;
    }
    g_agg[hit.rip] = a;
    g_order.push_back({hit.rip, hit.tid});
    printf("  [命中] #%-3zu TID %-6u %s  %016llX  %-32s 字节 %s\n",
           g_order.size(), hit.tid,
           a.write ? "写入" : "访问", (unsigned long long)hit.rip,
           a.text.c_str(), a.module.c_str());
  } else {
    it->second.count++;
  }
  ::fflush(stdout);
}

int main(int argc, char** argv) {
  ::setvbuf(stdout, nullptr, _IONBF, 0);   // 关掉缓冲，崩溃前也能看到全部输出
  if (argc < 4) {
    printf("用法: watchtest <pid> <地址(hex)> <access|write> [秒数]\n");
    return 2;
  }
  const DWORD pid = (DWORD)strtoul(argv[1], nullptr, 10);
  const ptruint addr = (ptruint)_strtoui64(argv[2], nullptr, 16);
  g_watchWrite = (strcmp(argv[3], "write") == 0);
  const int secs = argc > 4 ? atoi(argv[4]) : 5;
  g_verbose = true;

  g_proc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!g_proc) { printf("OpenProcess 失败\n"); return 1; }

  printf("=== CEScanVC 监视验证 ===\n");
  printf("目标 PID = %lu   监视地址 = %016llX   模式 = %s   收集 %d 秒\n",
         (unsigned long)pid, (unsigned long long)addr,
         g_watchWrite ? "谁写入" : "谁访问(读+写)", secs);

  Debugger dbg;
  dbg.SetHitCallback(OnHit);
  dbg.SetEventCallback([](const DEBUG_EVENT& ev) {
    ++g_events;
    if (!g_verbose) return;
    if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
      printf("   [事件] EXCEPTION TID %u code=0x%08X addr=%016llX\n",
             ev.dwThreadId, ev.u.Exception.ExceptionRecord.ExceptionCode,
             (unsigned long long)(ptruint)ev.u.Exception.ExceptionRecord.ExceptionAddress);
      ::fflush(stdout);
    }
  });
  std::string err;
  if (!dbg.Attach(pid, &err)) { printf("附加失败: %s\n", err.c_str()); return 1; }
  printf("已附加（调试器已载入，等价 CE 的 startdebuggerifneeded(true)）\n");

  ::Sleep(300);

  const bool seq = (strcmp(argv[3], "seq") == 0);
  if (seq) {
    // —— 复现 GUI 的操作顺序：先「谁访问」→ 停止 → 再「谁写入」同一调试会话，
    //    专门验证 StopFind 是否真把上一次的页面守卫摘干净。
    //    若没摘干净，第二次（写入）会把「读」指令也算进来。 ——
    dbg.FindWhatAccesses(addr, &err);
    if (!err.empty()) { printf("下监视(访问)失败: %s\n", err.c_str()); return 1; }
    DumpProtection(addr);
    printf("【阶段1 谁访问】收集中...\n\n");
    ::Sleep(secs * 1000);
    dbg.StopFind();
    ::Sleep(300);
    printf("【阶段1 结束】已 StopFind；下面复用同一调试会话开「谁写入」\n");
    {
      std::lock_guard<std::mutex> lk(g_mtx);
      g_agg.clear();
      g_order.clear();
    }
    g_watchWrite = true;
    dbg.FindWhatWrites(addr, &err);
    if (!err.empty()) { printf("下监视(写入)失败: %s\n", err.c_str()); return 1; }
    DumpProtection(addr);
    printf("【阶段2 谁写入】收集中...\n\n");
    ::Sleep(secs * 1000);
  } else {
    if (g_watchWrite) dbg.FindWhatWrites(addr, &err);
    else              dbg.FindWhatAccesses(addr, &err);
    if (!err.empty()) { printf("下监视失败: %s\n", err.c_str()); return 1; }
    DumpProtection(addr);
    printf("已下监视，开始收集...\n\n");
    ::Sleep(secs * 1000);
  }

  dbg.StopFind();
  dbg.Detach();
  ::CloseHandle(g_proc);

  // ---- 输出 CE 式汇总（计数 | 指令）----
  printf("\n=== 汇总：以下操作码%s了 %016llX ===\n",
         g_watchWrite ? "写入" : "访问", (unsigned long long)addr);
  printf("%-6s  %-20s  %-6s  %s\n", "计数", "指令地址", "线程", "指令");
  printf("------  --------------------  ------  ----------------------------------\n");
  std::lock_guard<std::mutex> lk(g_mtx);
  for (auto& kv : g_order) {
    auto& a = g_agg[kv.first];
    printf("%-6d  %016llX  %-6u  %s\n", a.count, (unsigned long long)kv.first,
           a.tid, a.text.c_str());
  }
  int reads = 0, writes = 0;
  for (auto& kv : g_agg) (kv.second.write ? writes : reads)++;
  size_t total = 0;
  for (auto& kv : g_agg) total += kv.second.count;
  printf("\n共 %zu 条不同指令（读 %d / 写 %d），总命中 %zu 次；调试事件 %ld 个\n",
         g_agg.size(), reads, writes, total, g_events);
  return 0;
}
