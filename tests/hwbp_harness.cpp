// ============================================================================
//  hwbp_harness.cpp —— 硬件访问断点（WinDbg 的 ba r1 / ba w4）全自动回归
//
//  这是「线程定位」功能的引擎级验证：窗口只是壳，真正决定能不能抓到线程的
//  是 Debugger 往目标线程 DR0-DR3/DR7 里写的位对不对、命中判定读的位对不对。
//
//  流程（对标手工在 WinDbg 里做的事）：
//    1) 起 bin\hwbp_target.exe，读它的 PID / CODE / DATA / TID_MAIN / TID_A / TID_B
//    2) 附加；阶段1：对 CODE 下 HardwareRW(长度 1) —— 等价 `ba r1 <代码地址>`
//       断言：命中线程 == {TID_MAIN, TID_A}，且**绝不含** TID_B
//    3) RemoveBp(CODE)，再收 1 秒：断言不再产生新命中
//       （验证"停止定位"把 DR 从目标线程上真摘掉了，而不是只删了表项）
//    4) 阶段2：对 DATA 下 HardwareWrite(长度 4) —— 等价 `ba w4 <数据地址>`
//       断言：命中线程 == {TID_B}，且**绝不含** TID_MAIN / TID_A
//       （读者误报 = DR7 的 R/W 位没写成"只写"，会把 HardwareWrite 退化成读写）
//    5) RemoveBp(DATA)，收 1 秒断言无新命中 → 分离 → 结束目标
//
//  用法：  bin\hwbptest.exe [每阶段秒数，默认 3]
//  退出码：0 全通过；1 有断言失败；2 环境错误
// ============================================================================
#include "../include/Debugger.h"
#include "../include/Disasm.h"

#include <windows.h>
#include <psapi.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace ce;

//---------------------------------------------------------------------------
//  命中收集（debug 线程写 / 主线程读）
//---------------------------------------------------------------------------
static std::mutex g_mtx;
static std::map<std::pair<DWORD, ptruint>, int> g_hits;   // (tid, rip) -> 次数
static long g_total = 0;

static void OnHit(const HitReport& h) {
  std::lock_guard<std::mutex> lk(g_mtx);
  ++g_hits[std::make_pair((DWORD)h.tid, h.rip)];
  ++g_total;
}

static void ResetHits() {
  std::lock_guard<std::mutex> lk(g_mtx);
  g_hits.clear();
  g_total = 0;
}

static std::set<DWORD> HitTids() {
  std::lock_guard<std::mutex> lk(g_mtx);
  std::set<DWORD> s;
  for (auto& kv : g_hits) s.insert(kv.first.first);
  return s;
}

static void DumpHits(const char* title) {
  std::lock_guard<std::mutex> lk(g_mtx);
  printf("  %s：%zu 组(线程,RIP)，合计 %ld 次\n", title, g_hits.size(), g_total);
  int shown = 0;
  for (auto& kv : g_hits) {
    printf("      TID %-6u  RIP %016llX  次数 %d\n", kv.first.first,
           (unsigned long long)kv.first.second, kv.second);
    if (++shown >= 12) { printf("      ...\n"); break; }
  }
}

static std::string TidSetStr(const std::set<DWORD>& s) {
  std::string out;
  char b[32];
  for (DWORD t : s) {
    snprintf(b, sizeof(b), "%u ", t);
    out += b;
  }
  return out.empty() ? "(空)" : out;
}

static bool g_ok = true;
static void Expect(bool cond, const char* what) {
  printf("  [%s] %s\n", cond ? " OK " : "FAIL", what);
  if (!cond) g_ok = false;
}

//---------------------------------------------------------------------------
//  启动靶子并读取它自报的信息
//---------------------------------------------------------------------------
struct TargetInfo {
  DWORD   pid = 0;
  ptruint code = 0, data = 0;
  DWORD   tidMain = 0, tidA = 0, tidB = 0;
};

static FILE* g_targetPipe = nullptr;

static bool StartTarget(TargetInfo* ti) {
  g_targetPipe = _popen("bin\\hwbp_target.exe", "r");
  if (!g_targetPipe) return false;
  char line[512];
  int got = 0;
  for (int i = 0; i < 40 && fgets(line, sizeof(line), g_targetPipe); ++i) {
    unsigned long long u = 0;
    if (sscanf(line, "PID=%lu", &ti->pid) == 1) { ++got; continue; }
    if (sscanf(line, "CODE=%llX", &u) == 1) { ti->code = (ptruint)u; ++got; continue; }
    if (sscanf(line, "DATA=%llX", &u) == 1) { ti->data = (ptruint)u; ++got; continue; }
    if (sscanf(line, "TID_MAIN=%lu", &ti->tidMain) == 1) { ++got; continue; }
    if (sscanf(line, "TID_A=%lu", &ti->tidA) == 1) { ++got; continue; }
    if (sscanf(line, "TID_B=%lu", &ti->tidB) == 1) { ++got; continue; }
    if (strncmp(line, "READY", 5) == 0) break;
  }
  return got >= 6 && ti->pid && ti->code && ti->data;
}

static void KillTarget(DWORD pid) {
  if (pid) {
    char cmd[96];
    snprintf(cmd, sizeof(cmd), "taskkill /F /PID %lu >nul 2>&1", (unsigned long)pid);
    system(cmd);
  }
  if (g_targetPipe) { _pclose(g_targetPipe); g_targetPipe = nullptr; }
}

//---------------------------------------------------------------------------
int main(int argc, char** argv) {
  ::setvbuf(stdout, nullptr, _IONBF, 0);
  const int secs = argc > 1 ? atoi(argv[1]) : 3;
  const int ms = (secs > 0 ? secs : 3) * 1000;

  printf("=== 硬件访问断点（线程定位引擎）回归 ===\n\n");
  TargetInfo ti;
  if (!StartTarget(&ti)) {
    printf("启动靶子失败（bin\\hwbp_target.exe 在吗？）\n");
    KillTarget(0);
    return 2;
  }
  printf("靶子 PID=%lu  CODE=%016llX  DATA=%016llX\n", (unsigned long)ti.pid,
         (unsigned long long)ti.code, (unsigned long long)ti.data);
  printf("      TID_MAIN=%lu  TID_A(读)=%lu  TID_B(写)=%lu\n\n",
         (unsigned long)ti.tidMain, (unsigned long)ti.tidA, (unsigned long)ti.tidB);

  Debugger dbg;
  dbg.SetHitCallback(OnHit);
  std::string err;
  if (!dbg.Attach(ti.pid, &err)) {
    printf("附加失败：%s\n", err.c_str());
    KillTarget(ti.pid);
    return 2;
  }
  ::Sleep(400);

  // ---------------- 阶段 1：ba r1 @ 代码 ----------------
  printf("--- 阶段1：对 CODE 下 HardwareRW 长度1（等价 ba r1）---\n");
  ResetHits();
  int applied = 0;
  if (!dbg.SetHardware(ti.code, BpKind::HardwareRW, &err, 1, &applied)) {
    printf("下断失败：%s\n", err.c_str());
    dbg.Detach();
    KillTarget(ti.pid);
    return 2;
  }
  printf("  DR 已写入 %d 个线程\n", applied);
  Expect(applied >= 3, "DR 至少写进了主线程 + A + B 三个线程（含附加前就存在的线程）");
  ::Sleep(ms);
  DumpHits("阶段1 命中");
  {
    const std::set<DWORD> tids = HitTids();
    printf("  命中线程集合：%s\n", TidSetStr(tids).c_str());
    Expect(tids.count(ti.tidMain) > 0, "抓到读代码的主线程");
    Expect(tids.count(ti.tidA) > 0, "抓到读代码的线程 A");
    Expect(tids.count(ti.tidB) == 0, "没有误报从不读代码的线程 B");
  }

  // ---------------- 阶段 2：RemoveBp 后必须彻底安静 ----------------
  printf("\n--- 阶段2：RemoveBp(CODE) 后应收不到任何新命中 ---\n");
  dbg.RemoveBp(ti.code);
  ResetHits();
  ::Sleep(1000);
  {
    std::lock_guard<std::mutex> lk(g_mtx);
    const long n = g_total;
    printf("  摘断点后 1 秒内的命中数：%ld\n", n);
    Expect(n == 0, "RemoveBp 把 DR 从目标线程上真摘掉了（否则每次访问仍会产生单步异常）");
  }

  // ---------------- 阶段 3：ba w4 @ 数据 ----------------
  printf("\n--- 阶段3：对 DATA 下 HardwareWrite 长度4（等价 ba w4）---\n");
  ResetHits();
  applied = 0;
  if (!dbg.SetHardware(ti.data, BpKind::HardwareWrite, &err, 4, &applied)) {
    printf("下断失败：%s\n", err.c_str());
    dbg.Detach();
    KillTarget(ti.pid);
    return 2;
  }
  printf("  DR 已写入 %d 个线程\n", applied);
  ::Sleep(ms);
  DumpHits("阶段3 命中");
  {
    const std::set<DWORD> tids = HitTids();
    printf("  命中线程集合：%s\n", TidSetStr(tids).c_str());
    Expect(tids.count(ti.tidB) > 0, "抓到写数据的线程 B");
    Expect(tids.count(ti.tidA) == 0, "没有误报纯读数据的线程 A（R/W 位写成了只写，没退化成读写）");
    Expect(tids.count(ti.tidMain) == 0, "没有误报纯读数据的主线程");
  }

  // ---------------- 阶段 4：收尾 ----------------
  printf("\n--- 阶段4：摘除并分离 ---\n");
  dbg.RemoveBp(ti.data);
  ResetHits();
  ::Sleep(800);
  {
    std::lock_guard<std::mutex> lk(g_mtx);
    printf("  摘断点后 0.8 秒内的命中数：%ld\n", g_total);
    Expect(g_total == 0, "第二个断点也摘干净了");
  }
  dbg.Detach();
  ::Sleep(300);
  KillTarget(ti.pid);

  printf("\n=== 结论：%s ===\n", g_ok ? "全部通过" : "存在失败项");
  return g_ok ? 0 : 1;
}
