// ============================================================================
//  dbvm_bp_target.cpp —— DBVM 断点测试的目标进程
//
//  · 一个工作线程在死循环里不停 ++ g_counter（典型"改一个变量"场景）；
//  · 通过 stdout 以行格式握手，把自身的关键地址送给测试器：
//        DBVM_TEST_READY
//        DBVM_TEST_COUNTER=0x<地址>     ← g_counter 的虚拟地址
//        DBVM_TEST_FUNC=0x<地址>        ← HotLoop（我们下 DBVM 断点的代码）
//  · 之后永远跑下去，直到测试器把它终止。
// ============================================================================
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <cstdint>

// 全局计数器：测试器用 ReadProcessMemory 读它，判断"是否还走得动"
static volatile uint64_t g_counter = 0;

// 我们不 inline / 不优化掉：DBVM 断点要作用在这段代码上
__declspec(noinline) static void HotLoop() {
  for (;;) { g_counter += 1; }
}

static DWORD WINAPI Worker(LPVOID) {
  HotLoop();
  return 0;
}

int main() {
  printf("DBVM_TEST_READY\n");
  printf("DBVM_TEST_COUNTER=0x%llx\n", (unsigned long long)&g_counter);
  printf("DBVM_TEST_FUNC=0x%llx\n", (unsigned long long)&HotLoop);
  fflush(stdout);

  HANDLE h = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
  if (!h) return 3;

  // 主线程占住，保持进程在；工作线程负责 ++
  for (;;) Sleep(1000);
}