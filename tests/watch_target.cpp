// ============================================================================
//  watch_target.cpp —— "谁访问 / 谁写入" 测试目标程序
//
//  用途：造一个被多条"不同指令"读写的值，供 CEScanVC 的
//        「查找访问此地址的内容 / 查找写入此地址的内容」验证用。
//
//  设计要点：
//   1) 被监视的值独占一整页（VirtualAlloc），页守卫只覆盖它一个变量，
//      不会把同页其它全局变量也算成命中（CE 的 bpmException 模式同理）。
//   2) 5 条互不相同的指令访问它：ReadA / ReadB / ReadC（读） + WriteA / WriteB（写），
//      全部 __declspec(noinline)，保证反汇编里是 5 个不同地址。
//   3) 另起一个工作线程读同一个值，用来验证多线程下也能抓到。
//
//  编译（与主工程同一套便携 MSVC）：
//     cl /nologo /O2 /MT /utf-8 /EHsc tests\watch_target.cpp /Fe:bin\watch_target.exe
// ============================================================================
#include <windows.h>
#include <stdio.h>

static volatile long* g_p = nullptr;   // 指向独占一页的被监视值

//--- 3 条不同的"读"指令 ------------------------------------------------
__declspec(noinline) long ReadA() { return *g_p + 1; }
__declspec(noinline) long ReadB() { return *g_p * 3 - 2; }
__declspec(noinline) long ReadC() { return *g_p ^ 0x5A5A; }

//--- 2 条不同的"写"指令 ------------------------------------------------
__declspec(noinline) void WriteA(long v) { *g_p = v; }
__declspec(noinline) void WriteB(long v) { *g_p = v + 7; }

//--- 工作线程：再多一个访问点（ReadB 被两个线程同时调用）----------------
static DWORD WINAPI Worker(LPVOID) {
  for (;;) {
    volatile long t = ReadB();
    (void)t;
    ::Sleep(1);
  }
}

int main() {
  void* page = ::VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
  if (!page) { printf("VirtualAlloc 失败\n"); return 1; }
  g_p = (volatile long*)page;
  *g_p = 100;

  printf("PID=%lu\n", (unsigned long)::GetCurrentProcessId());
  printf("ADDR=%p\n", (const void*)g_p);
  printf("被监视值独占 1 页；读写它的指令共 5 条(3 读 + 2 写)，另有 1 个工作线程\n");
  ::fflush(stdout);

  ::CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);

  long i = 0;
  for (;;) {
    WriteA(i);          // 写入指令 1
    (void)ReadA();      // 读取指令 1
    (void)ReadB();      // 读取指令 2
    (void)ReadC();      // 读取指令 3
    WriteB(i);          // 写入指令 2
    ++i;
    ::Sleep(2);
  }
}
