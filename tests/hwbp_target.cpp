// ============================================================================
//  hwbp_target.cpp —— 硬件访问断点（WinDbg 的 ba r1 / ba w4）验证靶子
//
//  刻意造出两组"可区分"的访问：
//    1) 一段代码（MarkedFunc 的首字节）被「主线程 + 读线程 A」反复读取；
//       线程 B 从不读它。
//       → 验证 ba r1：能抓到读它的线程，抓不到不读它的 B。
//    2) 一个 4 字节数据（g_data）被「写线程 B」反复写入，同时被
//       「主线程 + 读线程 A」反复读取。
//       → 验证 ba w4：只抓写者 B，**不能**抓纯读者。
//         （如果 DR7 的 R/W 位被写成"读写"而不是"只写"，读者就会误报——
//           这条断言专门卡这个）
//
//  自带 PID / 地址 / TID 输出，配合 hwbp_harness.cpp 做全自动断言。
//
//  编译：cl /nologo /O2 /MT /utf-8 /EHsc tests\hwbp_target.cpp /Fe:bin\hwbp_target.exe
// ============================================================================
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

// 被"读代码"的靶子函数：不调用它，只读它的首字节
__declspec(noinline) int MarkedFunc(int x) { return x * 3 + 1; }

static volatile LONG g_data = 0;    // 4 字节；DR 长度断点要求按长度对齐
static volatile LONG g_sink = 0;    // 只为了让上面的读写不被优化掉
static DWORD g_tidA = 0, g_tidB = 0;

// 读代码首字节：用 volatile 指针强制产生一条真实的内存读指令。
// 这与"反作弊去校验函数首字节有没有被改"是同一种访问。
static unsigned char ReadCodeByte() {
  volatile unsigned char* p = (volatile unsigned char*)(uintptr_t)&MarkedFunc;
  return *p;
}

// 读线程：读代码 + 读数据（它是 g_data 的纯读者，写断点绝不能抓到它）
static DWORD WINAPI ReaderA(LPVOID) {
  unsigned acc = 0;
  for (;;) {
    acc += ReadCodeByte();
    acc += (unsigned)g_data;
    g_sink = (LONG)acc;
    ::Sleep(1);
  }
}

// 写线程：只写数据，绝不碰代码（它是唯一合法的写断点命中者）
static DWORD WINAPI WriterB(LPVOID) {
  LONG v = 0;
  for (;;) {
    g_data = ++v;
    ::Sleep(2);
  }
}

int main() {
  ::setvbuf(stdout, nullptr, _IONBF, 0);
  (void)ReadCodeByte();   // 先触发一次，确保代码页已驻留
  g_sink = 0;

  printf("PID=%lu\n", (unsigned long)::GetCurrentProcessId());
  printf("CODE=%llX\n", (unsigned long long)(uintptr_t)&MarkedFunc);
  printf("DATA=%llX\n", (unsigned long long)(uintptr_t)&g_data);
  printf("TID_MAIN=%lu\n", (unsigned long)::GetCurrentThreadId());
  ::CreateThread(nullptr, 0, ReaderA, nullptr, 0, &g_tidA);
  ::CreateThread(nullptr, 0, WriterB, nullptr, 0, &g_tidB);
  printf("TID_A=%lu\n", (unsigned long)g_tidA);
  printf("TID_B=%lu\n", (unsigned long)g_tidB);
  printf("READY\n");

  for (;;) {   // 主线程：既读代码也读数据（两个都不是它的"写"行为）
    g_sink += ReadCodeByte();
    g_sink += (LONG)g_data;
    ::Sleep(1);
  }
}
