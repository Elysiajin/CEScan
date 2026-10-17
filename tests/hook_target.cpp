// ============================================================================
//  hook_target.cpp —— 给「VM/HOOK 还原字节自动查找」用的靶子进程
//
//  它做的事情，就是《VM还原档案》里描述的那种 VM HOOK：
//    ① 一段"原始函数"的头 5 字节是  55 8B EC 6A FF
//       （push ebp / mov ebp,esp / push -1，经典编译序言）
//    ② 有人把这 5 字节换成了 E9 xx xx xx xx（跳到 VM/蹦床区）
//    ③ VM 区跑完垃圾指令后，把被偷走的 5 字节"还原执行"一遍，再 jmp 回原函数 +5
//
//  这样我们的分析器就应该能把 55 8B EC 6A FF 自动找回来。
//
//  两个用例：
//    用例一 HOOK1：5 字节 jmp，蹦床紧贴还原代码 —— 而且真的可执行（端到端）
//    用例二 HOOK2：5 字节 jmp + 2 字节 NOP 填充（共 7 字节），
//                  对应档案 2/2.txt「一共 HOOK 了 7 个字节…跳回的地址就是 A+7」
//
//  另外还保留一个"独占一页的数据值"，供 GUI 的「谁访问了这个值」流程使用。
// ============================================================================
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

static unsigned char* g_page1 = nullptr;   // F1 所在页（可执行）
static unsigned char* g_tramp1 = nullptr;
static unsigned char* g_page2 = nullptr;   // F2 所在页（只当数据用，不执行）
static unsigned char* g_tramp2 = nullptr;
static unsigned char* g_page3 = nullptr;   // F3 所在页（可执行）
static unsigned char* g_tramp3 = nullptr;

// --- 扩充场景 ---
static unsigned char* g_page4  = nullptr;  // F4：多级回溯（档案 3/1.txt）
static unsigned char* g_trampD1 = nullptr; // 一级 handler（跳回 F4+5）
static unsigned char* g_trampD2 = nullptr; // 上游 handler（call 一级入口）
static unsigned char* g_page5  = nullptr;  // F5：CALL 型 VM（档案 2 方法三）
static unsigned char* g_tramp5 = nullptr;
static unsigned char* g_page6  = nullptr;  // F6：FF25 间接跳转
static unsigned char* g_tramp6 = nullptr;
static unsigned char* g_slot6  = nullptr;  // FF25 的目标指针槽

static unsigned char* AllocPage(DWORD prot) {
  return (unsigned char*)::VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, prot);
}

// 把 tramp 里那条"跳回 resume"的 jmp rel32 补好
static void EmitJmpBack(unsigned char* tramp, size_t at, unsigned char* resume) {
  tramp[at] = 0xE9;
  int rel = (int)((long long)resume - (long long)(tramp + at + 5));
  std::memcpy(tramp + at + 1, &rel, 4);
}

// 在 hook 处写入 5 字节 jmp rel32
static void EmitHook(unsigned char* site, unsigned char* target) {
  DWORD old = 0;
  ::VirtualProtect(site, 16, PAGE_EXECUTE_READWRITE, &old);
  site[0] = 0xE9;
  int rel = (int)((long long)target - (long long)(site + 5));
  std::memcpy(site + 1, &rel, 4);
  ::FlushInstructionCache(::GetCurrentProcess(), site, 16);
  ::VirtualProtect(site, 16, old, &old);
}

// ---------------------------------------------------------------------------
//  用例一：可执行的 5 字节 HOOK
// ---------------------------------------------------------------------------
static void BuildHook1() {
  g_page1 = AllocPage(PAGE_EXECUTE_READWRITE);
  g_tramp1 = AllocPage(PAGE_EXECUTE_READWRITE);
  unsigned char* f = g_page1;

  // ---- 原始函数（头 5 字节必须正好是 55 8B EC 6A FF）----
  size_t o = 0;
  f[o++] = 0x55;                      // push rbp        (= push ebp)
  f[o++] = 0x8B; f[o++] = 0xEC;       // mov ebp, esp
  f[o++] = 0x6A; f[o++] = 0xFF;       // push -1
  // 之后把上面两个 push 撤掉并正确返回（x64 下手写）
  f[o++] = 0x48; f[o++] = 0x89; f[o++] = 0xE5;          // mov rbp, rsp
  f[o++] = 0x48; f[o++] = 0x89; f[o++] = 0xEC;          // mov rsp, rbp
  f[o++] = 0x48; f[o++] = 0x83; f[o++] = 0xC4; f[o++] = 0x08;  // add rsp, 8
  f[o++] = 0x5D;                      // pop rbp
  f[o++] = 0xC3;                      // ret

  // ---- 蹦床（VM 区）：垃圾 → 还原代码 → 跳回 F1+5 ----
  size_t t = 0;
  for (int i = 0; i < 5; ++i) g_tramp1[t++] = 0x90;     // VM 垃圾
  const unsigned char restore[5] = {0x55, 0x8B, 0xEC, 0x6A, 0xFF};
  std::memcpy(g_tramp1 + t, restore, 5); t += 5;        // ← 还原代码，紧贴跳回指令
  EmitJmpBack(g_tramp1, t, f + 5);                      // jmp F1+5

  ::FlushInstructionCache(::GetCurrentProcess(), f, 4096);
  ::FlushInstructionCache(::GetCurrentProcess(), g_tramp1, 4096);
  ::VirtualProtect(g_page1, 4096, PAGE_EXECUTE_READ, nullptr);
  ::VirtualProtect(g_tramp1, 4096, PAGE_EXECUTE_READ, nullptr);

  EmitHook(f, g_tramp1);              // 打上 HOOK（5 字节）
}

// ---------------------------------------------------------------------------
//  用例二：5 字节 jmp + 2 字节 NOP = 共 7 字节（档案 2/2.txt 的形态）
// ---------------------------------------------------------------------------
static void BuildHook2() {
  g_page2 = AllocPage(PAGE_EXECUTE_READWRITE);
  g_tramp2 = AllocPage(PAGE_EXECUTE_READWRITE);
  unsigned char* f = g_page2;

  // 原始 7 字节：55 8B EC 6A FF 90 90
  size_t o = 0;
  f[o++] = 0x55;
  f[o++] = 0x8B; f[o++] = 0xEC;
  f[o++] = 0x6A; f[o++] = 0xFF;
  f[o++] = 0x90; f[o++] = 0x90;

  size_t t = 0;
  for (int i = 0; i < 5; ++i) g_tramp2[t++] = 0x90;     // VM 垃圾
  const unsigned char restore[7] = {0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x90, 0x90};
  std::memcpy(g_tramp2 + t, restore, 7); t += 7;        // ← 还原代码（7 字节）
  EmitJmpBack(g_tramp2, t, f + 7);                      // jmp F2+7（跳过 NOP 填充）

  ::VirtualProtect(g_page2, 4096, PAGE_EXECUTE_READ, nullptr);
  ::VirtualProtect(g_tramp2, 4096, PAGE_EXECUTE_READ, nullptr);

  EmitHook(f, g_tramp2);
  // 补上档案里的 2 字节 NOP 填充：看起来像 HOOK 了 7 字节
  DWORD old = 0;
  ::VirtualProtect(f, 16, PAGE_EXECUTE_READWRITE, &old);
  f[5] = 0x90; f[6] = 0x90;
  ::FlushInstructionCache(::GetCurrentProcess(), f, 16);
  ::VirtualProtect(f, 16, old, &old);
}

// ---------------------------------------------------------------------------
//  用例三：写入数据值的整条指令被搬进蹦床 ——
//  「谁写入了这个值」命中的指令落在 VM 区里（档案教程的实际场景），
//  分析器必须能从柱内命中反推出 HOOK 入口并还原字节。
//    原始12字节: 50 | A3 vp64 | 58 | C3   (push rax / mov [vp绝对地址],eax / pop rax / ret)
//    HOOK 10字节: E9 rel32 + 90×5         (正好覆盖 push + A3)
//    蹦床      : 垃圾×5 + 50 A3 vp64 (10字节) + jmp F3+10
//  注：x64 下 89 05 disp32 是 RIP 相对寻址，不能用绝对地址；A3 moffs64 才是绝对写。
// ---------------------------------------------------------------------------
static unsigned char* g_vp = nullptr;      // 数据值页（写入目标）

static void BuildHook3(unsigned char* vp) {
  g_vp = vp;
  g_page3 = AllocPage(PAGE_EXECUTE_READWRITE);
  g_tramp3 = AllocPage(PAGE_EXECUTE_READWRITE);
  unsigned char* f = g_page3;
  const uint64_t a64 = (uint64_t)(uintptr_t)vp;

  size_t o = 0;
  f[o++] = 0x50;                                   // push rax
  f[o++] = 0xA3;                                   // mov [vp], eax（绝对地址）
  std::memcpy(f + o, &a64, 8); o += 8;
  f[o++] = 0x58;                                   // pop rax
  f[o++] = 0xC3;                                   // ret

  size_t t = 0;
  for (int i = 0; i < 5; ++i) g_tramp3[t++] = 0x90;      // VM 垃圾
  g_tramp3[t++] = 0x50;                                   // ← 还原代码 10 字节
  g_tramp3[t++] = 0xA3;
  std::memcpy(g_tramp3 + t, &a64, 8); t += 8;
  EmitJmpBack(g_tramp3, t, f + 10);                       // jmp F3+10

  ::FlushInstructionCache(::GetCurrentProcess(), f, 4096);
  ::FlushInstructionCache(::GetCurrentProcess(), g_tramp3, 4096);
  ::VirtualProtect(g_page3, 4096, PAGE_EXECUTE_READ, nullptr);
  ::VirtualProtect(g_tramp3, 4096, PAGE_EXECUTE_READ, nullptr);

  EmitHook(f, g_tramp3);              // 5 字节 E9
  DWORD old = 0;                      // + 5 字节 NOP 填充（共 10 字节，档案 2/2.txt 形态）
  ::VirtualProtect(f, 16, PAGE_EXECUTE_READWRITE, &old);
  for (int i = 5; i < 10; ++i) f[i] = 0x90;
  ::FlushInstructionCache(::GetCurrentProcess(), f, 16);
  ::VirtualProtect(f, 16, old, &old);
}

// ---------------------------------------------------------------------------
//  用例四：多级回溯（《VM还原档案》3/1.txt 的完整形态）
//
//  原始函数 F4 头 5 字节 = 8B 16 | 8B 42 48
//    （mov edx,[rsi] ; mov eax,[rdx+0x48] —— 与档案 3 的结论完全一致）
//  VM 偷走这 5 字节后，把它们拆成两半、分别放进两级 handler：
//    一级 handler trampD1（跳回 F4+5）：
//        nop / movzx ax,cl / lea rsp,[rsp+0x34]   ← VM 垃圾
//        8B 42 48                                  ← 还原代码后半（3 字节）
//        jmp F4+5
//    上游 handler trampD2：
//        push rax
//        8B 16                                     ← 还原代码前半（2 字节）
//        call trampD1 入口                          ← 档案里"查找常量"追到的引用
//    一级取 5 字节会切出伪指令（and al,0x34 → VM 垃圾特征），
//    引擎必须向上追到 trampD2 补齐前 2 字节，拼出 8B 16 8B 42 48。
// ---------------------------------------------------------------------------
static void BuildHook4() {
  g_page4   = AllocPage(PAGE_EXECUTE_READWRITE);
  g_trampD1 = AllocPage(PAGE_EXECUTE_READWRITE);
  g_trampD2 = AllocPage(PAGE_EXECUTE_READWRITE);
  unsigned char* f = g_page4;

  size_t o = 0;
  f[o++] = 0x8B; f[o++] = 0x16;                 // mov edx,[rsi]
  f[o++] = 0x8B; f[o++] = 0x42; f[o++] = 0x48;  // mov eax,[rdx+0x48]
  f[o++] = 0xC3;                                // ret

  // ---- 一级 handler：垃圾 + 还原后半 + 跳回 ----
  size_t t = 0;
  g_trampD1[t++] = 0x90;                                        // nop（垃圾）
  g_trampD1[t++] = 0x66; g_trampD1[t++] = 0x0F;                 // movzx ax,cl
  g_trampD1[t++] = 0xB6; g_trampD1[t++] = 0xC1;                 // （垃圾）
  g_trampD1[t++] = 0x8D; g_trampD1[t++] = 0x64;                 // lea esp,[esp+0x34]
  g_trampD1[t++] = 0x24; g_trampD1[t++] = 0x34;                 // （VM 栈平衡垃圾）
  g_trampD1[t++] = 0x8B; g_trampD1[t++] = 0x42;                 // mov eax,[rdx+0x48]
  g_trampD1[t++] = 0x48;                                        // ← 还原后半（3 字节）
  EmitJmpBack(g_trampD1, t, f + 5);                             // jmp F4+5

  // ---- 上游 handler：还原前半 + call 一级入口 ----
  unsigned char* h1 = g_trampD1;                                // 一级入口
  size_t u = 0;
  g_trampD2[u++] = 0x50;                                        // push rax（垃圾）
  g_trampD2[u++] = 0x8B; g_trampD2[u++] = 0x16;                 // mov edx,[rsi]（还原前半）
  g_trampD2[u] = 0xE8;                                          // call h1
  { int rel = (int)((long long)h1 - (long long)(g_trampD2 + u + 5));
    std::memcpy(g_trampD2 + u + 1, &rel, 4); }
  u += 5;
  g_trampD2[u++] = 0xC3;                                        // ret

  ::FlushInstructionCache(::GetCurrentProcess(), f, 4096);
  ::FlushInstructionCache(::GetCurrentProcess(), g_trampD1, 4096);
  ::FlushInstructionCache(::GetCurrentProcess(), g_trampD2, 4096);
  ::VirtualProtect(g_page4,   4096, PAGE_EXECUTE_READ, nullptr);
  ::VirtualProtect(g_trampD1, 4096, PAGE_EXECUTE_READ, nullptr);
  ::VirtualProtect(g_trampD2, 4096, PAGE_EXECUTE_READ, nullptr);

  EmitHook(f, g_trampD1);                       // 5 字节 E9 → 一级 handler
}

// ---------------------------------------------------------------------------
//  用例五：CALL 型 VM（档案 2/2.txt 方法三：HOOK 是 E8 不是 E9）
//    原始 5 字节 = 55 48 89 E5 53（push rbp ; mov rbp,rsp ; push rbx）
//    HOOK = E8 rel32 → 蹦床（还原 5 字节 + jmp F5+5）
// ---------------------------------------------------------------------------
static void BuildHook5() {
  g_page5  = AllocPage(PAGE_EXECUTE_READWRITE);
  g_tramp5 = AllocPage(PAGE_EXECUTE_READWRITE);
  unsigned char* f = g_page5;

  size_t o = 0;
  f[o++] = 0x55;                                // push rbp
  f[o++] = 0x48; f[o++] = 0x89; f[o++] = 0xE5;  // mov rbp,rsp
  f[o++] = 0x53;                                // push rbx
  f[o++] = 0xC3;                                // ret

  size_t t = 0;
  for (int i = 0; i < 3; ++i) g_tramp5[t++] = 0x90;   // VM 垃圾
  const unsigned char restore[5] = {0x55, 0x48, 0x89, 0xE5, 0x53};
  std::memcpy(g_tramp5 + t, restore, 5); t += 5;
  EmitJmpBack(g_tramp5, t, f + 5);

  ::FlushInstructionCache(::GetCurrentProcess(), f, 4096);
  ::FlushInstructionCache(::GetCurrentProcess(), g_tramp5, 4096);
  ::VirtualProtect(g_page5,  4096, PAGE_EXECUTE_READ, nullptr);
  ::VirtualProtect(g_tramp5, 4096, PAGE_EXECUTE_READ, nullptr);

  DWORD old = 0;
  ::VirtualProtect(f, 16, PAGE_EXECUTE_READWRITE, &old);
  f[0] = 0xE8;                                  // call rel32 → 蹦床（档案 2 方法三）
  { int rel = (int)((long long)g_tramp5 - (long long)(f + 5));
    std::memcpy(f + 1, &rel, 4); }
  ::FlushInstructionCache(::GetCurrentProcess(), f, 16);
  ::VirtualProtect(f, 16, old, &old);
}

// ---------------------------------------------------------------------------
//  用例六：FF 25 间接跳转 HOOK（IAT/热补丁常见形态）
//    原始 6 字节 = 40 53 48 83 EC 20（push rbx ; sub rsp,0x20）
//    HOOK = FF 25 disp32（6 字节），目标地址放在独立指针槽里
// ---------------------------------------------------------------------------
static void BuildHook6() {
  g_page6  = AllocPage(PAGE_EXECUTE_READWRITE);
  g_tramp6 = AllocPage(PAGE_EXECUTE_READWRITE);
  g_slot6  = AllocPage(PAGE_READWRITE);
  unsigned char* f = g_page6;

  size_t o = 0;
  f[o++] = 0x40; f[o++] = 0x53;                       // push rbx
  f[o++] = 0x48; f[o++] = 0x83; f[o++] = 0xEC; f[o++] = 0x20;  // sub rsp,0x20
  f[o++] = 0xC3;                                      // ret

  size_t t = 0;
  for (int i = 0; i < 3; ++i) g_tramp6[t++] = 0x90;   // VM 垃圾
  const unsigned char restore[6] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20};
  std::memcpy(g_tramp6 + t, restore, 6); t += 6;
  EmitJmpBack(g_tramp6, t, f + 6);

  ::FlushInstructionCache(::GetCurrentProcess(), f, 4096);
  ::FlushInstructionCache(::GetCurrentProcess(), g_tramp6, 4096);
  ::VirtualProtect(g_page6,  4096, PAGE_EXECUTE_READ, nullptr);
  ::VirtualProtect(g_tramp6, 4096, PAGE_EXECUTE_READ, nullptr);

  *(volatile unsigned long long*)g_slot6 = (uintptr_t)g_tramp6;
  DWORD old = 0;
  ::VirtualProtect(f, 16, PAGE_EXECUTE_READWRITE, &old);
  f[0] = 0xFF; f[1] = 0x25;                           // jmp [rip+disp32]
  { int disp = (int)((long long)g_slot6 - (long long)(f + 6));
    std::memcpy(f + 2, &disp, 4); }
  ::FlushInstructionCache(::GetCurrentProcess(), f, 16);
  ::VirtualProtect(f, 16, old, &old);
}

// ---------------------------------------------------------------------------
static DWORD WINAPI DataThread(LPVOID p) {
  volatile LONG* v = (volatile LONG*)p;
  for (int i = 0;; ++i) {
    *v = i;
    ::Sleep(5);
  }
  return 0;
}

static DWORD WINAPI CallThread(LPVOID) {
  typedef long long (*Fn)();
  Fn f = (Fn)(void*)g_page1;
  for (;;) {
    volatile long long x = f();
    (void)x;
    ::Sleep(20);
  }
  return 0;
}

static DWORD WINAPI CallThread3(LPVOID) {
  // 反复调用 F3：写入数据值的指令在蹦床里执行（谁写入了这个值 → 命中在 VM 区）
  typedef void (*Fn)();
  Fn f = (Fn)(void*)g_page3;
  for (;;) {
    f();
    ::Sleep(5);
  }
  return 0;
}

int main() {
  ::SetConsoleOutputCP(65001);

  // 数据值独占一页，方便页守卫
  unsigned char* vp = AllocPage(PAGE_READWRITE);
  if (!vp) { std::printf("VirtualAlloc 失败\n"); return 1; }
  *(volatile LONG*)vp = 0;

  BuildHook1();
  BuildHook2();
  BuildHook3(vp);
  BuildHook4();
  BuildHook5();
  BuildHook6();

  ::printf("PID=%lu\n", (unsigned long)::GetCurrentProcessId());
  ::printf("ADDR=%llX\n", (unsigned long long)(uintptr_t)vp);
  ::printf("HOOK1=%llX\n", (unsigned long long)(uintptr_t)g_page1);
  ::printf("TRAMP1=%llX\n", (unsigned long long)(uintptr_t)g_tramp1);
  ::printf("RESUME1=%llX\n", (unsigned long long)(uintptr_t)(g_page1 + 5));
  ::printf("RESTORE1=55 8B EC 6A FF\n");
  ::printf("HOOK2=%llX\n", (unsigned long long)(uintptr_t)g_page2);
  ::printf("TRAMP2=%llX\n", (unsigned long long)(uintptr_t)g_tramp2);
  ::printf("RESUME2=%llX\n", (unsigned long long)(uintptr_t)(g_page2 + 7));
  ::printf("RESTORE2=55 8B EC 6A FF 90 90\n");
  ::printf("HOOK3=%llX\n", (unsigned long long)(uintptr_t)g_page3);
  ::printf("TRAMP3=%llX\n", (unsigned long long)(uintptr_t)g_tramp3);
  ::printf("RESUME3=%llX\n", (unsigned long long)(uintptr_t)(g_page3 + 10));
  // 命中点 = 蹦床里那条写内存的指令（垃圾5 + push1 之后）
  ::printf("HIT3=%llX\n", (unsigned long long)(uintptr_t)(g_tramp3 + 6));
  // 用例四：多级回溯（档案 3）
  ::printf("HOOK4=%llX\n",  (unsigned long long)(uintptr_t)g_page4);
  ::printf("TRAMP4=%llX\n", (unsigned long long)(uintptr_t)g_trampD1);
  ::printf("UP4=%llX\n",    (unsigned long long)(uintptr_t)g_trampD2);
  ::printf("RESTORE4=8B 16 8B 42 48\n");
  // 用例五：CALL 型 VM（档案 2 方法三）
  ::printf("HOOK5=%llX\n",  (unsigned long long)(uintptr_t)g_page5);
  ::printf("TRAMP5=%llX\n", (unsigned long long)(uintptr_t)g_tramp5);
  ::printf("RESTORE5=55 48 89 E5 53\n");
  // 用例六：FF25 间接跳转
  ::printf("HOOK6=%llX\n",  (unsigned long long)(uintptr_t)g_page6);
  ::printf("TRAMP6=%llX\n", (unsigned long long)(uintptr_t)g_tramp6);
  ::printf("RESTORE6=40 53 48 83 EC 20\n");
  ::printf("READY\n");
  std::fflush(stdout);

  ::CreateThread(nullptr, 0, DataThread, vp, 0, nullptr);    // 反复写这个数据值
  ::CreateThread(nullptr, 0, CallThread, nullptr, 0, nullptr); // 反复调用被 HOOK 的函数
  ::CreateThread(nullptr, 0, CallThread3, nullptr, 0, nullptr); // 写入指令在 VM 区里执行

  for (;;) ::Sleep(1000);
  return 0;
}
