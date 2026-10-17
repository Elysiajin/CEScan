// ---------------------------------------------------------------------------
// crc_target —— CRC 完整性保护模拟靶子（模拟"游戏保护"）
//
// 剧情：
//   GameTick() 是"游戏主逻辑"，也是外挂最想改的函数（本例演示把每 tick
//   回血 +10 改成 +99）。保护线程每 100ms 对 GameTick 的前 kCodeLen 字节
//   算一次 CRC32，与启动时（未修改前）记下的基准 g_gold 比对，不一致立即
//   判定"代码被修改"并 ExitProcess(2) —— 这就是最小可用的 CRC 完整性保护。
//
// 输出协议（供 tools/crc_hunter.exe 自动驱动，与 hook_target 同风格）：
//   PID=... / MOD=... SIZE=... / GAME_TICK=... / CHEAT_OFF=... / READY
//   运行期：[game] tick=.. hp=..（正常）  [保护] CRC 校验失败！...（被抓）
//   结局：活满 50 tick → GAME_OK，退出码 0；被检测到 → 退出码 2
//
// 用法：
//   bin/crc_target.exe            正常跑（谁不改它，它就活满 5 秒）
//   外挂方通过 WriteProcessMemory 改 GameTick+CHEAT_OFF 的 0A→99 来"作弊"
// ---------------------------------------------------------------------------
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstddef>

typedef unsigned char u8;
typedef unsigned int  u32;
typedef uintptr_t     uptr;

static volatile LONG g_hp = 100;
static u32 g_gold = 0;

static const size_t kCodeLen = 0x40;   // 受保护的代码长度（GameTick 起始 64 字节）

// "游戏主逻辑"：外挂的目标函数（noinline 保证代码形状稳定）
__declspec(noinline) void GameTick(void) {
  int hp = g_hp;
  hp = hp + 10;          // ← "+10" 的立即数就是外挂要改的点
  g_hp = hp;
}

// 标准查表法 CRC32（启动时算基准用；查表签名同时是自动寻找的特征之一）
static u32 Crc32Table(const u8* p, size_t n) {
  static u32 tab[256];
  static bool init = false;
  if (!init) {
    for (u32 i = 0; i < 256; ++i) {
      u32 c = i;
      for (int k = 0; k < 8; ++k)
        c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
      tab[i] = c;
    }
    init = true;
  }
  u32 crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < n; ++i) crc = tab[(crc ^ p[i]) & 0xFFu] ^ (crc >> 8);
  return crc ^ 0xFFFFFFFFu;
}

// 保护线程：位翻转法 CRC32（多项式 0xEDB88320 以立即数形式留在代码里，
// 自动寻找就靠它）。检测点 = "与 g_gold 比对 + 条件跳转"。
static DWORD WINAPI Watchdog(LPVOID) {
  const u8* p = (const u8*)&GameTick;
  for (;;) {
    u32 crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < kCodeLen; ++i) {
      crc ^= p[i];
      for (int b = 0; b < 8; ++b) {
        const u32 mask = 0u - (crc & 1u);
        crc = (crc >> 1) ^ (mask & 0xEDB88320u);   // ← 立即数在代码里
      }
    }
    crc ^= 0xFFFFFFFFu;
    if (crc != g_gold) {   // ← 检测点：cmp + 条件跳转
      ::printf("[保护] CRC 校验失败！代码被修改 期望=%08X 实际=%08X\n", g_gold, crc);
      ::fflush(stdout);
      ::ExitProcess(2);
    }
    ::Sleep(100);
  }
}

int main(void) {
  g_gold = Crc32Table((const u8*)&GameTick, kCodeLen);   // 修改前先记基准

  // 给外挂演示用：在 GameTick 前 kCodeLen 字节里找 "+10" 的立即数偏移
  int cheatOff = -1;
  {
    const u8* p = (const u8*)&GameTick;
    for (size_t i = 0; i + 6 <= kCodeLen; ++i) {
      if (p[i] == 0x83 && p[i + 1] >= 0xC0 && p[i + 1] <= 0xC7 &&
          p[i + 2] == 0x0A) { cheatOff = (int)(i + 2); break; }        // add r32,10
      if (p[i] == 0x05 && p[i + 1] == 0x0A && p[i + 2] == 0x00 &&
          p[i + 3] == 0x00 && p[i + 4] == 0x00) {
        cheatOff = (int)(i + 1); break;                                // add eax,imm32
      }
      if (p[i] == 0x81 && p[i + 1] >= 0xC0 && p[i + 1] <= 0xC7 &&
          p[i + 2] == 0x0A && p[i + 3] == 0x00 && p[i + 4] == 0x00 &&
          p[i + 5] == 0x00) { cheatOff = (int)(i + 2); break; }        // add r32,imm32
    }
  }

  const uptr mod = (uptr)::GetModuleHandleW(nullptr);
  u32 modSize = 0;
  {
    const u8* b = (const u8*)mod;
    const long e = *(const long*)(b + 0x3C);
    modSize = *(const u32*)(b + e + 0x50);   // OptionalHeader.SizeOfImage
  }

  ::printf("PID=%lu\n", (unsigned long)::GetCurrentProcessId());
  ::printf("MOD=%llX SIZE=%X\n", (unsigned long long)mod, modSize);
  ::printf("GAME_TICK=%llX GOLD=%08X\n",
           (unsigned long long)(uptr)&GameTick, g_gold);
  ::printf("CHEAT_OFF=%d\n", cheatOff);
  ::printf("READY\n");
  ::fflush(stdout);

  ::CreateThread(nullptr, 0, Watchdog, nullptr, 0, nullptr);

  for (int t = 1; t <= 50; ++t) {
    GameTick();
    ::printf("[game] tick=%d hp=%ld\n", t, (long)g_hp);
    ::fflush(stdout);
    ::Sleep(100);
  }
  ::printf("GAME_OK\n");
  ::fflush(stdout);
  return 0;
}
