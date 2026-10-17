// ============================================================================
//  dbg_probe.cpp —— 最小调试器探针：确认本机/本环境能否 DebugActiveProcess
//  用法: dbg_probe.exe <pid>
// ============================================================================
#include <windows.h>
#include <stdio.h>
#include <thread>
#include <atomic>

static std::atomic<int> g_got{0};

static void WaitLoopOnThisThread() {
  DEBUG_EVENT ev{};
  int got = 0;
  for (int i = 0; i < 20; ++i) {
    if (::WaitForDebugEvent(&ev, 500)) {
      if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        printf("    [线程内] exception code=0x%08X addr=%p\n",
               ev.u.Exception.ExceptionRecord.ExceptionCode,
               ev.u.Exception.ExceptionRecord.ExceptionAddress);
      ::ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
      if (++got >= 6) break;
    } else {
      printf("    [线程内] WaitForDebugEvent 超时/失败 err=%lu\n",
             (unsigned long)::GetLastError());
    }
  }
  g_got = got;
  printf("  [线程内] 共收到 %d 个事件\n", got);
  ::fflush(stdout);
}

int main(int argc, char** argv) {
  if (argc < 2) { printf("用法: dbg_probe <pid> [thread]\n"); return 2; }
  DWORD pid = (DWORD)strtoul(argv[1], nullptr, 10);
  const bool onThread = (argc > 2 && strcmp(argv[2], "thread") == 0);

  BOOL ok = ::DebugActiveProcess(pid);
  printf("DebugActiveProcess(%lu) -> %d, GetLastError=%lu  模式=%s\n",
         (unsigned long)pid, (int)ok, (unsigned long)::GetLastError(),
         onThread ? "子线程等事件" : "主线程等事件");
  ::fflush(stdout);
  if (!ok) return 1;
  ::DebugSetProcessKillOnExit(FALSE);

  if (onThread) {
    std::thread t(WaitLoopOnThisThread);
    t.join();
    printf("共收到 %d 个事件\n", g_got.load());
    ::DebugActiveProcessStop(pid);
    return 0;
  }

  DEBUG_EVENT ev{};
  int got = 0;
  for (int i = 0; i < 20; ++i) {
    if (::WaitForDebugEvent(&ev, 500)) {
      printf("  event code=%u tid=%u\n", ev.dwDebugEventCode, ev.dwThreadId);
      if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        printf("    exception code=0x%08X addr=%p\n",
               ev.u.Exception.ExceptionRecord.ExceptionCode,
               ev.u.Exception.ExceptionRecord.ExceptionAddress);
      ::fflush(stdout);
      ::ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
      if (++got >= 6) break;
    } else {
      printf("  WaitForDebugEvent 超时/失败 err=%lu\n", (unsigned long)::GetLastError());
      ::fflush(stdout);
    }
  }
  printf("共收到 %d 个事件\n", got);
  ::DebugActiveProcessStop(pid);
  return 0;
}

