// ============================================================================
//  dbvm_bp_test.cpp —— DBVM 断点测试器
//
//  流程（完全走我们移植的 DbvmLoader + Dbvm + DbvmTools 通道）：
//    1) 启动目标进程并解析它 `DBVM_TEST_FUNC=0x...` 的代码地址；
//    2) 用 DbvmLoader 加载并启动 DBVM（需管理员 + 驱动/LT 签名就绪）；
//    3) 用 DbvmTools::SetBreakpoint 对目标函数下 DBVM 断点
//       （WatchExecutes + kEptoDbvmBp：命中即冻结目标线程，目标不可感知）；
//    4) 校验「下断」：BrokenThreadCount()>0 且目标计数器停走（v2==v3）；
//    5) 删断点 + ResumeAllFrozen：校验「续跑」，计数器恢复增长（v4!=v5）；
//    6) 打印 PASS / FAIL 汇总，退出码 0=全绿。
//
//  用法：dbvm_bp_test.exe <目标exe> <dbk64.sys> <vmdisk.img>
//  注意：必须管理员运行（SCM 加载内核驱动需要）。
// ============================================================================
#include "DbvmLoader.h"
#include "DbvmTools.h"
#include "DBVM.h"

#include <windows.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>

namespace {

int g_fail = 0;
#define CHECK(cond, msg)                                                    \
  do {                                                                     \
    if (cond) {                                                            \
      printf("  [PASS] %s\n", (msg));                                       \
    } else {                                                               \
      printf("  [FAIL] %s\n", (msg));                                       \
      ++g_fail;                                                             \
    }                                                                      \
  } while (0)

std::wstring Utf8ToWide(const char* s) {
  int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
  std::wstring w(n > 0 ? n - 1 : 0, L'\0');
  if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s, -1, &w[0], n);
  return w;
}

uint64_t ParseHex(const char* p) {
  while (*p == ' ' || *p == '\t' || *p == '=') ++p;
  if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
  uint64_t v = 0;
  for (; *p; ++p) {
    char c = *p;
    int d = -1;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    if (d < 0) break;
    v = (v << 4) | (unsigned)d;
  }
  return v;
}

// 读子进程 stdout，直到拿到 DBVM_TEST_COUNTER / DBVM_TEST_FUNC 两行
bool ReadChildHandshake(const std::string& data, size_t* outCounter, size_t* outFunc) {
  *outCounter = *outFunc = 0;
  const char* c = strstr(data.c_str(), "DBVM_TEST_COUNTER=");
  const char* f = strstr(data.c_str(), "DBVM_TEST_FUNC=");
  if (c && f) { *outCounter = (size_t)ParseHex(c + 17); *outFunc = (size_t)ParseHex(f + 14); }
  return c && f;
}

bool ReadCounter(HANDLE proc, size_t va, uint64_t* out) {
  SIZE_T read = 0;
  return ReadProcessMemory(proc, (LPCVOID)va, out, sizeof(*out), &read) &&
         read == sizeof(*out);
}

}  // namespace

int main(int argc, char** argv) {
  printf("==== DBVM 下断点测试 ====\n");
  if (argc < 4) {
    printf("用法: dbvm_bp_test.exe <targetExe> <dbk64.sys> <vmdisk.img>\n");
    return 2;
  }
  const char* targetExe = argv[1];
  const char* dbkPath = argv[2];
  const char* vmdkPath = argv[3];

  // ---- 1) 启动目标并拿到握手地址 ----
  {  // 把目标 stdout 重定向到管道
    SECURITY_ATTRIBUTES sa{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE rPipe = nullptr, wPipe = nullptr;
    if (!CreatePipe(&rPipe, &wPipe, &sa, 0)) { printf("[FAIL] CreatePipe\n"); return 3; }
    SetHandleInformation(rPipe, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si{sizeof(STARTUPINFOA)};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wPipe; si.hStdError = wPipe; si.hStdInput = nullptr;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(targetExe, nullptr, nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
      printf("[FAIL] CreateProcess(%s) GLE=%lu\n", targetExe, GetLastError());
      return 3;
    }
    CloseHandle(wPipe);

    std::string buf;
    char tmp[256];
    DWORD avail = 0;
    const HANDLE h = pi.hProcess;
    for (int i = 0; i < 100; ++i) {  // 最多 ~10s
      if (PeekNamedPipe(rPipe, nullptr, 0, nullptr, &avail, nullptr) && avail) {
        DWORD got = 0;
        if (ReadFile(rPipe, tmp, (avail > sizeof(tmp)) ? sizeof(tmp) : avail, &got, nullptr))
          buf.append(tmp, got);
      }
      size_t c = 0, f = 0;
      if (ReadChildHandshake(buf, &c, &f)) {
        // 放下断目标
        size_t counterAddr = c, funcAddr = f;
        printf("[目标] counter=0x%zx  func=0x%zx  pid=%lu\n",
               counterAddr, funcAddr, pi.dwProcessId);

        // ---- 2) 加载并启动 DBVM ----
        ce::DbvmLoader loader;
        loader.cfg().driverPath = Utf8ToWide(dbkPath);
        loader.cfg().vmdiskPath = Utf8ToWide(vmdkPath);
        std::string err;
        printf("[DBVM] LoadDriver ... ");
        if (!loader.LoadDriver(&err)) { printf("FAIL: %s\n", err.c_str()); TerminateProcess(h, 0); return 4; }
        printf("OK\n");
        printf("[DBVM] Launch ... ");
        if (!loader.Launch(&err))    { printf("FAIL: %s\n", err.c_str()); return 4; }
        printf("OK\n");

        ce::Dbvm& dbvm = ce::Dbvm::Instance();
        const bool avail = dbvm.Detect();
        printf("[DBVM] Detect=%s\n", avail ? "YES" : "NO");
        if (!avail) { printf("[FAIL] DBVM 未就绪: %s\n", dbvm.LastError().c_str()); TerminateProcess(h, 0); return 4; }

        // ---- 3) 下 DBVM 断点 ----
        uint64_t v1, v2, v3, v4, v5;
        if (!ReadCounter(h, counterAddr, &v1)) { printf("[FAIL] 读目标计数器失败\n"); TerminateProcess(h, 0); return 5; }
        printf("[断点] SetBreakpoint(func=0x%zx) ... ", funcAddr);
        std::string bpErr;
        const int id = ce::DbvmTools::Instance().SetBreakpoint(pi.dwProcessId, (size_t)funcAddr, &bpErr);
        if (id <= 0) { printf("FAIL: %s\n", bpErr.c_str()); TerminateProcess(h, 0); return 5; }
        printf("watchId=%d\n", id);

        Sleep(1500);  // 等目标线程命中并被 DBVM 冻结

        // ---- 4) 校验「下断」----
        const int broken = dbvm.BrokenThreadCount();
        printf("[断点] BrokenThreadCount=%d\n", broken);
        CHECK(broken > 0, "目标线程被 DBVM 冻结(命中断点)");

        if (!ReadCounter(h, counterAddr, &v2)) { printf("[FAIL] 读计数器失败\n"); TerminateProcess(h, 0); return 5; }
        Sleep(1000);
        if (!ReadCounter(h, counterAddr, &v3)) { printf("[FAIL] 读计数器失败\n"); TerminateProcess(h, 0); return 5; }
        CHECK(v2 == v3, "冻结后计数器停走 (v2==v3)");

        // ---- 5) 删断点 + 续跑，校验「续跑」----
        printf("[断点] 删除断点 + 续跑 ...\n");
        ce::DbvmTools::Instance().RemoveBreakpoint((size_t)funcAddr);
        const int resumed = ce::DbvmTools::Instance().ResumeAllFrozen(true);
        printf("[断点] resumed=%d\n", resumed);

        Sleep(1500);
        if (!ReadCounter(h, counterAddr, &v4)) { printf("[FAIL] 读计数器失败\n"); TerminateProcess(h, 0); return 5; }
        Sleep(1000);
        if (!ReadCounter(h, counterAddr, &v5)) { printf("[FAIL] 读计数器失败\n"); TerminateProcess(h, 0); return 5; }
        CHECK(v5 != v4, "续跑后计数器恢复增长 (v5!=v4)");

        TerminateProcess(h, 0);
        CloseHandle(rPipe); CloseHandle(h);
        break;
      }
      Sleep(100);
    }
    if (g_fail != 0 || buf.empty()) {
      printf("[FAIL] 未在 10s 内完成握手，stdout=%s\n", buf.c_str());
      TerminateProcess(h, 0);
      CloseHandle(rPipe); CloseHandle(h);
    }
  }

  printf("==== %s (%d fail) ====  MAX_VERIFY 依赖真实 DBVM + 管理员 ====\n",
         g_fail == 0 ? "TEST_PASS" : "TEST_FAIL", g_fail);
  return g_fail == 0 ? 0 : 1;
}