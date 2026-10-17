// ============================================================================
//  hook_restore_test.cpp —— 「VM/HOOK 还原字节自动查找」验证程序
//
//  自己拉起 hook_target.exe，读取它打印的 HOOK/RESUME/RESTORE 基准，
//  然后调用 AnalyzeHook() 自动还原，逐条断言。
//  这是对《VM还原档案》方法二·第二种 / 方法三（搜索跳回点）的自动化验证。
// ============================================================================
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#include "HookRestore.h"
#include "ProcessMemory.h"

using namespace ce;

static int g_pass = 0, g_fail = 0;

static void Check(const char* what, bool ok, const std::string& detail = "") {
  if (ok) { ++g_pass; std::printf("  [PASS] %s\n", what); }
  else    { ++g_fail; std::printf("  [FAIL] %s  %s\n", what, detail.c_str()); }
}

// ---------------------------------------------------------------------------
//  子进程 + 管道
// ---------------------------------------------------------------------------
struct Child {
  PROCESS_INFORMATION pi{};
  HANDLE rd = nullptr;
  bool ok = false;
  std::string buf;

  bool Start(const std::string& exe) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE wr = nullptr;
    if (!::CreatePipe(&rd, &wr, &sa, 0)) return false;
    ::SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    std::string cmd = "\"" + exe + "\"";
    std::vector<char> mut(cmd.begin(), cmd.end());
    mut.push_back('\0');

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);

    ok = ::CreateProcessA(nullptr, mut.data(), nullptr, nullptr, TRUE, 0, nullptr,
                          nullptr, &si, &pi) != 0;
    ::CloseHandle(wr);
    return ok;
  }

  // 一直抽管道，直到出现 "READY" 或超时
  bool WaitReady(int timeoutMs) {
    const DWORD t0 = ::GetTickCount();
    char tmp[4096];
    for (;;) {
      DWORD avail = 0;
      if (::PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
        DWORD got = 0;
        const DWORD want = avail < sizeof(tmp) ? avail : (DWORD)sizeof(tmp);
        if (::ReadFile(rd, tmp, want, &got, nullptr) && got) buf.append(tmp, got);
      }
      if (buf.find("\nREADY") != std::string::npos ||
          buf.compare(0, 5, "READY") == 0)
        return true;
      if (::GetTickCount() - t0 > (DWORD)timeoutMs) return false;
      ::Sleep(30);
    }
  }

  void Kill() {
    if (pi.hProcess) { ::TerminateProcess(pi.hProcess, 0); ::CloseHandle(pi.hProcess); }
    if (pi.hThread) ::CloseHandle(pi.hThread);
    if (rd) { ::CloseHandle(rd); rd = nullptr; }
  }
};

static std::map<std::string, std::string> ParseKV(const std::string& buf) {
  std::map<std::string, std::string> m;
  size_t p = 0;
  while (p < buf.size()) {
    size_t e = buf.find('\n', p);
    if (e == std::string::npos) e = buf.size();
    std::string line = buf.substr(p, e - p);
    p = e + 1;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    const size_t c = line.find('=');
    if (c != std::string::npos) m[line.substr(0, c)] = line.substr(c + 1);
  }
  return m;
}

static ptruint HexToU64(const std::string& s) {
  return (ptruint)std::strtoull(s.c_str(), nullptr, 16);
}

// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
  ::SetConsoleOutputCP(65001);
  const std::string exe = argc > 1 ? argv[1] : "bin\\hook_target.exe";

  std::printf("=== VM/HOOK 还原字节自动查找 —— 验证 ===\n");
  std::printf("靶子: %s\n\n", exe.c_str());

  Child ch;
  if (!ch.Start(exe)) {
    std::printf("启动靶子失败 (err=%lu)\n", (unsigned long)::GetLastError());
    return 2;
  }
  if (!ch.WaitReady(8000)) {
    std::printf("等不到 READY，靶子输出:\n%s\n", ch.buf.c_str());
    ch.Kill();
    return 2;
  }
  const std::map<std::string, std::string> kv = ParseKV(ch.buf);
  {
    std::string shown = ch.buf;
    if (shown.size() > 400) shown.resize(400);
    std::printf("--- 靶子输出 ---\n%s\n----------------\n\n", shown.c_str());
  }

  const DWORD pid = (DWORD)std::strtoul(
      kv.count("PID") ? kv.at("PID").c_str() : "0", nullptr, 10);
  if (!pid) { std::printf("没解析到 PID\n"); ch.Kill(); return 2; }

  ProcessMemory proc;
  std::string err;
  if (!proc.Open(pid, &err)) {
    std::printf("打开进程 %lu 失败: %s\n", (unsigned long)pid, err.c_str());
    ch.Kill();
    return 2;
  }

  RestoreJournal journal;
  journal.Open();
  std::printf("记录文件: %s\n\n", journal.Path().c_str());

  // === 用例一：5 字节 jmp ===
  {
    const ptruint hook = HexToU64(kv.at("HOOK1"));
    const std::string expect = kv.at("RESTORE1");
    std::printf("【用例一】5 字节 HOOK  @ %08llX   期望还原 = %s\n",
                (unsigned long long)hook, expect.c_str());
    RestoreResult r = AnalyzeHook(proc, hook);
    std::printf("%s\n", FormatRestoreDetail(r).c_str());
    Check("判定为 HOOK", r.isHook, "hookKind=" + r.hookKind);
    Check("覆盖 5 字节", r.hookLen == 5, "hookLen=" + std::to_string(r.hookLen));
    Check("跳回点 = A+5", r.resumeAddr == hook + 5);
    Check("HOOK 目标 = TRAMP1", r.hookTarget == HexToU64(kv.at("TRAMP1")));
    Check("找到还原字节", r.found);
    Check("还原字节正确", r.origHex == expect, "得到 \"" + r.origHex + "\"");
    Check("还原码位置 = 蹦床跳回指令处",
          r.restoreSite == HexToU64(kv.at("TRAMP1")) + 10,
          "得到 " + std::to_string(r.restoreSite));
    Check("置信度=高(边界对齐)", r.confidence >= 2);
    journal.Write(FormatRestoreLine(r));
    journal.WriteRaw(FormatRestoreDetail(r));
    std::printf("\n");
  }

  // === 用例二：5 字节 jmp + 2 字节 NOP = 7 字节 ===
  {
    const ptruint hook = HexToU64(kv.at("HOOK2"));
    const std::string expect = kv.at("RESTORE2");
    std::printf("【用例二】7 字节 HOOK(jmp+NOP填充)  @ %08llX   期望还原 = %s\n",
                (unsigned long long)hook, expect.c_str());
    RestoreResult r = AnalyzeHook(proc, hook);
    std::printf("%s\n", FormatRestoreDetail(r).c_str());
    Check("判定为 HOOK", r.isHook);
    Check("识别出 NOP 填充 → 共 7 字节", r.hookLen == 7,
          "hookLen=" + std::to_string(r.hookLen));
    Check("跳回点 = A+7", r.resumeAddr == hook + 7);
    Check("找到还原字节", r.found);
    Check("还原字节正确", r.origHex == expect, "得到 \"" + r.origHex + "\"");
    journal.Write(FormatRestoreLine(r));
    journal.WriteRaw(FormatRestoreDetail(r));
    std::printf("\n");
  }

  // === 用例三：命中的指令在 VM 区里（「谁写入了这个值」的实际场景）===
  {
    const ptruint hit = HexToU64(kv.at("HIT3"));
    const ptruint vp  = HexToU64(kv.at("ADDR"));
    const ptruint tramp3 = HexToU64(kv.at("TRAMP3"));
    const ptruint resume3 = HexToU64(kv.at("RESUME3"));
    // 期望还原 = 50 A3 <vp 的 64 位，小端>
    char exp[80];
    const uint64_t a64 = (uint64_t)vp;
    std::snprintf(exp, sizeof(exp),
                  "50 A3 %02X %02X %02X %02X %02X %02X %02X %02X",
                  (unsigned)(a64 & 0xFF), (unsigned)((a64 >> 8) & 0xFF),
                  (unsigned)((a64 >> 16) & 0xFF), (unsigned)((a64 >> 24) & 0xFF),
                  (unsigned)((a64 >> 32) & 0xFF), (unsigned)((a64 >> 40) & 0xFF),
                  (unsigned)((a64 >> 48) & 0xFF), (unsigned)((a64 >> 56) & 0xFF));
    std::printf("【用例三】柱内命中(写入指令被搬进蹦床)  @ %08llX   期望还原 = %s\n",
                (unsigned long long)hit, exp);
    RestoreResult r = AnalyzeHook(proc, hit);
    std::printf("%s\n", FormatRestoreDetail(r).c_str());
    Check("柱内命中 → 自动判定为 HOOK", r.isHook, "note=" + r.note);
    Check("跳回点 = HOOK3+10", r.resumeAddr == resume3,
          "得到 " + std::to_string(r.resumeAddr));
    Check("反推出的 HOOK 入口正确", r.hookTarget == tramp3);
    Check("覆盖 10 字节(jmp+NOP)", r.hookLen == 10,
          "hookLen=" + std::to_string(r.hookLen));
    Check("找到还原字节", r.found, "note=" + r.note);
    Check("还原字节正确", r.origHex == exp, "得到 \"" + r.origHex + "\"");
    Check("还原码位置 = 蹦床跳回指令处", r.restoreSite == tramp3 + 15,
          "得到 " + std::to_string(r.restoreSite));
    journal.Write(FormatRestoreLine(r));
    journal.WriteRaw(FormatRestoreDetail(r));
    std::printf("\n");
  }

  // === 用例四：多级回溯（《VM还原档案》3/1.txt 的完整形态）===
  {
    const ptruint hook = HexToU64(kv.at("HOOK4"));
    const std::string expect = kv.at("RESTORE4");
    std::printf("【用例四】多级回溯(还原代码拆在两级 handler 里)  @ %08llX   期望还原 = %s\n",
                (unsigned long long)hook, expect.c_str());
    RestoreResult r = AnalyzeHook(proc, hook);
    std::printf("%s\n", FormatRestoreDetail(r).c_str());
    Check("判定为 HOOK", r.isHook, "note=" + r.note);
    Check("覆盖 5 字节", r.hookLen == 5, "hookLen=" + std::to_string(r.hookLen));
    Check("跳回点 = A+5", r.resumeAddr == hook + 5);
    Check("找到还原字节", r.found, "note=" + r.note);
    Check("还原字节正确(8B 16 8B 42 48)", r.origHex == expect,
          "得到 \"" + r.origHex + "\"");
    Check("走了多级回溯(chainDepth>=2)", r.chainDepth >= 2,
          "chainDepth=" + std::to_string(r.chainDepth));
    Check("置信度=高", r.confidence >= 2);
    Check("回溯链描述非空", !r.chainPath.empty());
    journal.Write(FormatRestoreLine(r));
    journal.WriteRaw(FormatRestoreDetail(r));
    std::printf("\n");
  }

  // === 用例五：CALL 型 VM（档案 2/2.txt 方法三）===
  {
    const ptruint hook = HexToU64(kv.at("HOOK5"));
    const std::string expect = kv.at("RESTORE5");
    std::printf("【用例五】CALL 型 VM(E8 进 VM 桩)  @ %08llX   期望还原 = %s\n",
                (unsigned long long)hook, expect.c_str());
    RestoreResult r = AnalyzeHook(proc, hook);
    std::printf("%s\n", FormatRestoreDetail(r).c_str());
    Check("判定为 HOOK", r.isHook);
    Check("HOOK 类型 = call rel32", r.hookKind == "call rel32",
          "hookKind=" + r.hookKind);
    Check("覆盖 5 字节", r.hookLen == 5, "hookLen=" + std::to_string(r.hookLen));
    Check("跳回点 = A+5", r.resumeAddr == hook + 5);
    Check("HOOK 目标 = 蹦床", r.hookTarget == HexToU64(kv.at("TRAMP5")));
    Check("找到还原字节", r.found, "note=" + r.note);
    Check("还原字节正确", r.origHex == expect, "得到 \"" + r.origHex + "\"");
    Check("置信度=高(边界对齐)", r.confidence >= 2);
    journal.Write(FormatRestoreLine(r));
    journal.WriteRaw(FormatRestoreDetail(r));
    std::printf("\n");
  }

  // === 用例六：FF 25 间接跳转 HOOK ===
  {
    const ptruint hook = HexToU64(kv.at("HOOK6"));
    const std::string expect = kv.at("RESTORE6");
    std::printf("【用例六】FF25 间接跳转 HOOK  @ %08llX   期望还原 = %s\n",
                (unsigned long long)hook, expect.c_str());
    RestoreResult r = AnalyzeHook(proc, hook);
    std::printf("%s\n", FormatRestoreDetail(r).c_str());
    Check("判定为 HOOK", r.isHook);
    Check("HOOK 类型 = jmp [rip+disp]", r.hookKind == "jmp [rip+disp]",
          "hookKind=" + r.hookKind);
    Check("覆盖 6 字节", r.hookLen == 6, "hookLen=" + std::to_string(r.hookLen));
    Check("跳回点 = A+6", r.resumeAddr == hook + 6);
    Check("间接目标解引用正确", r.hookTarget == HexToU64(kv.at("TRAMP6")));
    Check("找到还原字节", r.found, "note=" + r.note);
    Check("还原字节正确", r.origHex == expect, "得到 \"" + r.origHex + "\"");
    Check("置信度=高(边界对齐)", r.confidence >= 2);
    journal.Write(FormatRestoreLine(r));
    journal.WriteRaw(FormatRestoreDetail(r));
    std::printf("\n");
  }

  // === 反向用例：不是 HOOK 的地方不应误报 ===
  {
    const ptruint dataAddr = HexToU64(kv.at("ADDR"));
    RestoreResult r = AnalyzeHook(proc, dataAddr);
    std::printf("【反向】数据页 %08llX 不应被判成 HOOK\n",
                (unsigned long long)dataAddr);
    Check("数据页未误判为 HOOK", !r.isHook);
    Check("但仍然给出\"写法\"(字节/反汇编)", r.readable && !r.curHex.empty());
    journal.Write(FormatRestoreLine(r));
    std::printf("\n");

    const ptruint tramp = HexToU64(kv.at("TRAMP1"));
    RestoreResult r2 = AnalyzeHook(proc, tramp);
    std::printf("【新能力】蹦床里的 NOP（柱内任意地址）→ 反推出所在 HOOK\n");
    Check("蹦床NOP也能反推出所在 HOOK", r2.isHook && r2.found,
          "note=" + r2.note + " curHex=" + r2.curHex);
    Check("反推出的还原字节仍正确", r2.origHex == kv.at("RESTORE1"),
          "得到 \"" + r2.origHex + "\"");
    std::printf("\n");
  }

  proc.Close();
  ch.Kill();

  std::printf("===== 结果: %d 通过 / %d 失败 =====\n", g_pass, g_fail);
  if (journal.IsOpen()) std::printf("已存本地: %s\n", journal.Path().c_str());
  return g_fail ? 1 : 0;
}
