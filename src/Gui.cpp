// ============================================================================
//  Gui.cpp —— OllyDbg 风格 MDI 主窗口（暗色主题）
//  布局：MDI 四宫格（CPU 反汇编 | 寄存器 | 数据表 | 内存 Dump）
//        + 底部命令栏(Command:) + 状态栏
//  功能：附加进程 / F7 F8 单步 / F9 运行 / Ctrl+F9 / 断点 / 谁访问·谁写入
// ============================================================================
#include <windows.h>
#include <tlhelp32.h>
#include <commctrl.h>
#include <commdlg.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <functional>

#include "CETypes.h"
#include "CEUtil.h"
#include "ProcessMemory.h"
#include "Debugger.h"
#include "Disasm.h"
#include <thread>
#include "ScanEngine.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")

using namespace ce;

// ---------------------------------------------------------------------------
//  常量与配色（OllyDbg 暗色方案）
// ---------------------------------------------------------------------------
#define WC_MAIN    L"CEScanDbgMain"
#define WC_CPU     L"CEScanDbgCpu"
#define WC_REG     L"CEScanDbgReg"
#define WC_DATA    L"CEScanDbgData"
#define WC_DUMP    L"CEScanDbgDump"

#define IDC_STATUS  1001
#define IDC_CMD     1002
#define IDM_MENU_BASE 2000

// 菜单命令
#define CMD_ATTACH   3001
#define CMD_DETACH   3002
#define CMD_EXIT     3003
#define CMD_BP_INT3  3101
#define CMD_BP_HW    3102
#define CMD_BP_RM    3103
#define CMD_FINDACC  3201
#define CMD_FINDWRT  3202
#define CMD_STOPFIND 3203
#define CMD_SCAN     3301   // 打开扫描子窗口
#define CMD_TRACE_INTO  3401  // 跟踪步入 (100 步)
#define CMD_TRACE_OVER  3402  // 跟踪步过 (100 步)
#define CMD_UNTIL_RET   3403  // 运行到返回
#define CMD_STOP_TRACE  3404  // 停止跟踪

// 配色（参照截图：黑底、红/黄/绿指令着色、蓝色选中条）
static const COLORREF CLR_BG      = RGB(0, 0, 0);
static const COLORREF CLR_ADDR    = RGB(176, 160, 208); // 淡紫灰 地址
static const COLORREF CLR_BYTES   = RGB(160, 160, 160); // 灰 字节
static const COLORREF CLR_CALL    = RGB(255, 64, 64);   // 红 call/jmp/int3
static const COLORREF CLR_MOV     = RGB(255, 255, 128); // 黄 mov 等普通指令
static const COLORREF CLR_IMM     = RGB(96, 224, 96);   // 绿 立即数
static const COLORREF CLR_COMMENT = RGB(160, 160, 176); // 灰 注释
static const COLORREF CLR_SEL     = RGB(32, 64, 160);   // 蓝色选中条
static const COLORREF CLR_TEXT    = RGB(224, 224, 224);
static const COLORREF CLR_TITLE   = RGB(0, 32, 128);    // 面板标题蓝

static HINSTANCE g_hInst = nullptr;
static HWND g_hMain = nullptr, g_hMdiClient = nullptr, g_hStatus = nullptr, g_hCmd = nullptr;
static ce::Debugger g_dbg;
static DWORD g_pid = 0;
static std::wstring g_procName;
static ptruint g_eip = 0;             // 当前显示地址（CPU 面板滚动基址）
static int  g_selLine = -1;
static std::vector<ce::HitReport> g_hits;  // 谁访问/写入 命中列表（显示在数据面板）
static std::vector<ce::ProcessEntry> g_procs;
static int  g_attachSel = -1;              // 附加对话框选中

// ---------------------------------------------------------------------------
//  工具：GDI 双缓冲列表绘制辅助
// ---------------------------------------------------------------------------
struct PanelCtx {
  HWND hwnd; HDC hdc; PAINTSTRUCT ps;
  RECT rc; HFONT font; COLORREF bg;
};
static void PanelBegin(HWND hwnd, PanelCtx* pc, COLORREF bg) {
  pc->hwnd = hwnd;
  pc->hdc = ::BeginPaint(hwnd, &pc->ps);
  ::GetClientRect(hwnd, &pc->rc);
  pc->bg = bg;
  ::SetBkColor(pc->hdc, bg);
  static HFONT f = nullptr;
  if (!f) {
    f = ::CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                      FIXED_PITCH | FF_MODERN, L"Consolas");
  }
  pc->font = f;
  ::SelectObject(pc->hdc, f);
}
static void PanelEnd(PanelCtx* pc) { ::EndPaint(pc->hwnd, &pc->ps); }

static void DrawText2(HDC hdc, int x, int y, const std::wstring& s, COLORREF c) {
  ::SetTextColor(hdc, c);
  ::TextOutW(hdc, x, y, s.c_str(), (int)s.size());
}
static std::wstring Utf8ToW(const std::string& s) {
  if (s.empty()) return L"";
  int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
  std::wstring w(n, 0);
  ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
  if (!w.empty() && w.back() == 0) w.pop_back();
  return w;
}
static std::string FmtAddr(ptruint a) {
  char b[32]; snprintf(b, sizeof(b), "%016llX", (unsigned long long)a);
  return b;
}

// ---------------------------------------------------------------------------
//  CPU 反汇编面板
// ---------------------------------------------------------------------------
static LRESULT CALLBACK CpuProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  switch (m) {
    case WM_PAINT: {
      PanelCtx pc; PanelBegin(h, &pc, CLR_BG);
      const int lineH = 18;
      int lines = (pc.rc.bottom - pc.rc.top) / lineH;
      // 面板标题
      ::SetBkColor(pc.hdc, CLR_TITLE);
      ::SetTextColor(pc.hdc, RGB(255,255,255));
      ::TextOutW(pc.hdc, 4, 2, L"CPU - 反汇编 (F7 单步进入  F8 跳过  F9 运行)", 40);
      ::SetBkColor(pc.hdc, CLR_BG);

      // 读目标内存并反汇编
      static std::vector<ubyte> buf;
      static ptruint bufBase = 0;
      static HANDLE hProc = nullptr;
      if (g_dbg.IsAttached()) {
        if (!hProc) hProc = ::OpenProcess(PROCESS_VM_READ, FALSE, g_dbg.Pid());
      } else if (hProc) { ::CloseHandle(hProc); hProc = nullptr; bufBase = 0; }
      if (hProc && bufBase != g_eip) {
        buf.resize(1024);
        SIZE_T rd = 0;
        if (!::ReadProcessMemory(hProc, LPCVOID(g_eip), buf.data(), buf.size(), &rd))
          buf.clear();
        bufBase = g_eip;
      }
      if (!buf.empty() && hProc) {
        auto ins = ce::DisassembleRange(buf.data(), buf.size(), g_eip, lines - 1);
        ubyte raw[16];
        SIZE_T rd = 0;
        if (hProc) ::ReadProcessMemory(hProc, LPCVOID(g_eip), raw, sizeof(raw), &rd);

        int y = 24;
        for (int i = 0; i < (int)ins.size(); ++i) {
          // 选中行高亮
          if (i == g_selLine) {
            RECT lr{0, y, pc.rc.right, y + lineH};
            HBRUSH br = ::CreateSolidBrush(CLR_SEL);
            ::FillRect(pc.hdc, &lr, br); ::DeleteObject(br);
            ::SetBkColor(pc.hdc, CLR_SEL);
          }
          int x = 4;
          // 地址
          char a[32]; snprintf(a, sizeof(a), "%016llX", (unsigned long long)(g_eip + i * 0));
          DrawText2(pc.hdc, x, y, Utf8ToW(FmtAddr(g_eip)), CLR_ADDR); x += 130;
          // 字节
          std::string bs;
          for (int k = 0; k < ins[i].length && k < 8 && k < (int)rd - i; ++k) {
            char t[8]; snprintf(t, sizeof(t), "%02X ", raw[i + k]); bs += t;
          }
          DrawText2(pc.hdc, x, y, Utf8ToW(bs), CLR_BYTES); x += 100;
          // 指令（按类型着色）
          COLORREF c = CLR_MOV;
          if (ins[i].isInt3 || ins[i].isCall || ins[i].isJump || ins[i].isRet) c = CLR_CALL;
          DrawText2(pc.hdc, x, y, Utf8ToW(ins[i].text), c);
          ::SetBkColor(pc.hdc, i == g_selLine ? CLR_SEL : CLR_BG);
          y += lineH;
          if (y > pc.rc.bottom) break;
          g_eip += 0; // g_eip 固定为窗口基址；滚动另行处理
        }
      } else if (!g_dbg.IsAttached()) {
        DrawText2(pc.hdc, 8, 28, L"[未附加进程] 菜单: 文件 -> 附加进程...", CLR_COMMENT);
      }
      PanelEnd(&pc);
      return 0;
    }
    case WM_LBUTTONDOWN: {
      int y = HIWORD(l);
      g_selLine = (y - 24) / 18;
      ::InvalidateRect(h, nullptr, TRUE);
      return 0;
    }
    case WM_RBUTTONUP: {
      // 右键弹出断点菜单
      HMENU menu = ::CreatePopupMenu();
      ::AppendMenuW(menu, MF_STRING, CMD_BP_INT3, L"断点 -> INT3 执行断点 (F2)");
      ::AppendMenuW(menu, MF_STRING, CMD_BP_HW,   L"断点 -> 硬件执行断点");
      ::AppendMenuW(menu, MF_STRING, CMD_FINDACC, L"查找 -> 是什么访问了这个地址");
      ::AppendMenuW(menu, MF_STRING, CMD_FINDWRT, L"查找 -> 是什么写入这个地址");
      POINT pt; ::GetCursorPos(&pt);
      ::TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_hMain, nullptr);
      ::DestroyMenu(menu);
      return 0;
    }
  }
  return ::DefWindowProcW(h, m, w, l);
}

// ---------------------------------------------------------------------------
//  寄存器面板
// ---------------------------------------------------------------------------
static LRESULT CALLBACK RegProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  switch (m) {
    case WM_PAINT: {
      PanelCtx pc; PanelBegin(h, &pc, CLR_BG);
      ::SetBkColor(pc.hdc, CLR_TITLE);
      ::SetTextColor(pc.hdc, RGB(255,255,255));
      ::TextOutW(pc.hdc, 4, 2, L"寄存器 (FPU)", 12);
      ::SetBkColor(pc.hdc, CLR_BG);
      int y = 24;
      if (g_dbg.IsAttached()) {
        // 取主线程上下文（简化：取第一个线程）
        HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, g_dbg.Pid());
        if (snap != INVALID_HANDLE_VALUE) {
          THREADENTRY32 te{}; te.dwSize = sizeof(te);
          if (::Thread32First(snap, &te)) {
            DWORD tid = te.th32ThreadID;
            ::CloseHandle(snap);
            HANDLE th = ::OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
            if (th) {
              CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
              if (::GetThreadContext(th, &ctx)) {
                auto line = [&](const char* n, unsigned long long v) {
                  char b[96]; snprintf(b, sizeof(b), "%-4s %016llX", n, v);
                  DrawText2(pc.hdc, 6, y, Utf8ToW(b), CLR_TEXT); y += 17;
                };
                line("RAX", ctx.Rax); line("RCX", ctx.Rcx); line("RDX", ctx.Rdx);
                line("RBX", ctx.Rbx); line("RSP", ctx.Rsp); line("RBP", ctx.Rbp);
                line("RSI", ctx.Rsi); line("RDI", ctx.Rdi);
                line("R8",  ctx.R8);  line("R9",  ctx.R9);
                line("R10", ctx.R10); line("R11", ctx.R11);
                line("R12", ctx.R12); line("R13", ctx.R13);
                line("R14", ctx.R14); line("R15", ctx.R15);
                char e[96]; snprintf(e, sizeof(e), "EIP  %016llX", (unsigned long long)ctx.Rip);
                DrawText2(pc.hdc, 6, y, Utf8ToW(e), CLR_CALL); y += 17;
                snprintf(e, sizeof(e), "EFL  %08llX", (unsigned long long)ctx.EFlags);
                DrawText2(pc.hdc, 6, y, Utf8ToW(e), CLR_TEXT); y += 17;
              }
              ::CloseHandle(th);
            }
          } else ::CloseHandle(snap);
        }
      } else {
        DrawText2(pc.hdc, 8, 28, L"[未附加]", CLR_COMMENT);
      }
      PanelEnd(&pc);
      return 0;
    }
  }
  return ::DefWindowProcW(h, m, w, l);
}

// ---------------------------------------------------------------------------
//  数据面板（谁访问/写入 命中列表 / 断点列表）
// ---------------------------------------------------------------------------
static LRESULT CALLBACK DataProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  switch (m) {
    case WM_PAINT: {
      PanelCtx pc; PanelBegin(h, &pc, CLR_BG);
      ::SetBkColor(pc.hdc, CLR_TITLE);
      ::SetTextColor(pc.hdc, RGB(255,255,255));
      ::TextOutW(pc.hdc, 4, 2, L"命中记录 / 断点列表", 16);
      ::SetBkColor(pc.hdc, CLR_BG);
      int y = 24;
      if (g_hits.empty()) {
        DrawText2(pc.hdc, 8, y, L"(右键 CPU 面板 -> 是什么访问/写入)", CLR_COMMENT);
      } else {
        // 表头
        DrawText2(pc.hdc, 8,  y, L"地址            指令RIP          线程    类型", CLR_ADDR); y += 17;
        for (auto& r : g_hits) {
          char b[160];
          const char* k = (r.kind == ce::BpKind::Write) ? "WRITE" : "READ";
          snprintf(b, sizeof(b), "%016llX  %016llX  %-6u  %s",
                   (unsigned long long)r.address, (unsigned long long)r.rip, r.tid, k);
          DrawText2(pc.hdc, 8, y, Utf8ToW(b), CLR_TEXT);
          y += 17;
          if (y > pc.rc.bottom) break;
        }
      }
      PanelEnd(&pc);
      return 0;
    }
  }
  return ::DefWindowProcW(h, m, w, l);
}

// ---------------------------------------------------------------------------
//  内存 Dump 面板
// ---------------------------------------------------------------------------
static LRESULT CALLBACK DumpProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  switch (m) {
    case WM_PAINT: {
      PanelCtx pc; PanelBegin(h, &pc, CLR_BG);
      ::SetBkColor(pc.hdc, CLR_TITLE);
      ::SetTextColor(pc.hdc, RGB(255,255,255));
      ::TextOutW(pc.hdc, 4, 2, L"内存转储 (Hex Dump)", 18);
      ::SetBkColor(pc.hdc, CLR_BG);
      int y = 24;
      if (g_dbg.IsAttached() && g_eip) {
        HANDLE p = ::OpenProcess(PROCESS_VM_READ, FALSE, g_dbg.Pid());
        if (p) {
          ubyte buf[256]; SIZE_T rd = 0;
          if (::ReadProcessMemory(p, LPCVOID(g_eip), buf, sizeof(buf), &rd)) {
            for (int row = 0; row < 12 && row * 16 < (int)rd; ++row) {
              char b[128]; int o = 0;
              o += snprintf(b + o, sizeof(b) - o, "%016llX  ",
                            (unsigned long long)(g_eip + row * 16));
              for (int i = 0; i < 16 && row * 16 + i < (int)rd; ++i)
                o += snprintf(b + o, sizeof(b) - o, "%02X ", buf[row * 16 + i]);
              // ASCII
              std::string asc;
              for (int i = 0; i < 16 && row * 16 + i < (int)rd; ++i) {
                ubyte c = buf[row * 16 + i];
                asc += (c >= 32 && c < 127) ? (char)c : '.';
              }
              o += snprintf(b + o, sizeof(b) - o, " %s", asc.c_str());
              DrawText2(pc.hdc, 6, y, Utf8ToW(b), row == 0 ? CLR_IMM : CLR_TEXT);
              y += 17;
            }
          }
          ::CloseHandle(p);
        }
      } else {
        DrawText2(pc.hdc, 8, 28, L"[未附加]", CLR_COMMENT);
      }
      PanelEnd(&pc);
      return 0;
    }
  }
  return ::DefWindowProcW(h, m, w, l);
}

// ---------------------------------------------------------------------------
//  附加对话框：列出进程让用户选择
// ---------------------------------------------------------------------------
struct AttachCtx { int sel; std::vector<ce::ProcessEntry>* procs; };
static INT_PTR CALLBACK AttachDlgProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  static AttachCtx* ctx = nullptr;
  switch (m) {
    case WM_INITDIALOG: {
      ctx = (AttachCtx*)l;
      HWND lb = ::GetDlgItem(h, 1101);
      for (size_t i = 0; i < ctx->procs->size(); ++i) {
        auto& pe = (*ctx->procs)[i];
        std::wstring line = std::to_wstring(pe.pid) + L"   " + pe.name +
                            (pe.windowTitle.empty() ? L"" : L"   [" + pe.windowTitle + L"]");
        int idx = (int)::SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)line.c_str());
        ::SendMessageW(lb, LB_SETITEMDATA, idx, (LPARAM)i);
      }
      return TRUE;
    }
    case WM_COMMAND:
      if (LOWORD(w) == 1101 && HIWORD(w) == LBN_SELCHANGE) {
        int i = (int)::SendMessageW(::GetDlgItem(h, 1101), LB_GETCURSEL, 0, 0);
        if (i >= 0) ctx->sel = (int)::SendMessageW(::GetDlgItem(h, 1101), LB_GETITEMDATA, i, 0);
      }
      if (LOWORD(w) == IDOK && ctx->sel >= 0) { ::EndDialog(h, IDOK); return TRUE; }
      if (LOWORD(w) == IDCANCEL) { ::EndDialog(h, IDCANCEL); return TRUE; }
      break;
  }
  return FALSE;
}

// ---------------------------------------------------------------------------
//  MDI 框架主窗口
// ---------------------------------------------------------------------------
static void Layout() {
  RECT rc; ::GetClientRect(g_hMain, &rc);
  int statusH = 24;
  int cmdH = 26;
  int bodyH = rc.bottom - statusH - cmdH;
  ::MoveWindow(g_hMdiClient, 0, 0, rc.right, bodyH, TRUE);
  ::MoveWindow(g_hCmd, 0, bodyH, rc.right, cmdH, TRUE);
  ::MoveWindow(g_hStatus, 0, bodyH + cmdH, rc.right, statusH, TRUE);
}

static void DoCommand(int cmd) {
  switch (cmd) {
    case CMD_ATTACH: {
      g_procs = ce::ProcessMemory::ListProcesses();
      AttachCtx ctx{-1, &g_procs};
      if (::DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(200), g_hMain, AttachDlgProc, (LPARAM)&ctx) == IDOK
          && ctx.sel >= 0) {
        auto& pe = g_procs[ctx.sel];
        std::string err;
        if (g_dbg.Attach(pe.pid, &err)) {
          g_pid = pe.pid; g_procName = pe.name;
          g_dbg.SetHitCallback([](const ce::HitReport& r) {
            g_hits.push_back(r);
            ::InvalidateRect(::GetDlgItem(g_hMain, 0), nullptr, TRUE);
            ::InvalidateRect(g_hMdiClient, nullptr, TRUE);
          });
          std::wstring title = L"CEScan 调试器 - " + g_procName;
          ::SetWindowTextW(g_hMain, title.c_str());
          ::InvalidateRect(g_hMdiClient, nullptr, TRUE);
        } else {
          ::MessageBoxA(g_hMain, err.c_str(), "附加失败", MB_OK | MB_ICONERROR);
        }
      }
      break;
    }
    case CMD_DETACH:
      g_dbg.Detach();
      g_hits.clear();
      ::SetWindowTextW(g_hMain, L"CEScan 调试器");
      ::InvalidateRect(g_hMdiClient, nullptr, TRUE);
      break;
    case CMD_EXIT: ::PostQuitMessage(0); break;
    case CMD_BP_INT3: {
      if (g_dbg.IsAttached() && g_eip) {
        g_dbg.SetInt3(g_eip);
        char b[128]; snprintf(b, sizeof(b), "INT3 断点已设: %016llX", (unsigned long long)g_eip);
        ::SetWindowTextA(g_hStatus, b);
      }
      break;
    }
    case CMD_BP_HW: {
      if (g_dbg.IsAttached() && g_eip) {
        std::string err;
        if (!g_dbg.SetHardware(g_eip, ce::BpKind::HardwareExec, &err))
          ::MessageBoxA(g_hMain, err.c_str(), "硬件断点", MB_OK);
        else ::SetWindowTextA(g_hStatus, "硬件执行断点已设 (DR 槽占用)");
      }
      break;
    }
    case CMD_FINDACC:
      if (g_dbg.IsAttached() && g_eip) {
        g_hits.clear();
        g_dbg.FindWhatAccesses(g_eip);
        ::SetWindowTextA(g_hStatus, "监控中: 是什么访问了这个地址... ( StopFind 停止)");
      }
      break;
    case CMD_FINDWRT:
      if (g_dbg.IsAttached() && g_eip) {
        g_hits.clear();
        g_dbg.FindWhatWrites(g_eip);
        ::SetWindowTextA(g_hStatus, "监控中: 是什么写入这个地址...");
      }
      break;
    case CMD_STOPFIND: g_dbg.StopFind(); break;
    case CMD_TRACE_INTO:
    case CMD_TRACE_OVER:
      if (g_dbg.IsAttached()) {
        ::SetWindowTextA(g_hStatus, "跟踪中...");
        std::thread([cmd]() {
          g_dbg.TraceStepCallback([](ptruint rip) { g_eip = rip; });
          if (cmd == CMD_TRACE_INTO) g_dbg.TraceInto(100);
          else                        g_dbg.TraceOver(100);
          ::PostMessageW(g_hMain, WM_APP + 1, 0, 0);
        }).detach();
      }
      break;
    case CMD_UNTIL_RET:
      if (g_dbg.IsAttached()) {
        g_dbg.ExecuteUntilReturn();
        ::SetWindowTextA(g_hStatus, "运行到返回...");
      }
      break;
    case CMD_STOP_TRACE:
      g_dbg.StopFind();
      ::SetWindowTextA(g_hStatus, "跟踪已停止");
      break;
  }
  ::InvalidateRect(g_hMdiClient, nullptr, TRUE);
}

static void BuildMenu(HWND h) {
  HMENU mb = ::CreateMenu();
  HMENU mFile = ::CreatePopupMenu();
  ::AppendMenuW(mFile, MF_STRING, CMD_ATTACH, L"附加进程(&A)...");
  ::AppendMenuW(mFile, MF_STRING, CMD_DETACH, L"脱离(&D)");
  ::AppendMenuW(mFile, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(mFile, MF_STRING, CMD_EXIT, L"退出(&X)");
  ::AppendMenuW(mb, MF_POPUP, (UINT_PTR)mFile, L"文件(&F)");

  HMENU mDbg = ::CreatePopupMenu();
  ::AppendMenuW(mDbg, MF_STRING, 4001, L"运行 F9");
  ::AppendMenuW(mDbg, MF_STRING, 4002, L"单步进入 F7");
  ::AppendMenuW(mDbg, MF_STRING, 4003, L"单步跳过 F8");
  ::AppendMenuW(mDbg, MF_STRING, 4004, L"暂停 F12");
  ::AppendMenuW(mDbg, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(mDbg, MF_STRING, CMD_TRACE_INTO, L"跟踪步入 x100");
  ::AppendMenuW(mDbg, MF_STRING, CMD_TRACE_OVER, L"跟踪步过 x100");
  ::AppendMenuW(mDbg, MF_STRING, CMD_UNTIL_RET,  L"运行到返回 Ctrl+F9");
  ::AppendMenuW(mDbg, MF_STRING, CMD_STOP_TRACE, L"停止跟踪");
  ::AppendMenuW(mb, MF_POPUP, (UINT_PTR)mDbg, L"调试(&D)");

  HMENU mBp = ::CreatePopupMenu();
  ::AppendMenuW(mBp, MF_STRING, CMD_BP_INT3, L"INT3 执行断点 F2");
  ::AppendMenuW(mBp, MF_STRING, CMD_BP_HW,   L"硬件执行断点");
  ::AppendMenuW(mBp, MF_STRING, CMD_STOPFIND, L"删除所有断点");
  ::AppendMenuW(mb, MF_POPUP, (UINT_PTR)mBp, L"断点(&B)");

  HMENU mFind = ::CreatePopupMenu();
  ::AppendMenuW(mFind, MF_STRING, CMD_FINDACC, L"是什么访问了这个地址");
  ::AppendMenuW(mFind, MF_STRING, CMD_FINDWRT, L"是什么写入这个地址");
  ::AppendMenuW(mFind, MF_STRING, CMD_STOPFIND, L"停止监控");
  ::AppendMenuW(mb, MF_POPUP, (UINT_PTR)mFind, L"查找(&W)");

  ::SetMenu(h, mb);
}

static LRESULT CALLBACK MainProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  switch (m) {
    case WM_CREATE: {
      CLIENTCREATESTRUCT ccs{};
      g_hMdiClient = ::CreateWindowExW(0, L"MDICLIENT", nullptr,
          WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
          0, 0, 0, 0, h, nullptr, g_hInst, &ccs);

      // 四宫格：简化为直接子窗口（ OllyDbg 同款布局，不做 MDI 嵌套拖拽）
      struct { const wchar_t* cls; const wchar_t* title; } q[4] = {
        {WC_CPU,  L"CPU"},
        {WC_REG,  L"寄存器"},
        {WC_DATA, L"数据"},
        {WC_DUMP, L"Dump"},
      };
      for (int i = 0; i < 4; ++i)
        ::CreateWindowExW(WS_EX_CLIENTEDGE, q[i].cls, q[i].title,
                          WS_CHILD | WS_VISIBLE, 0, 0, 100, 100, g_hMdiClient,
                          (HMENU)(INT_PTR)(9000 + i), g_hInst, nullptr);

      g_hCmd = ::CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER,
                                 0, 0, 0, 0, h, (HMENU)IDC_CMD, g_hInst, nullptr);
      g_hStatus = ::CreateWindowExW(0, STATUSCLASSNAMEW, L"就绪",
                                    WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, h,
                                    (HMENU)IDC_STATUS, g_hInst, nullptr);
      BuildMenu(h);
      ::SetWindowTextW(h, L"CEScan 调试器 (OllyDbg 风格 MDI)");
      return 0;
    }
    case WM_SIZE: {
      // 四宫格布局：左上 CPU (60% 宽 60% 高)，右上寄存器(40%)，左下数据，右下 Dump
      RECT rc; ::GetClientRect(g_hMdiClient, &rc);
      int w1 = rc.right * 60 / 100, h1 = rc.bottom * 55 / 100;
      ::MoveWindow(::GetDlgItem(g_hMdiClient, 9000), 0, 0, w1, h1, TRUE);
      ::MoveWindow(::GetDlgItem(g_hMdiClient, 9001), w1, 0, rc.right - w1, h1, TRUE);
      ::MoveWindow(::GetDlgItem(g_hMdiClient, 9002), 0, h1, w1, rc.bottom - h1, TRUE);
      ::MoveWindow(::GetDlgItem(g_hMdiClient, 9003), w1, h1, rc.right - w1, rc.bottom - h1, TRUE);
      Layout();
      return 0;
    }
    case WM_COMMAND:
      switch (LOWORD(w)) {
        case 4001: g_dbg.Run(); ::InvalidateRect(g_hMdiClient, nullptr, TRUE); break;
        case 4002: g_dbg.StepInto(); ::InvalidateRect(g_hMdiClient, nullptr, TRUE); break;
        case 4003: g_dbg.StepOver(); ::InvalidateRect(g_hMdiClient, nullptr, TRUE); break;
        case 4004: g_dbg.Pause(); break;
        default: DoCommand(LOWORD(w));
      }
      return 0;
    case WM_APP + 1:
      ::SetWindowTextA(g_hStatus, "跟踪完成");
      ::InvalidateRect(g_hMdiClient, nullptr, TRUE);
      return 0;
    case WM_DESTROY: g_dbg.Detach(); ::PostQuitMessage(0); return 0;
  }
  return ::DefWindowProcW(h, m, w, l);
}

// ---------------------------------------------------------------------------
//  入口
// ---------------------------------------------------------------------------
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
  g_hInst = hInst;
  ::InitCommonControls();

  WNDCLASSW wc{};
  wc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
  wc.hInstance = hInst;
  wc.hbrBackground = ::CreateSolidBrush(CLR_BG);

  wc.lpfnWndProc = MainProc; wc.lpszClassName = WC_MAIN;
  wc.style = CS_HREDRAW | CS_VREDRAW;
  ::RegisterClassW(&wc);

  wc.lpfnWndProc = CpuProc;  wc.lpszClassName = WC_CPU;
  ::RegisterClassW(&wc);
  wc.lpfnWndProc = RegProc;  wc.lpszClassName = WC_REG;
  ::RegisterClassW(&wc);
  wc.lpfnWndProc = DataProc; wc.lpszClassName = WC_DATA;
  ::RegisterClassW(&wc);
  wc.lpfnWndProc = DumpProc; wc.lpszClassName = WC_DUMP;
  ::RegisterClassW(&wc);

  // 加载资源对话框需要 hInstance 绑定（此处用内存模板动态建对话框，简化为手工窗口）
  // —— 直接创建主窗口
  HWND h = ::CreateWindowExW(0, WC_MAIN, L"CEScan 调试器",
      WS_OVERLAPPEDWINDOW, 60, 60, 1200, 780, nullptr, nullptr, hInst, nullptr);
  g_hMain = h;
  ::ShowWindow(h, nShow);
  ::UpdateWindow(h);

  MSG msg;
  while (::GetMessageW(&msg, nullptr, 0, 0)) {
    ::TranslateMessage(&msg);
    ::DispatchMessageW(&msg);
  }
  return (int)msg.wParam;
}

// 标准 exe 入口：无参数 = 调试器界面；带参数 = CLI 扫描模式
int main(int argc, char** argv) {
  if (argc <= 1) {
    return wWinMain(::GetModuleHandleW(nullptr), nullptr, ::GetCommandLineW(), SW_SHOW);
  }
}
