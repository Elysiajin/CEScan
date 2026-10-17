#pragma once
// ============================================================================
//  ThreadLocator.h —— 「线程定位」窗口
//
//  对应 WinDbg 里 `ba r1 <addr>` 然后 `g` 的那套用法：
//    在对某个地址下**硬件访问断点**，抓出到底是**哪个线程**在访问它、
//    从哪条指令访问、访问次数与节奏。
//
//  为什么必须单独走硬件断点，而不是复用已有的「谁访问/谁写入」：
//    「谁访问/谁写入」是页守卫（PAGE_NOACCESS / PAGE_EXECUTE_READ），它改的是
//    **页属性**。对一个**代码地址**（典型就是被 HOOK 掉的 KiUserExceptionDispatcher）
//    挂页守卫，等于让目标一执行到那一页就吃 AV —— 而"恢复 HOOK 时游戏跟着退出"
//    恰恰是最不想要的结果。硬件 DR 断点只写线程的 DR0-DR3/DR7，不动页属性，
//    因此定位代码地址的访问者只能用硬件断点。
//
//  本模块刻意不 include ThemeColors.h，也不碰主程序的 static 全局：
//  宿主（main_gui.cpp）通过 TlHost 注入窗口句柄、调试引擎实例、主题与回调。
//  这样主程序侧的改动只有"初始化 + 转发命中 + 菜单项"三处，互不干扰。
// ============================================================================
#include <windows.h>

#include <functional>
#include <string>

#include "Debugger.h"

namespace ce {

struct TlHost {
  HWND      frame = nullptr;   // 主框架窗口：本窗口的 owner + 命中消息的投递目标
  HINSTANCE inst  = nullptr;
  Debugger* dbg   = nullptr;   // 主程序那个调试引擎实例（不拥有它）

  // 主题（由宿主注入；缺省值是一套中性灰，保证脱离主程序也能单独用）
  COLORREF  bg     = RGB(240, 240, 240);
  COLORREF  fg     = RGB(0, 0, 0);
  COLORREF  panel  = RGB(255, 255, 255);
  COLORREF  editBg = RGB(255, 255, 255);
  COLORREF  editFg = RGB(0, 0, 0);
  COLORREF  listBg = RGB(255, 255, 255);
  COLORREF  listFg = RGB(0, 0, 0);
  COLORREF  edge   = RGB(128, 128, 128);
  COLORREF  dim    = RGB(120, 120, 120);
  COLORREF  hot    = RGB(200, 0, 0);      // 强调色（命中提示文字）
  COLORREF  warn   = RGB(200, 120, 0);    // 提示色（"未附加/参数不合法"）
  wchar_t   uiFont[32]   = L"Microsoft YaHei UI";
  wchar_t   monoFont[32] = L"Consolas";
  int       uiFontH   = -14;
  int       monoFontH = -14;

  std::function<void(const wchar_t*)>     status;  // 写状态栏
  std::function<void(const std::string&)> log;     // 写日志窗口
};

// 主程序启动时调一次（注入宿主环境）
void TlInit(const TlHost& host);

// 打开或前置「线程定位」窗口
bool TlOpen();
bool TlIsOpen();

// 调试命中转发（在 UI 线程调用）。
// 返回 true 表示这次命中已被本窗口消化（调用方不必再喂给断点命中列表/监视窗口）。
bool TlOnHit(const HitReport& hit);

// 停止定位：摘掉硬件断点（会连目标线程的 DR 一起清）
void TlStopMonitor();

// 退出前清理（关进程句柄/字体/窗口）
void TlShutdown();

}  // namespace ce
