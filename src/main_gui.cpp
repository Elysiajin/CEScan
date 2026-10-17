//=============================================================================
//  main_gui.cpp
//  CEScanGUI —— OllyDbg 风格 MDI 调试器 + CE 内存搜索（VC++ x64 移植版）
//
//  MDI 窗口：
//    · CPU        反汇编 / 寄存器 / 内存转储 / 堆栈 四面板（OllyDbg 布局）
//    · 搜索        首扫/复扫、区域排除、结果写入
//    · 内存地图    VirtualQueryEx 全量区域列表
//    · 线程        线程列表与 RIP
//    · 断点        INT3 / 硬件 / 页守卫 断点管理 + 谁访问/谁写入 + 命中记录
//    · 日志        调试事件流
//=============================================================================
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <commdlg.h>
#include "ThreadLocator.h"
#include "DBVM.h"
#include "DbvmLoader.h"   // 加载并启动 DBVM（SCM 驱动 + IOCTL_CE_LAUNCHDBVM）
#include "DbvmTools.h"    // DBVM 断点 + 保护（破线程续跑 + cloak 隐藏）
#include <intrin.h>
#include <tlhelp32.h>

#include <atomic>
#include <set>
#include <cstdio>
#include <cstdarg>
#include <cmath>
#include <map>
#include <unordered_map>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "GuiConfig.h"  // kMdiMinWidth / kMdiMinHeight 等 GUI 全局配置
#include "ThemeColors.h"  // 全部界面配色（集中定义，改色只改头文件）

#include <ocidl.h>   // IPicture（附加窗口 logo 宫格静态兜底）
#include <olectl.h>  // OleLoadPicture

#include "CETypes.h"
#include "CEUtil.h"    // Utf8ToWide：错误串是 UTF-8，弹窗需转宽字符
#include "Debugger.h"
#include "Disasm.h"
#include "HookRestore.h"   // VM/HOOK 还原字节自动查找
#include "McpClient.h"
#include "StrSearch.h"
#include "PatternScan.h"
#include "ProcessMemory.h"
#include "ScanEngine.h"

// 主题全局实例（ThemeColors.h 中 extern；默认值来自 DefaultTheme()）
ThemeColors g_theme = DefaultTheme();

// ======================= 主题持久化（INI） =======================
// 颜色字段表：INI 键 = 字段名，值 = "R,G,B"；label 用于设置窗口显示
static const struct {
  const wchar_t* name;
  const wchar_t* label;
  COLORREF ThemeColors::*p;
} kThemeFields[] = {
  {L"disBg", L"反汇编·普通行背景", &ThemeColors::disBg},
  {L"disRipBg", L"反汇编·当前RIP行背景", &ThemeColors::disRipBg},
  {L"disSelBg", L"反汇编·选中行背景", &ThemeColors::disSelBg},
  {L"disRetBg", L"反汇编·retn高亮底", &ThemeColors::disRetBg},
  {L"disJumpFg", L"反汇编·跳转文字", &ThemeColors::disJumpFg},
  {L"disRetFg", L"反汇编·retn文字", &ThemeColors::disRetFg},
  {L"disJumpHexFg", L"反汇编·高亮底上的十六进制", &ThemeColors::disJumpHexFg},
  {L"disPlainMn", L"反汇编·普通助记符", &ThemeColors::disPlainMn},
  {L"disSegFg", L"反汇编·段前缀(dword ptr/ds)", &ThemeColors::disSegFg},
  {L"disRegFg", L"反汇编·寄存器", &ThemeColors::disRegFg},
  {L"disHexFg", L"反汇编·0x立即数", &ThemeColors::disHexFg},
  {L"disApiFg", L"反汇编·API/符号名", &ThemeColors::disApiFg},
  {L"disDbFg", L"反汇编·db数据行", &ThemeColors::disDbFg},
  {L"disAddrFg", L"反汇编·地址列", &ThemeColors::disAddrFg},
  {L"disBytesFg", L"反汇编·机器码列", &ThemeColors::disBytesFg},
  {L"disCommentFg", L"反汇编·备注列", &ThemeColors::disCommentFg},
  {L"disColLine1", L"disColLine1", &ThemeColors::disColLine1},
  {L"disColLine2", L"disColLine2", &ThemeColors::disColLine2},
  {L"disFlowJmp", L"反汇编·流程线jmp", &ThemeColors::disFlowJmp},
  {L"uiBg", L"通用·窗口背景", &ThemeColors::uiBg},
  {L"uiText", L"通用·列表文字", &ThemeColors::uiText},
  {L"uiStackBg", L"堆栈·背景", &ThemeColors::uiStackBg},
  {L"uiStackSelBg", L"堆栈·选中行", &ThemeColors::uiStackSelBg},
  {L"uiStackFg", L"堆栈·文字", &ThemeColors::uiStackFg},
  {L"uiStackRetFg", L"堆栈·返回到高亮", &ThemeColors::uiStackRetFg},
  {L"uiStackSehFg", L"堆栈·SEH提示", &ThemeColors::uiStackSehFg},
  {L"regNameFg", L"寄存器·名称", &ThemeColors::regNameFg},
  {L"regValueFg", L"寄存器·值", &ThemeColors::regValueFg},
  {L"regNoteFg", L"寄存器·标注", &ThemeColors::regNoteFg},
  {L"regEipFg", L"寄存器·EIP", &ThemeColors::regEipFg},
  {L"regEflFg", L"寄存器·EFL", &ThemeColors::regEflFg},
  {L"regFlagFg", L"寄存器·标志解码", &ThemeColors::regFlagFg},
  {L"regSegFg", L"寄存器·段寄存器", &ThemeColors::regSegFg},
  {L"sbTrackBg", L"滚动条·轨道", &ThemeColors::sbTrackBg},
  {L"sbBorder", L"滚动条·边线", &ThemeColors::sbBorder},
  {L"vScrollThumb", L"滚动条·滑块", &ThemeColors::vScrollThumb},
  {L"vScrollThumbHi", L"滚动条·滑块(拖动)", &ThemeColors::vScrollThumbHi},
  {L"splitFace", L"分割条·常态", &ThemeColors::splitFace},
  {L"splitHot", L"分割条·悬停", &ThemeColors::splitHot},
  {L"splitBorder", L"分割条·边线", &ThemeColors::splitBorder},
  {L"colAddrLine", L"数据窗·地址基线", &ThemeColors::colAddrLine},
  {L"btnFace", L"按钮·常态", &ThemeColors::btnFace},
  {L"btnPressed", L"按钮·按下", &ThemeColors::btnPressed},
  {L"btnDisabledBg", L"按钮·禁用底", &ThemeColors::btnDisabledBg},
  {L"btnBorder", L"按钮·边线", &ThemeColors::btnBorder},
  {L"btnCheckBg", L"复选框·内部", &ThemeColors::btnCheckBg},
  {L"btnCheckTick", L"复选框·对勾", &ThemeColors::btnCheckTick},
  {L"btnCheckBorder", L"复选框·边框", &ThemeColors::btnCheckBorder},
  {L"btnText", L"按钮·文字", &ThemeColors::btnText},
  {L"btnTextDisabled", L"按钮·文字禁用", &ThemeColors::btnTextDisabled},
  {L"editBg", L"编辑框·背景", &ThemeColors::editBg},
  {L"editText", L"编辑框·文字", &ThemeColors::editText},
  {L"editTextSub", L"编辑框·次级文字", &ThemeColors::editTextSub},
  {L"listBg", L"列表·背景", &ThemeColors::listBg},
  {L"watchRed", L"监视·红", &ThemeColors::watchRed},
  {L"watchDarkRed", L"监视·暗红", &ThemeColors::watchDarkRed},
  {L"watchGreen", L"监视·绿", &ThemeColors::watchGreen},
  {L"watchBlue", L"监视·蓝", &ThemeColors::watchBlue},
  {L"watchOrange", L"监视·橙", &ThemeColors::watchOrange},
  {L"watchPurple", L"监视·紫", &ThemeColors::watchPurple},
  {L"watchGray", L"监视·灰", &ThemeColors::watchGray},
};
static const int kThemeFieldCount =
    (int)(sizeof(kThemeFields) / sizeof(kThemeFields[0]));

// exe 同目录的 CEScanGUI.ini（设置持久化 / 启动复原）
static std::wstring ThemeIniPath() {
  wchar_t path[MAX_PATH] = {};
  ::GetModuleFileNameW(nullptr, path, MAX_PATH);
  std::wstring s(path);
  size_t p = s.find_last_of(L'\\');
  return (p == std::wstring::npos) ? std::wstring(L"CEScanGUI.ini")
                                   : s.substr(0, p + 1) + L"CEScanGUI.ini";
}

// 启动复原：读取 INI（文件不存在则保持默认主题）
static void ThemeLoadIni() {
  const std::wstring ini = ThemeIniPath();
  wchar_t buf[96] = {};
  for (const auto& f : kThemeFields) {
    ::GetPrivateProfileStringW(L"Theme", f.name, L"", buf, 96, ini.c_str());
    if (!buf[0]) continue;
    int r = 0, g = 0, b = 0;
    if (std::swscanf(buf, L"%d,%d,%d", &r, &g, &b) == 3)
      g_theme.*(f.p) = RGB(r, g, b);
  }
  g_theme.fontUiHeight = ::GetPrivateProfileIntW(L"Theme", L"fontUiHeight",
                                                 g_theme.fontUiHeight, ini.c_str());
  g_theme.fontMonoHeight = ::GetPrivateProfileIntW(L"Theme", L"fontMonoHeight",
                                                   g_theme.fontMonoHeight, ini.c_str());
  g_theme.fontTbHeight = ::GetPrivateProfileIntW(L"Theme", L"fontTbHeight",
                                                 g_theme.fontTbHeight, ini.c_str());
  g_theme.highlightOperands =
      ::GetPrivateProfileIntW(L"Theme", L"highlightOperands",
                              g_theme.highlightOperands ? 1 : 0, ini.c_str()) != 0;
  wchar_t fn[40] = {};
  ::GetPrivateProfileStringW(L"Theme", L"fontUiName", g_theme.fontUiName, fn, 32, ini.c_str());
  if (fn[0]) { g_theme.fontUiName[31] = 0; ::lstrcpynW(g_theme.fontUiName, fn, 32); }
  ::GetPrivateProfileStringW(L"Theme", L"fontMonoName", g_theme.fontMonoName, fn, 32, ini.c_str());
  if (fn[0]) { g_theme.fontMonoName[31] = 0; ::lstrcpynW(g_theme.fontMonoName, fn, 32); }
}

// 应用/确定时写 INI（下次启动自动复原）
static void ThemeSaveIni() {
  const std::wstring ini = ThemeIniPath();
  wchar_t buf[96];
  for (const auto& f : kThemeFields) {
    COLORREF c = g_theme.*(f.p);
    ::wsprintfW(buf, L"%d,%d,%d", (int)GetRValue(c), (int)GetGValue(c), (int)GetBValue(c));
    ::WritePrivateProfileStringW(L"Theme", f.name, buf, ini.c_str());
  }
  ::wsprintfW(buf, L"%d", g_theme.fontUiHeight);
  ::WritePrivateProfileStringW(L"Theme", L"fontUiHeight", buf, ini.c_str());
  ::wsprintfW(buf, L"%d", g_theme.fontMonoHeight);
  ::WritePrivateProfileStringW(L"Theme", L"fontMonoHeight", buf, ini.c_str());
  ::wsprintfW(buf, L"%d", g_theme.fontTbHeight);
  ::WritePrivateProfileStringW(L"Theme", L"fontTbHeight", buf, ini.c_str());
  ::WritePrivateProfileStringW(L"Theme", L"highlightOperands",
                               g_theme.highlightOperands ? L"1" : L"0", ini.c_str());
  ::WritePrivateProfileStringW(L"Theme", L"fontUiName", g_theme.fontUiName, ini.c_str());
  ::WritePrivateProfileStringW(L"Theme", L"fontMonoName", g_theme.fontMonoName, ini.c_str());
}

// 按颜色值缓存的画刷：主题切换后取新色，无需手动重建
static HBRUSH GetCachedBrush(COLORREF c) {
  static std::map<COLORREF, HBRUSH> cache;
  auto it = cache.find(c);
  if (it != cache.end()) return it->second;
  HBRUSH b = ::CreateSolidBrush(c);
  cache.emplace(c, b);
  return b;
}
// ===================== 主题持久化结束 =====================
// 尺寸全局实例（ThemeColors.h 中 extern；默认值来自 DefaultSizes()，控件尺寸集中在此调节）
ThemeSizes g_sz = DefaultSizes();

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

using namespace ce;

//=============================================================================
// 标识
//=============================================================================
static const wchar_t kFrameClass[] = L"CEScanFrame";
static const wchar_t kChildClass[] = L"CEScanChild";
static const wchar_t kRegPanelClass[] = L"CEScanRegPanel";  // 寄存器纯自绘面板（OD 风格）

enum ChildType {
  kChildCpu = 1,
  kChildScan,
  kChildMap,
  kChildThreads,
  kChildBps,
  kChildLog,
  kChildMcp,
  kChildStrs,
  kChildLogData,   // 日志数据（OD Log data）
};

// 菜单 ID
enum {
  IDM_FIRST = 2000,
  IDM_ATTACH, IDM_DETACH, IDM_EXIT,
  IDM_RUN, IDM_PAUSE, IDM_STEPIN, IDM_STEPOVER, IDM_RUNTORET, IDM_TOGGLEBP,
  IDM_FINDACCESS, IDM_FINDWRITE, IDM_STOPFIND,
  IDM_VIEW_CPU, IDM_VIEW_SCAN, IDM_VIEW_MAP, IDM_VIEW_THREADS, IDM_VIEW_BPS,
  IDM_VIEW_LOG, IDM_VIEW_MCP, IDM_VIEW_LOGDATA,
  IDM_CASCADE, IDM_TILE, IDM_CLOSEALL, IDM_ABOUT,
  IDM_SETTINGS,
  IDM_MCP_CONNECT, IDM_MCP_DISCONNECT, IDM_MCP_PING, IDM_MCP_PROCINFO,
  IDM_VIEW_STRS, IDM_STR_ASCII, IDM_STR_UNICODE, IDM_STR_SMART, IDM_STR_CHS,
  // 工具 -> 设置API断点（按类别一键批量下断）
  IDM_APB_FIRST,
  IDM_APB_STRING = IDM_APB_FIRST,      // 字符串类
  IDM_APB_MSGBOX,                      // 消息框
  IDM_APB_DIALOG,                      // 对话框
  IDM_APB_FILE,                        // 文件
  IDM_APB_LIB,                         // 库函数
  IDM_APB_MEM,                         // 内存管理
  IDM_APB_REG,                         // 注册表
  IDM_APB_DIR,                         // 目录及路径
  IDM_APB_DRIVE,                       // 驱动器
  IDM_APB_TIME,                        // 时间
  IDM_APB_MISC,                        // 其它杂类
  IDM_APB_VB,                          // VB APIs
  IDM_APB_CUSTOM,                      // Custom APIs
  IDM_APB_CLEAR,                       // 清除本工具设置的所有 API 断点
  IDM_APB_LAST,
  // 「线程定位」窗口（硬件访问断点 ba r1 → 抓访问该地址的线程）
  // 追加在末尾：新 ID 不挤动前面任何一项的值（菜单/工具栏都按名字引用，
  // 但留个"只增不改"的规矩，避免哪天有持久化 ID 的地方被悄悄改掉）
  IDM_VIEW_TLOC,
  IDM_DBVM_DETECT,   // 插件 -> DBVM 检测
  IDM_DBVM_LOAD,     // 插件 -> 加载并启动 DBVM
  IDM_DBVM_UNLOAD,   // 插件 -> 卸载 DBVM 驱动
  IDM_DBVM_BP,       // 插件 -> DBVM 断点（选中行）
  IDM_DBVM_BP_RESUME,// 插件 -> 续跑 DBVM 冻结线程
  IDM_DBVM_BP_CLEAR, // 插件 -> 删除所有 DBVM 断点
  IDM_DBVM_CLOAK,    // 插件 -> DBVM 保护(cloak) 隐藏目标内存
  IDM_DBVM_CLOAK_OFF,// 插件 -> 取消隐藏
  IDM_DBVM_HIDE_MEM, // 插件 -> 隐藏 DBVM 物理内存
  IDM_DBVM_CR_ON,    // 插件 -> DBVM 断点：命中改寄存器(RAX=0)
  IDM_DBVM_CR_OFF,   // 插件 -> DBVM 断点：取消改寄存器
  IDM_DBVM_TRACE_ON, // 插件 -> DBVM 断点：命中跟踪(启动)
  IDM_DBVM_TRACE_STOP,// 插件 -> DBVM 断点：命中跟踪(停止)
  IDM_DBVM_TRACE_LOG, // 插件 -> DBVM 断点：命中跟踪(取日志)
  IDM_DBVM_PHYSMEM,  // 插件 -> DBVM 物理内存查看(选中行)
  IDM_DBVM_KPROT,    // 插件 -> DBVM 内核级保护(该页)
};

// 控件 ID（各 MDI 子窗口内部独立使用）
enum {
  IDC_STATUS = 900,
  IDC_TOOLBAR = 901,
  // CPU
  IDC_BTN_RUN = 100, IDC_BTN_PAUSE, IDC_BTN_STEPIN, IDC_BTN_STEPOVER, IDC_BTN_RUNRET,
  IDC_BTN_BP, IDC_GOTO, IDC_BTN_GO, IDC_DISASM, IDC_REGS, IDC_DUMP, IDC_STACK,
  // 搜索
  IDC_TYPE, IDC_OPTION, IDC_V1, IDC_V2, IDC_HEX, IDC_WRONLY, IDC_EXCMODS, IDC_EXCRANGE,
  IDC_FIRST, IDC_NEXT, IDC_NEW, IDC_RESULTS, IDC_PROG, IDC_COUNT, IDC_WV, IDC_WRITEV,
  // 断点
  IDC_BADDR, IDC_BKIND, IDC_BTN_INT3, IDC_BTN_HW, IDC_BTN_PG, IDC_BTN_DELBP,
  IDC_BTN_FINDACC, IDC_BTN_FINDWR, IDC_BTN_STOPFIND, IDC_BPLIST, IDC_HITS,
  // 线程
  IDC_THRLIST, IDC_THRREFRESH,
  // 地图
  IDC_MAPLIST, IDC_MAPREFRESH,
  // 日志
  IDC_LOGLIST,
  IDC_LDLIST,          // 日志数据列表（自绘）
  // CPU 分隔条（可拖动调节比例）
  IDC_SPLIT_V, IDC_SPLIT_H,
  // CE 风格「以下操作码…」监视窗口
  IDC_W_LIST, IDC_W_INFO, IDC_W_STOP, IDC_W_DISASM, IDC_W_NOP, IDC_W_BP,
  IDC_W_RESTORE, IDC_W_AUTORESTORE,   // VM 自动还原 开/关
  IDC_W_BYPASS,                       // 过检测/过CRC（打掉比对分支）
  IDC_VSCROLL,
  IDC_CMDLABEL, IDC_CMD, IDC_CMD_ESP, IDC_CMD_EBP,
  // 中文搜索引擎
  IDC_STR_LIST, IDC_STR_SEARCH, IDC_STR_MODE, IDC_STR_MINLEN, IDC_STR_GOTO,
  // MCP 输出栏
  IDC_MCP_LOG, IDC_MCP_CMD, IDC_MCP_SEND, IDC_MCP_CONNECT, IDC_MCP_DISCONNECT,
  // 静态标签
  IDC_S_TYPE, IDC_S_OPT, IDC_S_VAL, IDC_S_TILDE, IDC_S_EXCM, IDC_S_EXCR, IDC_S_WV,
  IDC_S_BADDR, IDC_S_BKIND, IDC_S_BPS, IDC_S_HITS,
  // MCP 快速命令
  IDC_MCP_QUICK = 700,
  // 进程选择对话框
  IDC_PD_LIST = 800, IDC_PD_REFRESH, IDC_PD_ATTACH, IDC_PD_CANCEL, IDC_PD_HINT,
};

// 消息
static const UINT WM_APP_SCAN_DONE = WM_APP + 1;
static const UINT WM_APP_HIT = WM_APP + 2;
static const UINT WM_APP_SCAN_ERR = WM_APP + 3;
static const UINT WM_APP_LOG = WM_APP + 4;
static const UINT WM_APP_RESTORE = WM_APP + 5;   // HOOK/VM 还原分析结果回到 UI 线程
static const UINT WM_APP_MCP_LOG = WM_APP + 6;
static const UINT WM_APP_MCP_STATUS = WM_APP + 7;
static const UINT WM_APP_STR_DONE = WM_APP + 8;
static const UINT WM_APP_LOGDATA = WM_APP + 9;   // 日志数据窗口行（OD Log data）
static const UINT WM_APP_INIT = WM_APP + 10;  // 主窗口就绪后创建 MDI 子窗口
static const UINT WM_APP_SCAN_PRG = WM_APP + 11;  // 扫描进度 → UI 线程刷新进度条/状态

//=============================================================================
// 应用状态
//=============================================================================
struct App {
  HWND frame = nullptr;
  HWND client = nullptr;
  HWND status = nullptr;
  HWND toolbar = nullptr;      // 仿 x64dbg 工具栏
  HINSTANCE inst = nullptr;

  // MDI 子窗口
  HWND cpu = nullptr, scanWnd = nullptr, map = nullptr, thr = nullptr, bps = nullptr,
       log = nullptr, mcp = nullptr, strs = nullptr, logData = nullptr;
  // 日志数据窗口状态
  int ldAddrW = kLogDataAddrW;   // 地址列右缘（绿线，可拖动）
  bool ldDrag = false;           // 正在拖动绿线
  WNDPROC ldPrev = nullptr;      // 列表原窗口过程

  std::vector<ce::StrHit> strHits;   // 中文搜索引擎结果
  int strMode = 2;                   // 0=ASCII 1=UNICODE 2=智能
  std::atomic<bool> strSearchRunning{false};

  ce::McpClient mcpClient;
  bool mcpConnected = false;

  ProcessMemory proc;
  ScanEngine scan{proc};
  Debugger dbg;

  std::atomic<bool> scanning{false};

  // CPU 面板状态
  DWORD focusTid = 0;
  ptruint disasmBase = 0;
  ptruint lastDisasmBase = 0;      // 上次反汇编重建的基址（防闪烁：无变化不重建）
  ptruint dumpBase = 0;            // 数据窗口独立基址（滚动条/滚轮控制）
  ptruint lastRegsRip = 0;         // 上次寄存器刷新的 RIP
  std::vector<ptruint> disasmAddr;  // 反汇编列表行 -> 地址
  std::vector<DisasmResult> disasmLines;  // 每行反汇编信息（自绘着色用）
  ptruint currentRip = 0;               // 当前 RIP（高亮行）
  int disasmSel = -1;                   // 锚点行（屏幕行号，仅当前视口内有效）
  std::set<int> disasmMulti;            // 多选行号（屏幕坐标，当前视口）
  ptruint selAddr = 0;                  // 锚点行的指令地址（滚动后据此重映射）
  std::set<ptruint> multiAddrs;         // 多选行的指令地址集合（跨滚动持久）
  // 寄存器面板（OD 风格自绘）
  unsigned long long regVals[22] = {};  // 0-15 GPR, 16=RIP, 17=EFL, 18-21 段 ES/CS/SS/DS
  wchar_t regNotes[22][96] = {};        // 每行右侧灰色标注（模块名/API/栈帧等）
  bool regValid = false;
  // CPU 面板可调比例（0-1 浮点，分隔条拖动更新）
  double cpuSplitX = 0.60;   // 左（反汇编/数据）与右（寄存器/堆栈）的分割位置
  double cpuSplitY = 0.62;   // 上（反汇编/寄存器）与下（数据/堆栈）的分割位置
  // 其余子窗口的分割比例（下标 = ChildType）：X=内容宽度比例(1.0=铺满)，Y=上下分割比例
  double mSplitX[10] = {1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0};
  double mSplitY[10] = {1.0, 1.0, 1.0, 1.0, 1.0, 0.50, 1.0, 1.0, 1.0, 1.0};
  HWND dragSplitWnd = nullptr;   // 正在拖动分割条所属的子窗口
  int dragSplit = 0;         // 0=无 1=拖竖条 2=拖横条
  POINT dragStart{};
  double dragBase = 0.0;
  int dragAreaW = 0, dragAreaH = 0;
  // 虚拟滚动条状态（映射内存地址）
  int vscrollPos = 100;       // 0-200，100=居中（当前地址）
  bool vscrollDragging = false;
  int vscrollHotArrow = 0;    // 正在按住的箭头按钮：-1 上 / +1 下 / 0 无
  ptruint vscrollAnchor = 0;  // 拖动开始时的视口锚点地址（防止增量累加）
  RECT vscrollRect{};         // 滚动条区域（相对 CPU 子窗口客户区）
  std::vector<std::wstring> disasmComments;  // 注释列（API 名 / 字符串）
  std::set<ptruint> disasmJumpTargets;       // 视口内被 jmp/call 指向的地址（行背景高亮）

  // 反汇编列布局（OllyDbg 式：地址|十六进制|反汇编|备注，竖线分隔、可拖动）
  // 边界均为相对列表客户区左缘的 x：addrEnd 固定，其余三条线可拖动
  // 默认值统一在 ThemeColors.h 的 DefaultSizes()（kDisAddrEnd 等宏）
  int disAddrEnd  = kDisAddrEnd;    // 地址栏右缘（红线，可拖动调地址栏宽）
  int disBytesEnd = kDisBytesEnd;   // 机器码列右缘（绿线）
  int disCmtX     = kDisCmtX;       // 备注列起点（橙线；蓝色指令列线已删——重复多余）
  int disDragCol  = 0;     // 正在拖动的分隔线：0=无 1/2/3
  // 转储/堆栈列宽（OD 式：地址|机器码 红线，机器码|备注 绿线，可拖动）
  int dumpCol1 = kDumpCol1;      // 转储 地址列右缘（红线）
  int dumpCol2 = kDumpCol2;      // 转储 机器码列右缘（绿线）
  int dumpDragCol = 0;     // 转储正在拖动的线：0/1/2
  int stkCol1  = kStkCol1;      // 堆栈 地址列右缘（红线）
  int stkCol2  = kStkCol2;      // 堆栈 数值列右缘（绿线）
  int stkDragCol = 0;      // 堆栈正在拖动的线：0/1/2
  bool followRip = true;                // 反汇编视口跟随 RIP（滚轮/GOTO 后置 false）

  // ---- 反汇编视口"读不到内容"的显式状态 ----
  // 为什么必须有：ReadProcessMemory 失败时如果什么都不做，面板会一直显示上一个
  // 地址的内容 —— 用户点了地址跳转/拖了滚动条都"没反应"，看起来像功能坏了（64 位
  // 加壳/受保护目标、跳到未提交页时最常见）。这里把失败变成可见状态。
  bool   disasmBad = false;        // 当前视口基址不可读
  ptruint disasmBadAddr = 0;       // 不可读的地址（提示行用）
  std::wstring disasmHint;         // 面板提示行文本（空=正常反汇编内容）
  std::wstring disasmHintAddr;     // 提示行左侧地址文本（12 位十六进制）
  // 转储面板系统滚动条基准（绝对映射窗口的锚点地址）
  ptruint dumpScrollBase = 0;
  int  stackOff = 0;               // 堆栈面板相对 RSP 的行偏移（滚动条/滚轮控制）

  bool uiRunning = false;  // UI 侧记录的运行状态

  bool driverLoaded = false;  // JfDebug 驱动在线状态（时钟 3s 轮询刷新）

  HFONT uiFont = nullptr;
  HFONT monoFont = nullptr;
};

static App g;

// CE 风格「谁访问/谁写入」入口（实现见文件后部，先给前面的子窗口过程做前置声明）
static bool    StartWatch(bool write, ptruint addr);
static void    WatchStopFind(const wchar_t* why);
static ptruint PickWatchAddress();
static void    StartRestoreAnalyze(ptruint addr);   // HOOK/VM 还原字节后台分析

//=============================================================================
// 字符串工具
//=============================================================================
static std::string ToA(const std::wstring& w) {
  if (w.empty()) return "";
  int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
  std::string a(n, 0);
  ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &a[0], n, nullptr, nullptr);
  return a;
}

static std::wstring ToW(const std::string& s) {
  if (s.empty()) return std::wstring();
  int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
  std::wstring w(n, 0);
  ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
  return w;
}

static std::string Trim(const std::string& s) {
  size_t a = s.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return "";
  size_t b = s.find_last_not_of(" \t\r\n");
  return s.substr(a, b - a + 1);
}

static std::string GetText(HWND h) {
  int n = ::GetWindowTextLengthA(h);
  std::string s(n + 1, '\0');
  ::GetWindowTextA(h, &s[0], n + 1);
  s.resize(n);
  return s;
}

// ---- UI 行为追踪：环境变量 CE_UITRACE=1 时写 exe 同目录 ui_trace.txt（诊断交互问题用）----
static void UiTrace(const std::string& tag) {
  static bool on = false, checked = false;
  if (!checked) {
    checked = true;
    char b[8] = {};
    ::GetEnvironmentVariableA("CE_UITRACE", b, sizeof(b));
    on = (b[0] == '1');
  }
  if (!on) return;
  static char path[MAX_PATH] = {};
  if (!path[0]) {
    ::GetModuleFileNameA(nullptr, path, MAX_PATH);
    char* s = std::strrchr(path, '\\');
    if (s) *(s + 1) = 0;
    std::strcat(path, "ui_trace.txt");
  }
  if (FILE* f = std::fopen(path, "ab")) {
    char t[40];
    std::snprintf(t, sizeof(t), "[%10u] ", (unsigned)::GetTickCount());
    std::fwrite(t, 1, std::strlen(t), f);
    std::fwrite(tag.data(), 1, tag.size(), f);
    std::fputc('\n', f);
    std::fclose(f);
  }
}

// ---- 状态栏暗色自绘：文本存本地表，控件按 SBT_OWNERDRAW 回调父窗口 WM_DRAWITEM ----
static std::wstring g_statusText[4];


static void StatusOwnerSet(int part, const std::wstring& s) {
  if (part < 0 || part >= 4) return;
  g_statusText[part] = s;
  // Win32 默认风格状态栏：SB_SETTEXTW 交给系统绘制（经典浅灰样式）
  if (g.status) ::SendMessageW(g.status, SB_SETTEXTW, (WPARAM)part, (LPARAM)s.c_str());
}

// 还原流程跟踪（设 CE_RESTORE_TIMING=1 生效，写 CEScanVC/restore_trace.txt）
// GUI 是 /SUBSYSTEM:WINDOWS，stderr 看不见，只能落文件。
static void RTrace(const char* fmt, ...) {
  if (!::getenv("CE_RESTORE_TIMING")) return;
  FILE* f = ::fopen("restore_trace.txt", "ab");
  if (!f) return;
  va_list ap;
  va_start(ap, fmt);
  std::fprintf(f, "[%8lu] ", (unsigned long)::GetTickCount());
  std::vfprintf(f, fmt, ap);
  std::fputc('\n', f);
  std::fclose(f);
  va_end(ap);
}

static void StatusText(const std::wstring& t) {
  StatusOwnerSet(0, t);
}

// 日志窗口尚未创建时先存在这里，窗口建好后一次性补写，避免丢行
static std::vector<std::string> g_pendingLog;

static void AddLogLine(const std::string& text) {
  std::string* copy = new std::string(text);
  ::PostMessageW(g.frame, WM_APP_LOG, 0, (LPARAM)copy);
}

// 页面守卫是否在监视中 / 被监视地址。
// g_watch 结构体定义在后面，而调试事件回调在前面，所以用这两个镜像变量，
// 让事件日志可以过滤掉「守卫机制自己造出来的」异常。
static volatile LONG g_guardWatchOn = 0;
static ptruint        g_guardWatchAddr = 0;
static inline bool GuardPageHit(ptruint fault) {
  if (!g_guardWatchOn) return false;
  const ptruint page = g_guardWatchAddr & ~(ptruint)0xFFF;
  return fault >= page && fault < page + 0x1000;
}

// 把攒下来的行补写进日志窗口（在日志窗口创建完成后调用）
static void FlushPendingLog() {
  if (g_pendingLog.empty()) return;
  std::vector<std::string> lines;
  lines.swap(g_pendingLog);
  for (const std::string& s : lines) AddLogLine(s);
}

static HWND Ctrl(HWND child, int id) { return ::GetDlgItem(child, id); }

//-----------------------------------------------------------------------------
// 日志数据窗口（OD Log data）：地址|消息 两列。行格式固定 "地址|消息"。
//-----------------------------------------------------------------------------
static std::vector<std::wstring> g_pendingLogData;   // 窗口未开先攒着

static void LogDataAdd(const std::wstring& addr, const std::wstring& msg) {
  std::wstring* row = new std::wstring(addr + L"|" + msg);
  ::PostMessageW(g.frame, WM_APP_LOGDATA, 0, (LPARAM)row);
}

// 窗口建好后把攒下的行一次性补进去
static void FlushPendingLogData() {
  if (g_pendingLogData.empty()) return;
  if (!g.logData || !::IsWindow(g.logData)) return;
  std::vector<std::wstring> rows;
  rows.swap(g_pendingLogData);
  HWND list = ::GetDlgItem(g.logData, IDC_LDLIST);
  for (const std::wstring& r : rows) {
    int idx = (int)::SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)r.c_str());
    ::SendMessageW(list, LB_SETTOPINDEX, idx, 0);
  }
}

static void AddListColumn(HWND list, const wchar_t* title, int width) {
  LVCOLUMNW c{};
  c.mask = LVCF_TEXT | LVCF_WIDTH;
  c.pszText = const_cast<LPWSTR>(title);
  c.cx = width;
  ::SendMessageW(list, LVM_INSERTCOLUMNW, 0x7FFF, (LPARAM)&c);
}

// ---------------------------------------------------------------------------
//  补丁「写法」输出：过检测 / VM还原 / 过CRC 的每一步都要可手工复现。
//  每行加 "# " 前缀发输出窗口（# 作为写法块的换行标记，整段可复制），
//  同时把整块写法复制到剪贴板（CF_UNICODETEXT），照着手工操作即可。
// ---------------------------------------------------------------------------
static void PostRecipe(const std::vector<std::string>& lines) {
  std::string block;
  for (const std::string& l : lines) {
    if (l.empty()) continue;
    AddLogLine("# " + l);
    block += "# " + l + "\r\n";
  }
  if (block.empty() || !::OpenClipboard(g.frame)) return;
  ::EmptyClipboard();
  const std::wstring w = ToW(block);
  HGLOBAL hg = ::GlobalAlloc(GMEM_MOVEABLE, (w.size() + 1) * sizeof(wchar_t));
  if (hg) {
    void* p = ::GlobalLock(hg);
    if (p) {
      std::memcpy(p, w.c_str(), (w.size() + 1) * sizeof(wchar_t));
      ::GlobalUnlock(hg);
    }
    if (::SetClipboardData(CF_UNICODETEXT, hg) == nullptr) ::GlobalFree(hg);
  }
  ::CloseClipboard();
}

//=============================================================================
// 数值显示
//=============================================================================
static std::string FormatValueBytes(VariableType type, bool hex, const unsigned char* p,
                                    int n) {
  char buf[128] = "";
  switch (type) {
    case VariableType::vtByte:
      std::snprintf(buf, sizeof(buf), hex ? "0x%02X" : "%u", p[0]);
      break;
    case VariableType::vtWord:
      std::snprintf(buf, sizeof(buf), hex ? "0x%04X" : "%u",
                    *reinterpret_cast<const unsigned short*>(p));
      break;
    case VariableType::vtDword:
      if (hex)
        std::snprintf(buf, sizeof(buf), "0x%08X", *reinterpret_cast<const unsigned*>(p));
      else
        std::snprintf(buf, sizeof(buf), "%d", *reinterpret_cast<const int*>(p));
      break;
    case VariableType::vtQword:
      if (hex)
        std::snprintf(buf, sizeof(buf), "0x%016llX",
                      (unsigned long long)*reinterpret_cast<const unsigned long long*>(p));
      else
        std::snprintf(buf, sizeof(buf), "%lld",
                      (long long)*reinterpret_cast<const long long*>(p));
      break;
    case VariableType::vtSingle:
      std::snprintf(buf, sizeof(buf), "%g", *reinterpret_cast<const float*>(p));
      break;
    case VariableType::vtDouble:
      std::snprintf(buf, sizeof(buf), "%g", *reinterpret_cast<const double*>(p));
      break;
    case VariableType::vtString:
    case VariableType::vtCodePageString:
      if (n > 0) return std::string(reinterpret_cast<const char*>(p), n - 1);
      return "";
    case VariableType::vtUnicodeString:
      if (n > 0) {
        std::wstring w(reinterpret_cast<const wchar_t*>(p), (n - 1) / 2);
        int m = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0,
                                      nullptr, nullptr);
        std::string s(m, 0);
        ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], m, nullptr,
                              nullptr);
        return s;
      }
      return "";
    case VariableType::vtByteArray:
    case VariableType::vtByteArrays: {
      std::string s;
      char b[8];
      for (int i = 0; i < n && i < 32; ++i) {
        std::snprintf(b, sizeof(b), "%02X ", p[i]);
        s += b;
      }
      return s;
    }
    case VariableType::vtBinary: {
      std::string s;
      for (int i = n - 1; i >= 0 && i < 8; --i)
        for (int bit = 7; bit >= 0; --bit) s += ((p[i] >> bit) & 1) ? '1' : '0';
      return s;
    }
    default:
      std::snprintf(buf, sizeof(buf), "(%d 字节)", n);
      return buf;
  }
  return buf;
}

//=============================================================================
// MDI 子窗口创建
//=============================================================================
static void CreateCpuControls(HWND child);
static void CreateScanControls(HWND child);
static void CreateMapControls(HWND child);
static void CreateThreadsControls(HWND child);
static void CreateBpsControls(HWND child);
static void CreateLogControls(HWND child);
static void CreateLogDataControls(HWND child);
static void CreateMcpControls(HWND child);
static void CreateStrsControls(HWND child);
static void LayoutChild(HWND child, ChildType type, int w, int h);

static void NewChild(ChildType type, const wchar_t* title, int w, int h) {
  MDICREATESTRUCTW mcs{};
  mcs.szClass = kChildClass;
  mcs.szTitle = title;
  mcs.hOwner = g.inst;
  mcs.x = 10; mcs.y = 10; mcs.cx = w; mcs.cy = h;
  mcs.style = WS_VISIBLE | WS_OVERLAPPEDWINDOW;
  mcs.lParam = (LPARAM)type;
  HWND child = (HWND)::SendMessageW(g.client, WM_MDICREATE, 0, (LPARAM)&mcs);

  // CPU 窗口默认最大化（其余保持原尺寸）
  if (type == kChildCpu && child)
    ::PostMessageW(g.client, WM_MDIMAXIMIZE, (WPARAM)child, 0);

  switch (type) {
    case kChildCpu: g.cpu = child; break;
    case kChildScan: g.scanWnd = child; break;
    case kChildMap: g.map = child; break;
    case kChildThreads: g.thr = child; break;
    case kChildBps: g.bps = child; break;
    case kChildLog: g.log = child; break;
    case kChildLogData: g.logData = child; break;
    case kChildMcp: g.mcp = child; break;
    case kChildStrs: g.strs = child; break;
  }
}

//=============================================================================
// 调试事件回调（调试线程）
//=============================================================================
static void OnDebugEvent(const DEBUG_EVENT& ev) {
  char buf[256];
  // 调试线程不许碰 g.proc（CachedModules 无锁懒加载会毁堆），
  // 模块名查询自己 OpenProcess（只做 PSAPI 查询，安全）
  static volatile LONG s_dbgPid = 0;
  switch (ev.dwDebugEventCode) {
    case CREATE_PROCESS_DEBUG_EVENT:
      std::snprintf(buf, sizeof(buf), "[事件] 进程创建 TID %u", ev.dwThreadId);
      s_dbgPid = ev.dwProcessId;
      LogDataAdd(L"", L"进程创建");
      if (ev.u.CreateProcessInfo.hFile) ::CloseHandle(ev.u.CreateProcessInfo.hFile);
      break;
    case CREATE_THREAD_DEBUG_EVENT: {
      std::snprintf(buf, sizeof(buf), "[事件] 线程创建 TID %u", ev.dwThreadId);
      wchar_t ab[16], tb[64];
      std::swprintf(ab, 16, L"%012llX",
                    (unsigned long long)(size_t)ev.u.CreateThread.lpStartAddress);
      std::swprintf(tb, 64, L"线程创建 TID %u", ev.dwThreadId);
      LogDataAdd(ab, tb);
      break;
    }
    case EXIT_THREAD_DEBUG_EVENT:
      std::snprintf(buf, sizeof(buf), "[事件] 线程退出 TID %u", ev.dwThreadId);
      LogDataAdd(L"", [&]{ wchar_t t[64]; std::swprintf(t, 64, L"线程退出 TID %u", ev.dwThreadId); return std::wstring(t); }());
      break;
    case EXIT_PROCESS_DEBUG_EVENT:
      std::snprintf(buf, sizeof(buf), "[事件] 目标进程退出");
      LogDataAdd(L"", L"目标进程退出");
      break;
    case LOAD_DLL_DEBUG_EVENT: {
      if (ev.u.LoadDll.hFile) ::CloseHandle(ev.u.LoadDll.hFile);
      // OD 式：Module <完整路径>（地址列=模块基址）。名字查不到就只报基址
      wchar_t path[MAX_PATH] = L"";
      HANDLE ph = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                FALSE, s_dbgPid);
      if (ph) {
        ::GetModuleFileNameExW(ph, (HMODULE)(size_t)ev.u.LoadDll.lpBaseOfDll,
                               path, MAX_PATH);
        ::CloseHandle(ph);
      }
      wchar_t ab[16];
      std::swprintf(ab, 16, L"%012llX",
                    (unsigned long long)(size_t)ev.u.LoadDll.lpBaseOfDll);
      LogDataAdd(ab, path[0] ? (L"Module " + std::wstring(path)) : L"Module");
      return;
    }
    case EXCEPTION_DEBUG_EVENT: {
      const EXCEPTION_RECORD& r = ev.u.Exception.ExceptionRecord;
      // 「谁访问/谁写入」每命中一次都会产生两条**我们自己造的**异常：
      //   0xC0000005（页守卫命中）+ 0x80000004（我们置 TF 后的单步）。
      // 把它们也写进日志，一分钟就能刷出几千行，把 [还原] 这类真正要看的
      // 输出彻底冲掉（还会被 3000 行上限裁掉），所以在这里过滤掉。
      if (r.ExceptionCode == 0x80000004u) return;          // STATUS_SINGLE_STEP
      if (r.ExceptionCode == 0xC0000005u && r.NumberParameters >= 2 &&
          GuardPageHit((ptruint)r.ExceptionInformation[1]))
        return;                                            // 守卫页上的 AV，是自己造的
      std::snprintf(buf, sizeof(buf), "[异常] TID %u  code=0x%08X  addr=%012llX",
                    ev.dwThreadId, r.ExceptionCode,
                    (unsigned long long)(size_t)r.ExceptionAddress);
      break;
    }
    default:
      return;
  }
  AddLogLine(buf);
}

// 「谁访问/谁写入」的轮次号。命中是调试线程 PostMessage 过来的，异步排队；
// 停止监视或重新开一轮时把它 +1，队列里上一轮残留的命中就会被丢弃。
// 不这么做的话：先看「谁访问」再看「谁写入」时，上一次排在队列里的读命中
// 会在新列表里冒出来，写入模式的窗口里会莫名其妙混进读指令。
static std::atomic<unsigned> g_watchGen{0};

// 已 PostMessage 出去、还没被 UI 线程处理的命中条数。
// 页面守卫在「这个值被高频读写」时会瞬间产生成千上万次命中；如果无节制地往
// 消息队列里塞，UI 线程会被彻底堵死（表现为监视窗口迟迟不刷新，而且下一次
// 监视的结果要等很久才出现——因为它在慢慢消化上一轮积压的消息）。
// 这里给在途条数封顶，超出就丢样本，但页面守卫本身照常工作。
static std::atomic<int> g_hitInFlight{0};
static const int kMaxHitInFlight = 2000;

// 丢掉队列里堆积的 WM_APP_HIT（停止/重开监视时调用，顺带释放 HitReport）
static void DropPendingHits() {
  MSG msg;
  while (::PeekMessageW(&msg, g.frame, WM_APP_HIT, WM_APP_HIT, PM_REMOVE)) {
    delete (HitReport*)msg.lParam;
  }
  g_hitInFlight.store(0);   // 队列已清空，在途计数归零
}

static void OnDebugHit(const HitReport& hit) {
  // 队列已经太深就丢样本，保证 UI 还能响应（计数按样本统计，CE 也是近似值）
  if (g_hitInFlight.load() >= kMaxHitInFlight) return;
  HitReport* copy = new HitReport(hit);
  if (::PostMessageW(g.frame, WM_APP_HIT, (WPARAM)g_watchGen.load(), (LPARAM)copy))
    ++g_hitInFlight;
  else
    delete copy;
}

//=============================================================================
// 扫描
//=============================================================================
static bool BuildRegionFilter(RegionFilter* f, HWND child) {
  *f = RegionFilter();
  if (::SendMessageW(Ctrl(child, IDC_WRONLY), BM_GETCHECK, 0, 0) == BST_CHECKED)
    f->SetWritableOnly();

  std::string mods = Trim(GetText(Ctrl(child, IDC_EXCMODS)));
  if (!mods.empty()) {
    std::string item;
    for (size_t i = 0; i <= mods.size(); ++i) {
      if (i == mods.size() || mods[i] == ',' || mods[i] == ';') {
        item = Trim(item);
        if (!item.empty()) {
          std::wstring w(item.begin(), item.end());
          f->excludeModules.push_back(w);
        }
        item.clear();
      } else {
        item.push_back(mods[i]);
      }
    }
  }
  std::string ranges = Trim(GetText(Ctrl(child, IDC_EXCRANGE)));
  if (!ranges.empty()) {
    std::string item;
    for (size_t i = 0; i <= ranges.size(); ++i) {
      if (i == ranges.size() || ranges[i] == ',') {
        item = Trim(item);
        size_t dash = item.find('-');
        if (dash != std::string::npos) {
          AddressRange r;
          r.start = std::strtoull(item.substr(0, dash).c_str(), nullptr, 16);
          r.stop = std::strtoull(item.substr(dash + 1).c_str(), nullptr, 16);
          if (r.stop > r.start) f->excludeRanges.push_back(r);
        }
        item.clear();
      } else {
        item.push_back(ranges[i]);
      }
    }
  }
  return true;
}

static bool BuildScanRequest(ScanRequest* req, HWND child) {
  *req = ScanRequest();
  req->hexadecimal =
      ::SendMessageW(Ctrl(child, IDC_HEX), BM_GETCHECK, 0, 0) == BST_CHECKED;

  HWND typeCombo = Ctrl(child, IDC_TYPE);
  int ti = (int)::SendMessageW(typeCombo, CB_GETCURSEL, 0, 0);
  if (ti >= 0) req->variableType = (VariableType)::SendMessageW(typeCombo, CB_GETITEMDATA, ti, 0);

  static const ScanOption kOptions[] = {
      ScanOption::soExactValue,     ScanOption::soBiggerThan,     ScanOption::soSmallerThan,
      ScanOption::soValueBetween,   ScanOption::soIncreasedValue, ScanOption::soIncreasedValueBy,
      ScanOption::soDecreasedValue, ScanOption::soDecreasedValueBy,
      ScanOption::soChanged,        ScanOption::soUnchanged,      ScanOption::soUnknownValue,
  };
  int oi = (int)::SendMessageW(Ctrl(child, IDC_OPTION), CB_GETCURSEL, 0, 0);
  if (oi >= 0 && oi < (int)(sizeof(kOptions) / sizeof(kOptions[0])))
    req->scanOption = kOptions[oi];

  req->value1 = Trim(GetText(Ctrl(child, IDC_V1)));
  req->value2 = Trim(GetText(Ctrl(child, IDC_V2)));
  BuildRegionFilter(&req->regionFilter, child);
  return true;
}

struct ScanJob {
  ScanRequest req;
  bool next;
};

// 扫描进度消息载荷：scanned/total 单位都是“字节”。由扫描后台线程 PostMessage
// 到 UI 线程，UI 据此驱动进度条与状态栏，让扫描一按下就有可视反馈（对应 CE 的
// “正在扫描…”实时进度）。
struct ScanPctMsg {
  qword scanned;
  qword total;
};

static DWORD WINAPI ScanThreadProc(void* p) {
  std::unique_ptr<ScanJob> job(static_cast<ScanJob*>(p));
  std::string err;

  // 与 CE 一致：扫描过程实时汇报进度。回调在扫描线程内被调用（FirstScan 等待循环、
  // NextScan 的 RescanResultList/RescanImage），按 ≤100ms 节流后 PostMessage 到 UI，
  // 避免结果极多时把 UI 消息队列塞爆。
  auto lastTick = ::GetTickCount64();
  g.scan.SetProgressCallback([lastTick](qword scanned, qword total) mutable {
    const ULONGLONG now = ::GetTickCount64();
    if (scanned < total && now - lastTick < 100) return;  // 节流：非终态且未到时间窗
    lastTick = now;
    auto* m = new ScanPctMsg{scanned, total};
    ::PostMessageW(g.frame, WM_APP_SCAN_PRG, 0, (LPARAM)m);
  });

  // 立刻反馈“正在扫描”，不用等 BuildRegions 枚举完 x64 大地址空间才有反应
  ::PostMessageW(g.frame, WM_APP_SCAN_PRG, 0, (LPARAM)new ScanPctMsg{0, 0});

  bool ok = job->next ? g.scan.NextScan(job->req, &err) : g.scan.FirstScan(job->req, &err);
  if (!ok && err.empty()) err = "扫描失败";
  if (!ok) ::PostMessageW(g.frame, WM_APP_SCAN_ERR, 0, (LPARAM)new std::string(err));
  ::PostMessageW(g.frame, WM_APP_SCAN_DONE, ok ? 1 : 0, 0);
  ScanPctMsg* doneMsg = new ScanPctMsg{g.scan.Stats().totalBytes, g.scan.Stats().totalBytes};
  ::PostMessageW(g.frame, WM_APP_SCAN_PRG, 0, (LPARAM)doneMsg);
  g.scanning = false;
  return 0;
}

static void StartScan(bool next, HWND child) {
  if (g.scanning.load()) return;
  if (!g.proc.IsOpen()) {
    ::MessageBoxW(child, L"请先通过 文件-附加进程 选择目标", L"提示",
                  MB_OK | MB_ICONINFORMATION);
    return;
  }
  ScanJob* job = new ScanJob();
  BuildScanRequest(&job->req, child);
  job->next = next;
  g.scanning = true;
  HWND prog = Ctrl(child, IDC_PROG);
  ::SendMessageW(prog, PBM_SETRANGE, 0, MAKELPARAM(0, 1000));  // 进度条 0..1000
  ::SendMessageW(prog, PBM_SETPOS, 0, 0);
  std::thread(ScanThreadProc, job).detach();
}

static void RefreshResultList(HWND child) {
  HWND list = Ctrl(child, IDC_RESULTS);
  ListView_SetItemCountEx(list, g.scan.ResultCount(), 0);  // 0 标志 = 自动重绘
  ::InvalidateRect(list, nullptr, TRUE);                   // 虚拟列表必须强制重绘
  wchar_t buf[160];
  std::swprintf(buf, 160, L"结果数: %zu    区域数: %d    用时: %.2f 秒",
                g.scan.ResultCount(), g.scan.Stats().regionCount,
                g.scan.Stats().elapsedSeconds);
  ::SetWindowTextW(Ctrl(child, IDC_COUNT), buf);
}

//=============================================================================
// CPU 面板
//=============================================================================
static DWORD PickFocusTid() {
  // 命中过的线程优先，否则取目标第一个线程
  HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return 0;
  const DWORD pid = g.dbg.Pid();
  DWORD first = 0;
  THREADENTRY32 te{};
  te.dwSize = sizeof(te);
  if (::Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID != pid) continue;
      if (first == 0) first = te.th32ThreadID;
      if (te.th32ThreadID == g.focusTid) {
        ::CloseHandle(snap);
        return g.focusTid;
      }
    } while (::Thread32Next(snap, &te));
  }
  ::CloseHandle(snap);
  g.focusTid = first;
  return first;
}


//=============================================================================
// 反汇编注释列：解析目标进程 PE 导出表 → API 名；探测内存 → 字符串
//=============================================================================
static void UpdateCpuWindow();
// 轻量版：只重建反汇编视口（不碰寄存器 GetThreadContext / API 解析 / 数据·堆栈面板）。
// 滚动条拖动等高频场景直接调用；返回有效基址（0=不可用）。
static ptruint DisasmRefreshViewport();
// 轻量版：只重建数据（转储）面板（转储滚动条/滚轮高频路径用）
static void RefreshDumpPanel();

static std::map<ptruint, std::wstring> BuildExportMap(const ModuleEntry& m) {
  std::map<ptruint, std::wstring> out;
  unsigned char hdr[4096];
  if (g.proc.ReadPartial(m.base, hdr, sizeof(hdr)) < 512) return out;
  if (hdr[0] != 'M' || hdr[1] != 'Z') return out;
  int e_lfanew = 0; std::memcpy(&e_lfanew, hdr + 0x3C, 4);
  if (e_lfanew <= 0 || e_lfanew > 2048) return out;
  unsigned int exportRva = 0;
  std::memcpy(&exportRva, hdr + e_lfanew + 0x18 + 112, 4);  // PE32+ OptionalHeader.ExportDirectory
  if (!exportRva) return out;
  unsigned char ed[4096];
  if (g.proc.ReadPartial(m.base + exportRva, ed, sizeof(ed)) < 40) return out;
  unsigned int numberOfFunctions = 0, numberOfNames = 0, addrFunc = 0, addrNames = 0, addrOrds = 0;
  std::memcpy(&numberOfFunctions, ed + 0x14, 4);   // NumberOfFunctions
  std::memcpy(&numberOfNames, ed + 0x18, 4);       // NumberOfNames
  std::memcpy(&addrFunc, ed + 0x1C, 4);            // AddressOfFunctions
  std::memcpy(&addrNames, ed + 0x20, 4);           // AddressOfNames
  std::memcpy(&addrOrds, ed + 0x24, 4);            // AddressOfNameOrdinals
  if (!numberOfFunctions || numberOfFunctions > 300000) return out;
  if (!numberOfNames || numberOfNames > 300000) numberOfNames = 0;
  // AddressOfFunctions 有 NumberOfFunctions 项（>= NumberOfNames），必须按它分配，
  // 否则 ordinals[] 里指向高位序号的导出会被整体丢弃（KERNEL32 大量转发导出属此列）
  std::vector<unsigned int> funcs(numberOfFunctions);
  std::vector<unsigned int> names(numberOfNames ? numberOfNames : 1);
  std::vector<unsigned short> ords(numberOfNames ? numberOfNames : 1);
  g.proc.ReadPartial(m.base + addrNames, names.data(), numberOfNames * 4);
  g.proc.ReadPartial(m.base + addrOrds, ords.data(), numberOfNames * 2);
  g.proc.ReadPartial(m.base + addrFunc, funcs.data(), funcs.size() * 4);
  char nb[160];
  for (unsigned int i = 0; i < numberOfNames; ++i) {
    if (!names[i]) continue;
    if (g.proc.ReadPartial(m.base + names[i], nb, sizeof(nb) - 1) < 4) continue;
    nb[sizeof(nb) - 1] = 0;
    unsigned short o = ords[i];
    if (o >= funcs.size()) continue;
    const unsigned int fnRva = funcs[o];
    if (fnRva == 0) continue;
    // 转发导出（RVA 落在导出目录内 → 指向 "DLL.Func" 字符串），跳过
    if (fnRva >= exportRva && fnRva < exportRva + 0x10000) continue;
    ptruint fn = m.base + fnRva;
    if (out.count(fn)) continue;
    out[fn] = ToW(std::string(nb));
  }
  return out;
}

static std::wstring StripExt(const std::wstring& n) {
  size_t d = n.find_last_of(L'.');
  return d == std::wstring::npos ? n : n.substr(0, d);
}

// API 名 / 导出表缓存：**跨目标必须清空**。
// 以前这两个缓存是 ResolveApiName 里的函数内 static，重新附加新进程时不会失效：
// 导出表按模块名缓存（key 只有 "ntdll.dll" 这种名字），于是换目标后注释列会拿
// 上一个进程的导出地址去匹配 —— 32/64 位目标来回切换时满屏注释错乱就是这样来的。
static std::unordered_map<ptruint, std::wstring> g_apiNameCache;
static std::map<std::wstring, std::map<ptruint, std::wstring>> g_exportCache;

static void ResetApiNameCache() {
  g_apiNameCache.clear();
  g_exportCache.clear();
}

static std::wstring ResolveApiName(ptruint addr) {
  if (addr == 0) return std::wstring();
  auto it = g_apiNameCache.find(addr);
  if (it != g_apiNameCache.end()) return it->second;
  std::wstring res;
  const std::vector<ModuleEntry>& mods = g.proc.CachedModules();
  const ModuleEntry* m = ProcessMemory::FindModule(mods, addr);
  if (m) {
    auto eit = g_exportCache.find(m->name);
    if (eit == g_exportCache.end()) {
      auto em = BuildExportMap(*m);
      eit = g_exportCache.emplace(m->name, std::move(em)).first;
    }
    auto fit = eit->second.find(addr);
    if (fit != eit->second.end()) res = StripExt(m->name) + L"." + fit->second;
  }
  g_apiNameCache.emplace(addr, res);
  return res;
}

static std::wstring ProbeString(ptruint addr) {
  if (addr < 0x10000) return L"";
  unsigned char buf[96];
  size_t got = g.proc.ReadPartial(addr, buf, sizeof(buf) - 2);
  if (got < 4) return L"";
  // ASCII / GBK 前缀探测
  {
    int n = 0;
    while (n < (int)got && n < 64 && ((buf[n] >= 0x20 && buf[n] < 0x7F) || buf[n] == '\t')) ++n;
    if (n >= 4) {
      std::string t((const char*)buf, (size_t)n);
      return L"\"" + ToW(t) + L"\"";
    }
  }
  // UTF-16LE 探测
  {
    int n = 0;
    while (n + 1 < (int)got && n < 64) {
      wchar_t c = (wchar_t)(buf[n] | (buf[n + 1] << 8));
      if (c >= 0x20 && c < 0x7F) { n += 2; continue; }
      if (c >= 0x4E00 && c <= 0x9FFF) { n += 2; continue; }  // CJK
      break;
    }
    if (n >= 8) {
      std::wstring t;
      for (int k = 0; k < n; k += 2) t += (wchar_t)(buf[k] | (buf[k + 1] << 8));
      return L"L\"" + t + L"\"";
    }
  }
  return L"";
}

static std::wstring BuildDisasmComment(const DisasmResult& dr, ptruint self) {
  (void)self;
  // 间接调用/跳转（FF 15 等）mini-disasm 不设 isCall，按文本前缀识别
  const bool isBranch = dr.isCall || dr.isJump ||
                        dr.text.rfind("call", 0) == 0 || dr.text.rfind("jmp", 0) == 0;
  // 1) 直接跳转/调用目标 → API 名；非 API 则给 模块+偏移
  if (isBranch && dr.jumpTarget) {
    std::wstring api = ResolveApiName(dr.jumpTarget);
    if (!api.empty()) return api;
    const std::vector<ModuleEntry>& mods = g.proc.CachedModules();
    const ModuleEntry* m = ProcessMemory::FindModule(mods, dr.jumpTarget);
    if (m && dr.jumpTarget != m->base) {
      wchar_t buf[128];
      std::swprintf(buf, 128, L"%hs+%llX", ToA(StripExt(m->name)).c_str(),
                    (unsigned long long)(dr.jumpTarget - m->base));
      return buf;
    }
  }
  // 2) 从指令文本提取 0x 地址：间接调用 → 读 IAT 指针解析 API；其他 → 字符串/API 探测
  for (size_t pos = dr.text.find("0x"); pos != std::string::npos;
       pos = dr.text.find("0x", pos + 1)) {
    unsigned long long v = std::strtoull(dr.text.c_str() + pos + 2, nullptr, 16);
    ptruint tok = (ptruint)v;
    if (tok < 0x10000) continue;
    if (isBranch) {
      unsigned long long fp = 0;
      if (g.proc.ReadPartial(tok, (unsigned char*)&fp, 8) == 8 && fp > 0x10000) {
        std::wstring api = ResolveApiName((ptruint)fp);
        if (!api.empty()) return api;
      }
      std::wstring api = ResolveApiName(tok);
      if (!api.empty()) return api;
    } else {
      // 非分支指令：地址本身是导出函数（如 mov eax, <API地址>）也解析
      std::wstring api = ResolveApiName(tok);
      if (!api.empty()) return api;
    }
    std::wstring s = ProbeString(tok);
    if (!s.empty()) return s;
  }
  // 3) 常见指令简短说明（无地址信息时备注列也有内容）
  {
    auto has = [&dr](const char* p) { return dr.text.rfind(p, 0) == 0; };
    if (has("syscall") || has("int 2e")) return L"系统调用";
    if (has("sysenter")) return L"系统调用";
    if (has("leave"))    return L"恢复栈帧";
    if (has("nop"))      return L"空操作";
    if (has("cdq") || has("cwde")) return L"符号扩展";
    if (has("ret") || has("retn")) return L"返回";
    if (has("hlt"))      return L"停机";
    if (has("int3"))     return L"断点";
    if (has("ud2"))      return L"未定义指令";
    if (has("endbr"))    return L"分支边界";
  }
  return L"";
}

//=============================================================================
// 反汇编滚轮滚动：向下跳过前 N 条指令；向上从候选起点重新反汇编对齐
//   性能：以前每格滚轮都调 UpdateCpuWindow()（GetThreadContext + 寄存器标注 +
//   数据/堆栈面板整块重建），滚起来明显卡；这里改走轻量 DisasmRefreshViewport()。
//   健壮性：视口处于"地址不可读"状态时（disasmLines 为空）按固定 16 字节步进平移，
//   保证滚轮/滚动条任何时候都能把视口挪走，而不是原地卡死。
//=============================================================================
static void DisasmScroll(int lines) {
  if (g.cpu == nullptr || !IsWindow(g.cpu)) return;
  if (lines == 0) return;
  ptruint base = g.disasmBase;
  if (base == 0) return;

  if (g.disasmBad || g.disasmAddr.empty() || g.disasmLines.empty()) {
    // 没有可用的指令长度：按固定步长平移（滚轮向上/向下都能脱开不可读地址）
    const long long delta = (long long)lines * 16;
    const long long nb = (long long)base + delta;
    if (nb <= 0x1000) return;
    g.disasmBase = (ptruint)nb;
    g.followRip = false;
    DisasmRefreshViewport();
    return;
  }

  if (lines > 0) {
    for (int i = 0; i < lines && i < (int)g.disasmLines.size(); ++i)
      base += g.disasmLines[i].length;
  } else {
    const int want = -lines;
    // 在 base 之前一小段里找"反汇编恰好落在 base 上、且条数正好 want"的起点。
    // 旧实现在第一个命中的 d 上就停下：容器的填充字节（连续的 1~2 字节指令）很容易
    // 凑出恰好 want 步，于是对齐到假的指令边界 → 汇编码整屏变成垃圾。
    // 这里把所有候选都试一遍，优先选**不产生 db 兜底**的候选，再取跨度最大的。
    // 性能：整段只读一次（以前每个候选各读一次 → 一趟滚轮 40+ 次 RPM）。
    const int maxD = want * 15 < 48 ? want * 15 : 48;   // 单条指令最长 15 字节
    int bestD = 0, bestScore = -1;
    if ((ptruint)maxD < base) {
      const ptruint win = base - (ptruint)maxD;
      unsigned char code[64];                           // maxD(48) + 单条最长(15) ≤ 64
      const size_t got = g.proc.ReadPartial(win, code, sizeof(code));
      for (int d = 1; d <= maxD && (size_t)d <= got; ++d) {
        const size_t off0 = (size_t)(maxD - d);         // 候选起点在缓冲里的位置
        const ptruint cand = base - (ptruint)d;
        const size_t avail = got - off0;
        ptruint a = cand;
        int steps = 0, dbCount = 0;
        while (a < base && (size_t)(a - cand) < avail) {
          const size_t rel = (size_t)(a - cand);
          DisasmResult dr;
          int n = Disassemble(code + off0 + rel, avail - rel, a, &dr);
          if (n <= 0) break;
          if (dr.text.rfind("db ", 0) == 0) ++dbCount;  // 兜底指令（多半是错位）
          a += n; ++steps;
        }
        if (a == base && steps == want) {
          const int score = -dbCount * 100 + d;         // 无兜底优先，其次跨度大
          if (score > bestScore) { bestScore = score; bestD = d; }
        }
      }
    }
    if (bestD > 0) base -= (ptruint)bestD;
    else if (base > 16) base -= 16;                     // 实在对不齐：退 16 字节兜底
    else return;
  }
  g.disasmBase = base;
  g.followRip = false;  // 用户滚动后停止跟随 RIP
  DisasmRefreshViewport();
}

//=============================================================================
// 寄存器面板（OD 风格，纯自绘单窗口——非 LISTBOX，避免条目重复绘制）
// 布局严格对照 OD 截图：
//   8 行 GPR（名称黄 / 值白 / 灰色标注）
//   EIP（值品红）
//   EFL（值蓝 + 括号标志解码）
//   段寄存器 2x3 表：ES/CS/SS/DS/FS/GS（值 + "32位" + base 0(FFFFFFFF)）
//=============================================================================
static LRESULT CALLBACK RegPanelProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  switch (m) {
    case WM_PAINT: {
      PAINTSTRUCT ps;
      HDC dc = ::BeginPaint(h, &ps);
      RECT rc; ::GetClientRect(h, &rc);
      const COLORREF bg = kRegBg;                    // 纯黑背景（配色见 ThemeColors.h）
      HBRUSH br = ::CreateSolidBrush(bg);
      ::FillRect(dc, &rc, br);
      ::DeleteObject(br);
      ::SetBkColor(dc, bg);
      ::SelectObject(dc, g.monoFont);

      // 标题栏（中性深灰底白字，去蓝调）
      RECT title{rc.left, rc.top, rc.right, rc.top + 20};
      HBRUSH tb = ::CreateSolidBrush(kSplitFace);
      ::FillRect(dc, &title, tb);
      ::DeleteObject(tb);
      ::SetBkColor(dc, kSplitFace);
      ::SetTextColor(dc, kDisBytesFg);
      ::TextOutW(dc, rc.left + 4, rc.top + 3, L"寄存器 (FPU)", 9);

      int y = title.bottom + 4;
      if (!g.regValid) {
        ::SetBkColor(dc, bg);
        ::SetTextColor(dc, kRegNoteFg);
        ::TextOutW(dc, rc.left + 8, y, L"[未附加进程]", 8);
        ::EndPaint(h, &ps);
        return 0;
      }

      auto line = [&](const wchar_t* name, const std::wstring& val,
                      const std::wstring& note, COLORREF valC) {
        ::SetBkColor(dc, bg);
        ::SetTextColor(dc, kRegNameFg);              // 寄存器名黄
        ::TextOutW(dc, rc.left + 8, y, name, (int)wcslen(name));
        ::SetTextColor(dc, valC);
        ::TextOutW(dc, rc.left + 62, y, val.c_str(), (int)val.size());
        if (!note.empty()) {
          ::SetTextColor(dc, kRegNoteFg);            // 标注灰
          ::TextOutW(dc, rc.left + 160, y, note.c_str(), (int)note.size());
        }
        y += 18;
      };

      static const wchar_t* GN[8] = {L"EAX",L"ECX",L"EDX",L"EBX",L"ESP",L"EBP",L"ESI",L"EDI"};
      wchar_t v[64];
      for (int i = 0; i < 8; ++i) {
        std::swprintf(v, 64, L"%08llX", g.regVals[i] & 0xFFFFFFFFull);
        line(GN[i], v, g.regNotes[i], kRegValueFg);
      }
      // EIP 品红
      std::swprintf(v, 64, L"%08llX", g.regVals[16] & 0xFFFFFFFFull);
      line(L"EIP", v, g.regNotes[16], kRegEipFg);

      y += 4;
      // EFL + 括号解码（对照截图 "00000246 (NO,NB,E,BE,NS,PE,GE,LE)"）
      unsigned efl = (unsigned)g.regVals[17];
      std::swprintf(v, 64, L"%08X", efl);
      std::wstring fl = L"(";
      fl += (efl & 0x400) ? L"O1," : L"NO,";
      fl += (efl & 0x400) ? L"" : L"NB,";
      fl += (efl & 0x080) ? L"NG," : L"PL,";
      fl += (efl & 0x004) ? L"ZR," : L"NZ,";
      fl += (efl & 0x010) ? L"AC," : L"NA,";
      fl += (efl & 0x001) ? L"PE," : L"PO,";
      fl += (efl & 0x040) ? L"CY)" : L"NC)";
      {
        ::SetTextColor(dc, kRegEflFg);
        ::TextOutW(dc, rc.left + 8, y, L"EFL", 3);
        ::SetTextColor(dc, kRegFlagFg);
        ::TextOutW(dc, rc.left + 62, y, v, (int)wcslen(v));
        ::SetTextColor(dc, kRegNoteFg);
        ::TextOutW(dc, rc.left + 160, y, fl.c_str(), (int)fl.size());
        y += 18;
      }

      y += 4;
      // 段寄存器 2 列 x 3 行：ES/CS/SS | DS/FS/GS（对照截图排布）
      struct Seg { const wchar_t* n; unsigned val; };
      Seg segs[6] = {{L"ES", (unsigned)g.regVals[18]}, {L"CS", (unsigned)g.regVals[19]},
                     {L"SS", (unsigned)g.regVals[20]}, {L"DS", (unsigned)g.regVals[21]},
                     {L"FS", 0x53}, {L"GS", 0x2B}};
      for (int row = 0; row < 3; ++row) {
        for (int col = 0; col < 2; ++col) {
          const Seg& sg = segs[row * 2 + col];
          int x = rc.left + 8 + col * 190;
          wchar_t sv[96];
          std::swprintf(sv, 96, L"%c 0 %hs %03X 32位 0(FFFFFFFF)",
                        (row * 2 + col) % 3 == 0 ? L'C' : L' ',
                        ToA(sg.n).c_str(), sg.val);
          ::SetTextColor(dc, kRegSegFg);
          ::TextOutW(dc, x, y, sv, (int)wcslen(sv));
        }
        y += 17;
      }

      // 栈顶返回提示（灰）
      y += 6;
      if (g.regVals[4]) {
        unsigned long long ret = 0;
        if (g.proc.ReadPartial((ptruint)g.regVals[4], (unsigned char*)&ret, 8) == 8 && ret > 0x10000) {
          std::wstring api = ResolveApiName((ptruint)ret);
          wchar_t sv[200];
          if (!api.empty()) {
            std::swprintf(sv, 200, L"栈顶返回 → %s", api.c_str());
            ::SetTextColor(dc, kRegNoteFg);
            ::TextOutW(dc, rc.left + 8, y, sv, (int)wcslen(sv));
          }
        }
      }

      ::EndPaint(h, &ps);
      return 0;
    }
    case WM_ERASEBKGND:
      return 1;   // 防闪：背景在 WM_PAINT 里整体填充
    case WM_LBUTTONDBLCLK:
      UpdateCpuWindow();
      return 0;
  }
  return ::DefWindowProcW(h, m, wp, lp);
}

static WNDPROC s_oldDisProc = nullptr;
static WNDPROC s_oldSplitVProc = nullptr, s_oldSplitHProc = nullptr;
static WNDPROC s_oldVScrollProc = nullptr;
static WNDPROC s_oldCmdEdit = nullptr;   // Command 输入框子类
static HWND g_cmdEdit = nullptr;
static WNDPROC s_oldDumpProc = nullptr;

//=============================================================================
// 数据（转储）/堆栈面板的系统滚动条
//   以前的问题：转储的 WM_VSCROLL 只认 SB_LINE*/SB_PAGE*，拖滑块发的是
//   SB_THUMBTRACK/SB_THUMBPOSITION，落到 default 分支 → 拖滑块完全没反应；
//   而且每次重建都把 nPos 复位成 0、范围只有(可见行+4) → 滑块永远贴顶。
//   堆栈面板更彻底：一个 WM_VSCROLL 处理都没有 → 滚动条纯摆设。
//   现在：滑块位置与内容地址**绝对映射**在一个 ±128KB 的窗口里，拖动即可定位；
//   超出窗口时重新锚定到中段（保证永远拖得动）。
//=============================================================================
static constexpr int kScrollWinRows = 0x2000;        // 滑块行程 8192 行
static constexpr int kScrollHalf    = kScrollWinRows / 2;

// 转储面板：滑块位置(行) ↔ dumpBase
static int DumpBarPos() {
  const long long d = (long long)g.dumpBase - (long long)g.dumpScrollBase;
  long long r = d / 16;
  if (r < 0) r = 0;
  if (r > kScrollWinRows) r = kScrollWinRows;
  return (int)r;
}
static void DumpBarSync(HWND h, int visibleRows) {
  int p = DumpBarPos();
  if (p <= 0 || p >= kScrollWinRows) {          // 出窗口：重新锚定到窗口中间
    const ptruint half = (ptruint)kScrollHalf * 16;
    g.dumpScrollBase = (g.dumpBase > half) ? (g.dumpBase - half) : 0;
    p = DumpBarPos();
  }
  SCROLLINFO si{};
  si.cbSize = sizeof(si);
  si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS | SIF_DISABLENOSCROLL;
  si.nMin = 0;
  si.nMax = kScrollWinRows;
  si.nPage = (visibleRows > 0 ? (UINT)visibleRows : 1u);
  si.nPos = p;
  ::SetScrollInfo(h, SB_VERT, &si, TRUE);
}
// 转储：把 dumpBase 移动 rows 行（16 字节/行），并保底不为负
static void DumpMoveRows(long long rows) {
  long long v = (long long)g.dumpBase + rows * 16;
  if (v < 0) v = 0;
  g.dumpBase = (ptruint)v;
}
// 堆栈面板：滑块位置(0-0xFFFF) ↔ 相对 RSP 的行偏移，中点 = RSP
static void StackBarSync(HWND h, int visibleRows) {
  if (g.stackOff < -kScrollHalf) g.stackOff = -kScrollHalf;
  if (g.stackOff > kScrollHalf) g.stackOff = kScrollHalf;
  SCROLLINFO si{};
  si.cbSize = sizeof(si);
  si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS | SIF_DISABLENOSCROLL;
  si.nMin = 0;
  si.nMax = kScrollWinRows;
  si.nPage = (visibleRows > 0 ? (UINT)visibleRows : 1u);
  si.nPos = kScrollHalf + g.stackOff;      // 中点=栈顶
  ::SetScrollInfo(h, SB_VERT, &si, TRUE);
}

static LRESULT CALLBACK DumpListProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  switch (m) {
    case WM_MOUSEWHEEL: {
      int delta = (short)HIWORD(wp);
      int rows = delta > 0 ? -3 : 3;
      DumpMoveRows(rows);
      RefreshDumpPanel();          // 轻量：只重建转储面板（不再全量刷新）
      return 0;
    }
    case WM_VSCROLL: {
      const int req = LOWORD(wp);
      if (req == SB_THUMBTRACK || req == SB_THUMBPOSITION) {
        // 拖滑块：绝对定位（HIWORD(wp) = 滑块位置，行程 8192 < 32767 不会截断）
        const int pos = (int)HIWORD(wp);
        const ptruint nb = g.dumpScrollBase + (ptruint)pos * 16;
        g.dumpBase = nb;
        RefreshDumpPanel();        // 轻量：拖滑块只重画转储面板
        return 0;
      }
      int rows = 0;
      if (req == SB_LINEDOWN) rows = 1;
      else if (req == SB_LINEUP) rows = -1;
      else if (req == SB_PAGEDOWN) rows = 12;
      else if (req == SB_PAGEUP) rows = -12;
      else if (req == SB_BOTTOM) rows = 256;
      else if (req == SB_TOP) rows = -256;
      else if (req == SB_ENDSCROLL) return 0;
      if (rows) {
        DumpMoveRows(rows);
        RefreshDumpPanel();        // 轻量：只重建转储面板
      }
      return 0;
    }
  }
  return ::CallWindowProcW(s_oldDumpProc, h, m, wp, lp);
}
// 滚动条位置(0-200) -> 相对锚点地址的偏移（OD 式相对滚动条）
// pos 100 = 锚点不动；向上拖看更小地址，向下拖看更大地址。
// 必须传拖动开始时的锚点 anchor，否则拖动过程中每次都基于已移动的 base 计算，会越拖越快
static ptruint VScrollToAddr(int pos, ptruint anchor) {
  long long delta = ((long long)pos - 100) * 0x20;  // 每格 0x20 字节（满行程 ±0x1900）
  if (delta >= 0) return anchor + (ptruint)delta;
  return (anchor > (ptruint)(-delta)) ? anchor - (ptruint)(-delta) : 0;
}
// 分割条窗口类（所有子窗口通用）：竖条 IDC_SPLIT_V 左右拖动改宽度，
//                   横条 IDC_SPLIT_H 上下拖动改高度
static const wchar_t* kSplitClass = L"CEScanSplit";
// 反汇编虚拟滚动条窗口类（OD 式相对滚动竖条）
static const wchar_t* kVScrollClass = L"CEScanVScroll";

// 取某子窗口的分割比例（CPU 用 cpuSplitX/Y，其余用 mSplitX/mSplitY）
static double& WinSplitX(ChildType t) {
  return (t == kChildCpu) ? g.cpuSplitX : g.mSplitX[(int)t];
}
static double& WinSplitY(ChildType t) {
  return (t == kChildCpu) ? g.cpuSplitY : g.mSplitY[(int)t];
}

static LRESULT CALLBACK SplitProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  const bool isV = (int)::GetDlgCtrlID(h) == IDC_SPLIT_V;
  HWND parent = ::GetParent(h);
  const ChildType t = (ChildType)(INT_PTR)::GetWindowLongPtrW(parent, GWLP_USERDATA);
  // 每个子窗口一种分割条色相（颜色可辨、互不相同，用户要求）：
  // 竖条=本色，横条=同色相加深到 60%，拖动中=整体加亮提示可交互
  auto splitColor = [&](bool hot) -> COLORREF {
    static const COLORREF base[10] = {
      RGB(0, 0, 0),
      RGB(46, 106, 214),   // CPU      蓝
      RGB(214, 130, 36),   // 扫描     橙
      RGB(38, 172, 182),   // 内存图   青
      RGB(150, 84, 200),   // 线程     紫
      RGB(198, 172, 40),   // 断点     金黄
      RGB(64, 168, 76),    // 日志     绿
      RGB(200, 72, 124),   // MCP      玫红
      RGB(104, 132, 184),  // 字符串   钢蓝
      RGB(140, 140, 152),  // 日志数据 灰
    };
    int i = (int)t;
    if (i < 1 || i > 9) i = 9;
    COLORREF c = base[i];
    if (!isV) c = RGB(GetRValue(c) * 6 / 10, GetGValue(c) * 6 / 10, GetBValue(c) * 6 / 10);
    if (hot) c = RGB(GetRValue(c) / 2 + 128, GetGValue(c) / 2 + 128, GetBValue(c) / 2 + 128);
    return c;
  };
  switch (m) {
    case WM_ERASEBKGND:
      return 1;
    case WM_PAINT: {
      PAINTSTRUCT ps;
      HDC dc = ::BeginPaint(h, &ps);
      RECT rc; ::GetClientRect(h, &rc);
      // 拖动中高亮，提示可交互
      const bool hot = (g.dragSplit != 0 && g.dragSplitWnd == parent &&
                        g.dragSplit == (isV ? 1 : 2));
      HBRUSH br = ::CreateSolidBrush(splitColor(hot));
      ::FillRect(dc, &rc, br);
      ::DeleteObject(br);
      // 中线：常态用本色调亮，拖动中用亮蓝白
      COLORREF lineC = hot ? RGB(240, 248, 255)
                           : splitColor(false) ;  // 常态中线=本色（同底色则整条纯色更醒目）
      HPEN pen = ::CreatePen(PS_SOLID, 1, lineC);
      HPEN op = (HPEN)::SelectObject(dc, pen);
      if (isV) {
        ::MoveToEx(dc, rc.right / 2, 0, nullptr);
        ::LineTo(dc, rc.right / 2, rc.bottom);
      } else {
        ::MoveToEx(dc, 0, rc.bottom / 2, nullptr);
        ::LineTo(dc, rc.right, rc.bottom / 2);
      }
      ::SelectObject(dc, op);
      ::DeleteObject(pen);
      ::EndPaint(h, &ps);
      return 0;
    }
    case WM_SETCURSOR:
      ::SetCursor(::LoadCursor(nullptr, isV ? IDC_SIZEWE : IDC_SIZENS));
      return TRUE;
    case WM_LBUTTONDOWN: {
      RECT rc; ::GetClientRect(parent, &rc);
      g.dragSplit = isV ? 1 : 2;
      g.dragSplitWnd = parent;
      ::GetCursorPos(&g.dragStart);
      g.dragBase = isV ? WinSplitX(t) : WinSplitY(t);
      g.dragAreaW = rc.right - 16;
      g.dragAreaH = (t == kChildCpu) ? (rc.bottom - 38) : (rc.bottom - 16);
      ::SetCapture(h);
      ::InvalidateRect(h, nullptr, FALSE);
      return 0;
    }
    case WM_MOUSEMOVE: {
      if (g.dragSplit && g.dragSplitWnd == parent && (wp & MK_LBUTTON)) {
        POINT now; ::GetCursorPos(&now);
        if (isV && g.dragAreaW > 120) {
          double nx = g.dragBase + (now.x - g.dragStart.x) / (double)g.dragAreaW;
          if (nx < 0.12) nx = 0.12;
          if (nx > 1.0) nx = 1.0;
          WinSplitX(t) = nx;
        } else if (!isV && g.dragAreaH > 100) {
          double ny = g.dragBase + (now.y - g.dragStart.y) / (double)g.dragAreaH;
          if (ny < 0.15) ny = 0.15;
          if (ny > 1.0) ny = 1.0;
          WinSplitY(t) = ny;
        }
        RECT rc; ::GetClientRect(parent, &rc);
        LayoutChild(parent, t, rc.right, rc.bottom);
        ::InvalidateRect(h, nullptr, FALSE);
      }
      return 0;
    }
    case WM_LBUTTONUP:
      if (g.dragSplit && g.dragSplitWnd == parent) {
        g.dragSplit = 0;
        g.dragSplitWnd = nullptr;
        ::ReleaseCapture();
        ::InvalidateRect(h, nullptr, FALSE);
      }
      return 0;
  }
  return ::DefWindowProcW(h, m, wp, lp);
}

// 在子窗口里创建一根分割条（id = IDC_SPLIT_V 竖 / IDC_SPLIT_H 横）
static void MakeSplitter(HWND child, int id) {
  static bool reg = false;
  if (!reg) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = SplitProc;
    wc.hInstance = g.inst;
    wc.hCursor = ::LoadCursor(nullptr, IDC_SIZEWE);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = kSplitClass;
    ::RegisterClassW(&wc);
    reg = true;
  }
  ::CreateWindowExW(0, kSplitClass, nullptr, WS_CHILD | WS_VISIBLE,
                    0, 0, kSplitBar + 2, kSplitBar + 2, child, (HMENU)(INT_PTR)id, g.inst, nullptr);
}

// 自绘虚拟滚动条（OD 式相对滚动）：反汇编面板右缘竖条，
// 拖动实时平移视口地址，松手滑块回中、地址保持在拖到的位置（视口不弹回）
static LRESULT CALLBACK VScrollProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  // 滚动条几何：上下各一个 17px 箭头按钮（经典滚动条样式）
  constexpr int kArrowH = 17;
  // y 坐标 -> 0-200（轨道在两个箭头之间，再各留 20px 死区）
  auto posFromY = [&](LPARAM lp) {
    RECT rc; ::GetClientRect(h, &rc);
    int top = kArrowH + 20, bottom = rc.bottom - kArrowH - 20;
    int trackH = bottom - top;
    if (trackH < 1) trackH = 1;
    int y = (short)HIWORD(lp);
    int p = (y - top) * 200 / trackH;
    if (p < 0) p = 0;
    if (p > 200) p = 200;
    return p;
  };
  // 箭头命中：-1 上 / +1 下 / 0 未命中
  auto arrowFromY = [&](LPARAM lp) {
    RECT rc; ::GetClientRect(h, &rc);
    int y = (short)HIWORD(lp);
    if (y < kArrowH) return -1;
    if (y >= rc.bottom - kArrowH) return 1;
    return 0;
  };
  // 按当前位置平移视口（以拖动起点为锚，避免增量累加）。
  // 性能关键：拖动时 WM_MOUSEMOVE 可达 125-500Hz，全量 UpdateCpuWindow（寄存器
  // GetThreadContext + API 名解析 + 数据/堆栈面板）会淹没消息队列 → 用户实测非常卡顿。
  // 这里只走轻量视口重建，并按 25ms 节流；跳帧无损（pos 是相对锚点的绝对映射，
  // 跳到最新值即为正确位置，松手时再补一次终帧）。
  auto apply = [&](int pos) {
    ptruint newBase = VScrollToAddr(pos, g.vscrollAnchor);
    if (newBase != 0) {
      g.disasmBase = newBase;
      g.followRip = false;
      static DWORD s_lastApply = 0;
      DWORD now = ::GetTickCount();
      if (now - s_lastApply >= 25) {
        s_lastApply = now;
        DisasmRefreshViewport();
        char tb[96];
        std::snprintf(tb, sizeof(tb), "vscroll apply pos=%d base=%012llX", pos,
                      (unsigned long long)newBase);
        UiTrace(tb);
      }
    }
    ::InvalidateRect(h, nullptr, FALSE);
  };
  // 箭头滚动（换锚点模式）：向上看更小地址 / 向下看更大地址
  auto arrowScroll = [&](int dir) {
    g.vscrollAnchor = g.disasmBase;   // 以当前位置为锚
    g.vscrollPos = 100 + dir * 10;    // 相当于拖动滑块偏移 10 格（约 0x140 字节）
    ptruint newBase = VScrollToAddr(g.vscrollPos, g.vscrollAnchor);
    if (newBase != 0) {
      g.disasmBase = newBase;
      g.followRip = false;
      DisasmRefreshViewport();
    }
    g.vscrollPos = 100;               // 立即回中
    ::InvalidateRect(h, nullptr, FALSE);
  };
  // 按住箭头的自动重复（WM_TIMER）：首次 400ms 后每 80ms 一步
  auto startRepeat = [&](int dir) {
    g.vscrollHotArrow = dir;
    ::SetCapture(h);
    ::SetTimer(h, 1, 400, nullptr);
    arrowScroll(dir);
  };
  switch (m) {
    case WM_TIMER:
      if (wp == 1 && g.vscrollHotArrow != 0) {
        ::KillTimer(h, 1);
        ::SetTimer(h, 1, 80, nullptr);   // 加速为连续滚动
        arrowScroll(g.vscrollHotArrow);
      }
      return 0;
    case WM_PAINT: {
      PAINTSTRUCT ps;
      HDC dc = ::BeginPaint(h, &ps);
      RECT rc; ::GetClientRect(h, &rc);
      // 系统默认配色 + 经典凹凸外观（用户要求滚动条与系统一致）
      HBRUSH track = ::CreateSolidBrush(::GetSysColor(COLOR_SCROLLBAR));
      ::FillRect(dc, &rc, track);
      ::DeleteObject(track);
      // 中点刻度（100 = 当前视口，OD 式相对滚动基准线）——画在轨道区中部
      int midY = (rc.top + rc.bottom) / 2;
      RECT mid{rc.left + 2, midY - 1, rc.right - 2, midY + 1};
      HBRUSH mb = ::CreateSolidBrush(::GetSysColor(COLOR_GRAYTEXT));
      ::FillRect(dc, &mid, mb);
      ::DeleteObject(mb);
      // 滑块（位置按 vscrollPos 0-200，纵向，限于箭头之间的轨道区）：经典凹凸立体
      const int thumbH = 40;
      const int trackTop = rc.top + kArrowH;
      const int trackBot = rc.bottom - kArrowH;
      int ty = trackTop + (trackBot - trackTop - thumbH) * g.vscrollPos / 200;
      RECT thumb{rc.left + 1, ty, rc.right - 1, ty + thumbH};
      HBRUSH tb = ::CreateSolidBrush(::GetSysColor(COLOR_BTNFACE));
      ::FillRect(dc, &thumb, tb);
      ::DeleteObject(tb);
      ::DrawEdge(dc, &thumb, g.vscrollDragging ? EDGE_SUNKEN : EDGE_RAISED,
                 BF_RECT | BF_ADJUST);
      // 上下箭头按钮（经典滚动条样式：凸起 + 黑色三角，按住时凹陷）
      auto drawArrow = [&](int atTop) {
        RECT b{rc.left, atTop ? rc.top : rc.bottom - kArrowH,
               rc.right, atTop ? rc.top + kArrowH : rc.bottom};
        HBRUSH fb = ::CreateSolidBrush(::GetSysColor(COLOR_BTNFACE));
        ::FillRect(dc, &b, fb);
        ::DeleteObject(fb);
        const bool pressed = (g.vscrollHotArrow == (atTop ? -1 : 1));
        ::DrawEdge(dc, &b, pressed ? EDGE_SUNKEN : EDGE_RAISED, BF_RECT | BF_ADJUST);
        // 三角形（黑）
        int cx = (b.left + b.right) / 2;
        int cy = (b.top + b.bottom) / 2;
        POINT tri[3];
        if (atTop) { tri[0] = {cx - 4, cy + 2}; tri[1] = {cx + 4, cy + 2}; tri[2] = {cx, cy - 3}; }
        else       { tri[0] = {cx - 4, cy - 2}; tri[1] = {cx + 4, cy - 2}; tri[2] = {cx, cy + 3}; }
        HBRUSH tb2 = ::CreateSolidBrush(RGB(0, 0, 0));
        HBRUSH ob = (HBRUSH)::SelectObject(dc, tb2);
        ::Polygon(dc, tri, 3);
        ::SelectObject(dc, ob);
        ::DeleteObject(tb2);
      };
      drawArrow(TRUE);
      drawArrow(FALSE);
      ::EndPaint(h, &ps);
      return 0;
    }
    case WM_LBUTTONDOWN: {
      const int arrow = arrowFromY(lp);
      if (arrow != 0) {                 // 点在箭头上：滚动 + 按住连续
        startRepeat(arrow);
        return 0;
      }
      g.vscrollDragging = true;
      g.vscrollAnchor = g.disasmBase;   // 锚定拖动起点地址
      ::SetCapture(h);
      g.vscrollPos = posFromY(lp);
      apply(g.vscrollPos);
      return 0;
    }
    case WM_MOUSEMOVE: {
      if (g.vscrollDragging && (wp & MK_LBUTTON)) {
        g.vscrollPos = posFromY(lp);
        apply(g.vscrollPos);
      }
      return 0;
    }
    case WM_LBUTTONUP:
      if (g.vscrollHotArrow != 0) {     // 松开箭头：停止连续滚动
        g.vscrollHotArrow = 0;
        ::KillTimer(h, 1);
        if (::GetCapture() == h) ::ReleaseCapture();
        ::InvalidateRect(h, nullptr, FALSE);
        return 0;
      }
      if (g.vscrollDragging) {
        g.vscrollDragging = false;
        // 补一次终帧：25ms 节流可能吞掉最后一个 WM_MOUSEMOVE，确保停住的位置生效
        ptruint finalBase = VScrollToAddr(g.vscrollPos, g.vscrollAnchor);
        if (finalBase != 0 && finalBase != g.disasmBase) {
          g.disasmBase = finalBase;
          g.followRip = false;
          DisasmRefreshViewport();
        }
        char tb[96];
        std::snprintf(tb, sizeof(tb), "vscroll up pos=%d final=%012llX", g.vscrollPos,
                      (unsigned long long)finalBase);
        UiTrace(tb);
        ::ReleaseCapture();
        // 松手滑块回中：视口地址留在当前位置（"一直保持在这里"）
        g.vscrollPos = 100;
        ::InvalidateRect(h, nullptr, FALSE);
      }
      return 0;
  }
  return ::DefWindowProcW(h, m, wp, lp);
}

// 有效列分隔线位置：把存储列宽按当前客户区宽度钳制，
// 保证三条线（红=地址栏右缘、绿=机器码右缘、橙=备注起点）都在可视范围内且互不重叠
// （原蓝色"指令列右缘"线已删——与备注起点线重复；指令列宽度实际由橙线决定）
static void DisasmCols(int cw, int& ea, int& e1, int& e3) {
  // 红线：地址+流程线区右缘，可拖动（最窄 100px，右侧至少留 210px 给机器码+指令）
  int maxA = cw - 210; if (maxA < 100) maxA = 100;
  ea = g.disAddrEnd < 100 ? 100 : (g.disAddrEnd > maxA ? maxA : g.disAddrEnd);
  // 绿线：机器码列右缘（红线右侧至少 60px，右缘保 150px）
  const int min1 = ea + 60;
  int maxL1 = cw - 150; if (maxL1 < min1) maxL1 = min1;
  e1 = g.disBytesEnd < min1 ? min1 : (g.disBytesEnd > maxL1 ? maxL1 : g.disBytesEnd);
  // 橙线：备注列起点（绿线右侧至少 60px，右缘保 70px）
  const int minL3 = e1 + 60;
  int maxL3 = cw - 70;  if (maxL3 < minL3) maxL3 = minL3;
  e3 = g.disCmtX < minL3 ? minL3 : (g.disCmtX > maxL3 ? maxL3 : g.disCmtX);
}

// 分隔线命中检测：返回 1/2/3 表示红/绿/橙线（±4px 内），0=未命中
static int DisasmHitSplit(HWND h, int mx) {
  RECT rc{};
  ::GetClientRect(h, &rc);
  int ea, e1, e3;
  DisasmCols(rc.right, ea, e1, e3);
  const int cols[3] = { ea, e1, e3 };
  for (int i = 0; i < 3; ++i)
    if (mx >= cols[i] - 4 && mx <= cols[i] + 4) return i + 1;
  return 0;
}

// ---- 转储/堆栈列分隔线（OD 式：地址|机器码=红，机器码|备注=绿，可拖动）----
// 有效列位置：把存储列宽按客户区宽度钳制，两条线互不重叠
static void DumpCols(int cw, int& e1, int& e2) {
  int hi1 = cw - kDumpRightKeep; if (hi1 < kColMinW) hi1 = kColMinW;
  e1 = g.dumpCol1 < kColMinW ? kColMinW : (g.dumpCol1 > hi1 ? hi1 : g.dumpCol1);
  const int lo = e1 + kDumpHexGap, hi2 = cw - kColMinW;
  e2 = g.dumpCol2 < lo ? lo : (g.dumpCol2 > hi2 ? hi2 : g.dumpCol2);
}
static void StkCols(int cw, int& e1, int& e2) {
  int hi1 = cw - kStkRightKeep; if (hi1 < kColMinW) hi1 = kColMinW;
  e1 = g.stkCol1 < kColMinW ? kColMinW : (g.stkCol1 > hi1 ? hi1 : g.stkCol1);
  const int lo = e1 + kStkHexGap, hi2 = cw - kColMinW;
  e2 = g.stkCol2 < lo ? lo : (g.stkCol2 > hi2 ? hi2 : g.stkCol2);
}
// 命中检测：返回 1/2 表示第几条线（±4px 内），0=未命中
static int ColHit2(int mx, int e1, int e2) {
  if (mx >= e1 - 4 && mx <= e1 + 4) return 1;
  if (mx >= e2 - 4 && mx <= e2 + 4) return 2;
  return 0;
}
// 转储/堆栈列表子类化：列分隔线拖动（同反汇编列线交互），其余消息透传
// （转储透传给 DumpListProc——滚轮/滚动条联动 dumpBase；堆栈透传系统原过程）
static WNDPROC s_oldStkProc = nullptr;
static LRESULT CALLBACK ColDragListProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  const bool isDump = (int)::GetDlgCtrlID(h) == IDC_DUMP;
  switch (m) {
    case WM_SETCURSOR: {
      if (LOWORD(lp) == HTCLIENT) {
        POINT pt; ::GetCursorPos(&pt); ::ScreenToClient(h, &pt);
        RECT rc; ::GetClientRect(h, &rc);
        int e1, e2;
        if (isDump) DumpCols(rc.right, e1, e2); else StkCols(rc.right, e1, e2);
        if (ColHit2(pt.x, e1, e2) > 0) {
          ::SetCursor(::LoadCursor(nullptr, IDC_SIZEWE));
          return TRUE;
        }
      }
      break;
    }
    case WM_LBUTTONDOWN: {
      const int mx = (short)LOWORD(lp);
      RECT rc; ::GetClientRect(h, &rc);
      int e1, e2;
      if (isDump) DumpCols(rc.right, e1, e2); else StkCols(rc.right, e1, e2);
      const int hit = ColHit2(mx, e1, e2);
      if (hit > 0) {
        if (isDump) g.dumpDragCol = hit; else g.stkDragCol = hit;
        ::SetCapture(h);
        return 0;   // 命中线：不当作行选择
      }
      break;
    }
    case WM_MOUSEMOVE: {
      if ((wp & MK_LBUTTON) && ::GetCapture() == h) {
        const int mx = (short)LOWORD(lp);
        int& c1 = isDump ? g.dumpCol1 : g.stkCol1;
        int& c2 = isDump ? g.dumpCol2 : g.stkCol2;
        int drag = isDump ? g.dumpDragCol : g.stkDragCol;
        if (drag == 1) c1 = mx;
        else if (drag == 2) c2 = mx;
        else break;
        ::InvalidateRect(h, nullptr, TRUE);
        return 0;
      }
      break;
    }
    case WM_LBUTTONUP: {
      int& drag = isDump ? g.dumpDragCol : g.stkDragCol;
      if (drag > 0) {
        drag = 0;
        if (::GetCapture() == h) ::ReleaseCapture();
        return 0;
      }
      break;
    }
    // 堆栈面板的系统滚动条 / 滚轮：OD 式相对栈顶滚动（中点 = RSP）
    // （以前这两个消息直接透传给原过程，滚动条是死的）
    case WM_VSCROLL: {
      if (isDump) break;                    // 转储由 DumpListProc 处理
      const int req = LOWORD(wp);
      if (req == SB_THUMBTRACK || req == SB_THUMBPOSITION)
        g.stackOff = (int)HIWORD(wp) - kScrollHalf;
      else if (req == SB_LINEDOWN) g.stackOff += 1;
      else if (req == SB_LINEUP)   g.stackOff -= 1;
      else if (req == SB_PAGEDOWN) g.stackOff += 16;
      else if (req == SB_PAGEUP)   g.stackOff -= 16;
      else if (req == SB_BOTTOM)   g.stackOff += 256;
      else if (req == SB_TOP)      g.stackOff -= 256;
      else if (req == SB_ENDSCROLL) return 0;
      if (g.stackOff < -kScrollHalf) g.stackOff = -kScrollHalf;
      if (g.stackOff >  kScrollHalf) g.stackOff =  kScrollHalf;
      UpdateCpuWindow();
      return 0;
    }
    case WM_MOUSEWHEEL: {
      if (isDump) break;                    // 转储由 DumpListProc 处理
      g.stackOff += ((short)HIWORD(wp) > 0) ? -3 : 3;
      if (g.stackOff < -kScrollHalf) g.stackOff = -kScrollHalf;
      if (g.stackOff >  kScrollHalf) g.stackOff =  kScrollHalf;
      UpdateCpuWindow();
      return 0;
    }
  }
  return isDump ? DumpListProc(h, m, wp, lp)
                : (s_oldStkProc ? ::CallWindowProcW(s_oldStkProc, h, m, wp, lp)
                                : ::DefWindowProcW(h, m, wp, lp));
}

// 右键菜单用到的前置声明（定义在文件后面）
static void ToggleBpOnSelectedLine();   // F2 / 右键断点切换
static void ShowGotoDlg(HWND frame);    // 右键-地址跳转小窗

// 纯文本写剪贴板（CF_UNICODETEXT）
static void CopyTextToClipboard(const std::wstring& text) {
  if (text.empty() || !::OpenClipboard(g.frame)) return;
  ::EmptyClipboard();
  const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
  HGLOBAL hg = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
  if (hg) {
    void* p = ::GlobalLock(hg);
    if (p) { std::memcpy(p, text.c_str(), bytes); ::GlobalUnlock(hg); }
    if (::SetClipboardData(CF_UNICODETEXT, hg) == nullptr) ::GlobalFree(hg);
  }
  ::CloseClipboard();
}

static void UpdateCmdInfoLine();   // 命令栏信息行（定义在 UpdateCpuWindow 前）
static LRESULT CALLBACK DisasmListProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  switch (m) {
    case WM_MOUSEWHEEL: {
      int delta = (short)HIWORD(wp);
      DisasmScroll(delta > 0 ? -3 : 3);
      return 0;
    }
    case WM_SETCURSOR: {
      if (LOWORD(lp) == HTCLIENT) {
        POINT pt;
        ::GetCursorPos(&pt);
        ::ScreenToClient(h, &pt);
        if (DisasmHitSplit(h, pt.x) > 0) {
          ::SetCursor(::LoadCursor(nullptr, IDC_SIZEWE));
          return TRUE;
        }
      }
      break;
    }
    case WM_VSCROLL: {
      // 滚动条事件 → 地址联动
      int req = LOWORD(wp);
      if (req == SB_LINEDOWN)       DisasmScroll(1);
      else if (req == SB_LINEUP)    DisasmScroll(-1);
      else if (req == SB_PAGEDOWN)  DisasmScroll(16);
      else if (req == SB_PAGEUP)    DisasmScroll(-16);
      else if (req == SB_BOTTOM)    DisasmScroll(64);
      else if (req == SB_TOP)       DisasmScroll(-64);
      return 0;
    }
    case WM_LBUTTONDOWN: {
      // 命中列分隔线 → 进入拖动模式，不当作行选择
      const int hit = DisasmHitSplit(h, (short)LOWORD(lp));
      if (hit > 0) {
        g.disDragCol = hit;
        ::SetCapture(h);
        return 0;
      }
      g.disDragCol = 0;
      const int lineH = 18;
      int idx = (int)(((short)HIWORD(lp)) / lineH) +
                (int)::SendMessageW(h, LB_GETTOPINDEX, 0, 0);
      const int n = (int)g.disasmAddr.size();
      if (n > 0) {
        if (idx >= n) idx = n - 1;
        if (idx >= 0) {
          const ptruint a = g.disasmAddr[idx];
          if (wp & MK_CONTROL) {
            // Ctrl：按地址加/减选
            if (g.multiAddrs.count(a)) g.multiAddrs.erase(a);
            else { g.multiAddrs.insert(a); g.selAddr = a; }
          } else if (wp & MK_SHIFT) {
            // Shift：从锚点地址到本行地址的区间（按视口行序遍历填地址）
            g.multiAddrs.clear();
            if (g.selAddr != 0) {
              // 找锚点行号
              int anchor = -1;
              for (int i = 0; i < n; ++i)
                if (g.disasmAddr[i] == g.selAddr) { anchor = i; break; }
              if (anchor < 0) anchor = idx;
              int lo = anchor < idx ? anchor : idx;
              int hi = anchor < idx ? idx : anchor;
              for (int i = lo; i <= hi; ++i) g.multiAddrs.insert(g.disasmAddr[i]);
            } else {
              g.multiAddrs.insert(a);
            }
          } else {
            g.multiAddrs.clear();
            g.selAddr = a;
            g.disasmSel = idx;
            UpdateCmdInfoLine();
            ::SetCapture(h);
          }
          ::InvalidateRect(h, nullptr, TRUE);
        }
      }
      return 0;  // 接管：不让系统 LISTBOX 画自己的选中条
    }
    case WM_MOUSEMOVE: {
      // 拖动分隔线：1=红线(地址栏右缘，拖动调地址栏宽) 2=绿线(机器码右缘) 3=橙线(备注起点)
      // （原蓝线已删；指令列宽度实际由橙线决定）
      if (::GetCapture() == h && g.disDragCol > 0) {
        const int mx = (short)LOWORD(lp);
        RECT rc{};
        ::GetClientRect(h, &rc);
        int ea, e1, e3;
        DisasmCols(rc.right, ea, e1, e3);
        if (g.disDragCol == 1) {
          // 红线：拖动调地址栏宽度，范围 [100, cw-210]
          int hi = rc.right - 210; if (hi < 100) hi = 100;
          g.disAddrEnd = mx < 100 ? 100 : (mx > hi ? hi : mx);
        } else if (g.disDragCol == 2) {
          // 绿线：只改机器码列右缘，范围 [ea+60, cw-150]
          int hi = rc.right - 150; if (hi < ea + 60) hi = ea + 60;
          g.disBytesEnd = mx < ea + 60 ? ea + 60 : (mx > hi ? hi : mx);
        } else if (g.disDragCol == 3) {
          // 橙线：只改备注列起点，范围 [e1+60, cw-70]
          int lo = e1 + 60;
          int hi = rc.right - 70; if (hi < lo) hi = lo;
          g.disCmtX = mx < lo ? lo : (mx > hi ? hi : mx);
        }
        ::InvalidateRect(h, nullptr, TRUE);
        return 0;
      }
      // 拖动刷选（单选/多选公用）：鼠标移出列表上下边缘时自动连续滚动，
      // 选区随滚动持续延伸 → 可无限往下/往上拖
      if (::GetCapture() == h && (wp & MK_LBUTTON) && !(wp & MK_SHIFT) && !(wp & MK_CONTROL)) {
        const int lineH = 18;
        RECT rc{};
        ::GetClientRect(h, &rc);
        int my = (short)HIWORD(lp);
        // 自动滚动：低于顶/底 14px 触发，越界越远滚得越快（每 120ms 一行起步）
        static POINT s_lastPt = {0, 0};
        s_lastPt.x = (short)LOWORD(lp); s_lastPt.y = my;
        if (my < 14) {
          // 向上滚（次数随超出距离加大）
          int steps = 1 + (14 - my) / 10;
          while (steps-- > 0) DisasmScroll(-1);
        } else if (my > rc.bottom - 14) {
          int steps = 1 + (my - (rc.bottom - 14)) / 10;
          while (steps-- > 0) DisasmScroll(1);
        }
        // 重建视口后把鼠标 y 夹回可视区，计算当前指向的行地址
        if (my < 0) my = 0;
        if (my > rc.bottom - 1) my = rc.bottom - 1;
        int idx = (my / lineH) + (int)::SendMessageW(h, LB_GETTOPINDEX, 0, 0);
        const int n = (int)g.disasmAddr.size();
        if (idx >= n) idx = n - 1;
        if (idx >= 0 && g.selAddr != 0) {
          // 拖动刷选：锚点地址到当前行地址区间
          g.multiAddrs.clear();
          int anchor = -1;
          for (int i = 0; i < n; ++i)
            if (g.disasmAddr[i] == g.selAddr) { anchor = i; break; }
          if (anchor < 0) anchor = idx;
          int lo = anchor < idx ? anchor : idx;
          int hi = anchor < idx ? idx : anchor;
          for (int i = lo; i <= hi; ++i) g.multiAddrs.insert(g.disasmAddr[i]);
          ::InvalidateRect(h, nullptr, TRUE);
        }
      }
      break;
    }
    case WM_LBUTTONUP:
      if (g.disDragCol > 0) g.disDragCol = 0;   // 结束拖动分隔线
      if (::GetCapture() == h) ::ReleaseCapture();
      break;
    case WM_CONTEXTMENU: {
      // 反汇编右键菜单：地址跳转 / 切换断点 / 复制行地址
      {
        char tb[80];
        std::snprintf(tb, sizeof(tb), "WM_CONTEXTMENU wp=%p self=%p", (void*)wp, (void*)h);
        UiTrace(tb);
      }
      if ((HWND)wp != h) break;
      POINT pt; ::GetCursorPos(&pt);
      POINT cpt = pt; ::ScreenToClient(h, &cpt);
      // 光标下的行（不在内容行上时只提供地址跳转）
      int hitIdx = -1;
      {
        RECT rc{}; ::GetClientRect(h, &rc);
        if (cpt.y >= 0 && cpt.y < rc.bottom) {
          const int lineH = 18;
          hitIdx = (cpt.y / lineH) + (int)::SendMessageW(h, LB_GETTOPINDEX, 0, 0);
          if (hitIdx >= (int)g.disasmAddr.size()) hitIdx = -1;
        }
      }
      HMENU menu = ::CreatePopupMenu();
      ::AppendMenuW(menu, MF_STRING, 1, L"地址跳转");
      if (hitIdx >= 0) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING, 2, L"切换断点(F2)");
        ::AppendMenuW(menu, MF_STRING, 3, L"复制行地址");
      }
      // 前台化宿主窗口：避免菜单点外面不消失（Win32 经典坑）
      HWND frame = ::GetAncestor(h, GA_ROOT);
      ::SetForegroundWindow(frame);
      int cmd = ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD,
                                 pt.x, pt.y, 0, h, nullptr);
      ::DestroyMenu(menu);
      ::PostMessageW(frame, WM_NULL, 0, 0);
      {
        char tb[48];
        std::snprintf(tb, sizeof(tb), "menu cmd=%d hit=%d", cmd, hitIdx);
        UiTrace(tb);
      }
      if (cmd == 1) {
        ShowGotoDlg(frame);
      } else if (cmd == 2 && hitIdx >= 0) {
        g.disasmSel = hitIdx;
        g.selAddr = g.disasmAddr[hitIdx];
        ToggleBpOnSelectedLine();
        ::InvalidateRect(h, nullptr, TRUE);
      } else if (cmd == 3 && hitIdx >= 0) {
        char b[32];
        std::snprintf(b, sizeof(b), "%012llX", (unsigned long long)g.disasmAddr[hitIdx]);
        CopyTextToClipboard(ToW(std::string(b)));
      }
      return 0;
    }
    case WM_KEYDOWN:
      if (wp == 'A' && (::GetKeyState(VK_CONTROL) & 0x8000)) {
        g.multiAddrs.clear();
        for (int i = 0; i < (int)g.disasmAddr.size(); ++i)
          g.multiAddrs.insert(g.disasmAddr[i]);
        ::InvalidateRect(h, nullptr, TRUE);
        return 0;
      }
      if (wp == VK_ESCAPE) {
        g.multiAddrs.clear();
        g.selAddr = 0;
        ::InvalidateRect(h, nullptr, TRUE);
        return 0;
      }
      break;
  }
  return ::CallWindowProcW(s_oldDisProc, h, m, wp, lp);
}

//=============================================================================
// 视口地址不可读：把"读不到"变成看得见的状态
//   以前失败时静默返回，面板保留上一个地址的反汇编内容 → 用户以为跳转/滚动坏了。
//   这里清空旧行（含旧选中/多选，它们指向的内容已经不在了）、在面板顶部留一行
//   说明、写日志窗口 + 状态栏，并且同一地址只记一次日志（避免 500ms 定时器刷屏）。
//=============================================================================
static void ShowDisasmUnreadable(ptruint addr) {
  const bool first = !g.disasmBad || g.disasmBadAddr != addr;
  g.disasmBad = true;
  g.disasmBadAddr = addr;

  // 旧内容全部作废：不清掉的话，自绘行会拿旧地址去显示新位置
  g.disasmAddr.clear();
  g.disasmLines.clear();
  g.disasmComments.clear();
  g.disasmJumpTargets.clear();
  g.multiAddrs.clear();
  g.selAddr = 0;
  g.disasmSel = -1;

  char ab[32];
  std::snprintf(ab, sizeof(ab), "%012llX", (unsigned long long)addr);
  g.disasmHintAddr = ToW(std::string(ab));
  g.disasmHint = L"该地址读不到内容（ReadProcessMemory 失败）—— 可能未提交、未映射，"
                 L"或被目标的反调试/反作弊拦掉了；换可执行区块内的地址再试";

  HWND disList = Ctrl(g.cpu, IDC_DISASM);
  if (disList && IsWindow(disList)) {
    wchar_t line[512];
    std::swprintf(line, 512, L"%s   ?  %s", g.disasmHintAddr.c_str(), g.disasmHint.c_str());
    ::SendMessageW(disList, WM_SETREDRAW, FALSE, 0);
    ::SendMessageW(disList, LB_RESETCONTENT, 0, 0);
    ::SendMessageW(disList, LB_ADDSTRING, 0, (LPARAM)line);
    ::SendMessageW(disList, WM_SETREDRAW, TRUE, 0);
    ::SendMessageW(disList, LB_SETTOPINDEX, 0, 0);
    ::InvalidateRect(disList, nullptr, FALSE);
  }

  if (first) {
    char mb[160];
    std::snprintf(mb, sizeof(mb), "反汇编视口: %s 读不到内存（RPM 失败）", ab);
    AddLogLine(mb);
    {
      wchar_t sb[200];
      std::swprintf(sb, 200, L"反汇编: %hs 不可读（跳转/滚动已生效，但该地址没有可读内存）", ab);
      StatusText(sb);
    }
    char tb[128];
    std::snprintf(tb, sizeof(tb), "disasm UNREADABLE base=%s", ab);
    UiTrace(tb);
  }
  UpdateCmdInfoLine();
}

//=============================================================================
// 轻量视口刷新：只重建反汇编列表（拖动滚动条等高频路径专用，不走全量刷新）。
// 返回有效基址（0=未附加或窗口不可用），UpdateCpuWindow 里 dump 初始化复用该值。
//=============================================================================
static ptruint DisasmRefreshViewport() {
  if (g.cpu == nullptr || !IsWindow(g.cpu)) return 0;
  if (!g.dbg.IsAttached()) return 0;
  HWND disList = Ctrl(g.cpu, IDC_DISASM);
  // 反汇编视口：跟随 RIP 或用户滚动位置
  ptruint rip = g.disasmBase;
  if (rip == 0 && g.currentRip) rip = g.disasmBase = g.currentRip;
  if (rip != 0) {
    // 防闪烁：基址和 RIP 都没变就不重建（只重绘断点/选中等覆盖状态）
    const bool needRebuild = (rip != g.lastDisasmBase) || g.disasmAddr.empty();
    if (needRebuild) {
      unsigned char code[320];
      size_t got = g.proc.ReadPartial(rip, code, sizeof(code));
      {
        char tb[96];
        std::snprintf(tb, sizeof(tb), "disasm rebuild base=%012llX got=%zu",
                      (unsigned long long)rip, got);
        UiTrace(tb);
      }
      if (got > 0) {
        g.disasmBad = false;
        g.disasmHint.clear();
        g.disasmHintAddr.clear();
        // 视口行数：按面板实际高度算（每行 18px）+ 2 行缓冲让滚动条常驻
      RECT arc{};
      ::GetClientRect(disList, &arc);
      const int disRows = arc.bottom > 36 ? (arc.bottom - 4) / 18 + 2 : 26;
      std::vector<DisasmResult> lines = DisassembleRange(code, got, rip, disRows);
        ::SendMessageW(disList, WM_SETREDRAW, FALSE, 0);
        g.disasmLines = lines;
        g.disasmAddr.clear();
        g.disasmComments.clear();
        g.disasmJumpTargets.clear();
        // 先收集视口内所有 jmp/call 目标地址（供行背景高亮）
        for (const DisasmResult& r : lines)
          if ((r.isJump || r.isCall) && r.jumpTarget)
            g.disasmJumpTargets.insert((ptruint)r.jumpTarget);
        ::SendMessageW(disList, LB_RESETCONTENT, 0, 0);
        wchar_t line[512];
        for (const DisasmResult& r : lines) {
          ptruint lineAddr = rip;
          g.disasmAddr.push_back(lineAddr);
          char addrBuf[32];
          std::snprintf(addrBuf, sizeof(addrBuf), "%012llX", (unsigned long long)rip);
          std::wstring addr = ToW(std::string(addrBuf));
          std::swprintf(line, 512, L"%s   %s", addr.c_str(), ToW(r.text).c_str());
          ::SendMessageW(disList, LB_ADDSTRING, 0, (LPARAM)line);
          g.disasmComments.push_back(BuildDisasmComment(r, lineAddr));
          rip += r.length;
        }
        g.lastDisasmBase = g.disasmBase;
        ::SendMessageW(disList, WM_SETREDRAW, TRUE, 0);
        ::SendMessageW(disList, LB_SETTOPINDEX, 0, 0);   // 内容即视口，归顶
        ::InvalidateRect(disList, nullptr, FALSE);        // 不擦背景，直接重绘
      } else {
        // ---- 该地址读不到：必须把失败显式化 ----
        // 以前这里什么都不做：面板继续显示**上一个地址**的反汇编，而 g.disasmBase
        // 已经是新地址 —— 于是"地址跳转没反应""滚动条怎么拖都不动"都从这里来
        // （64 位加壳/受保护目标的主模块代码页、跳到未提交页时最常见）。
        // 现在：清掉旧内容 + 面板上写明不可读，并让 lastDisasmBase 跟上，
        // 避免 500ms 定时器每帧都去重试这次注定失败的读取。
        ShowDisasmUnreadable(rip);
        g.lastDisasmBase = g.disasmBase;
      }
    } else {
      // 基址没变：仅重绘（断点/选中/多选高亮可能变了）
      ::InvalidateRect(disList, nullptr, FALSE);
    }
  }
  return rip;
}

// CPU 选中行信息：起始/结束/当前值 → 主窗口底部真状态栏第三段（随选中地址联动）
static void UpdateCmdInfoLine() {
  if (g.cpu == nullptr || !IsWindow(g.cpu)) return;
  wchar_t buf[160];
  if (g.selAddr) {
    int len = 4;
    for (size_t i = 0; i < g.disasmAddr.size(); ++i)
      if (g.disasmAddr[i] == g.selAddr) { len = g.disasmLines[i].length; break; }
    unsigned long long v = 0;
    g.proc.ReadPartial(g.selAddr, (unsigned char*)&v, 8);
    std::swprintf(buf, 160, L"起始: %llX  结束: %llX  当前值: %llX",
                  (unsigned long long)g.selAddr,
                  (unsigned long long)(g.selAddr + len - 1), v);
  } else {
    std::swprintf(buf, 160, L"起始: -  结束: -  当前值: -");
  }
  StatusOwnerSet(2, buf);
}

//=============================================================================
// 只刷新「数据（转储）」面板
//   转储滚动条拖动/滚轮是高频操作，以前每次都走全量 UpdateCpuWindow()
//   （GetThreadContext + 16 个寄存器标注 + 反汇编 + 堆栈全部重建，实测 31~40ms/格），
//   拖着明显发涩。这里把转储面板的构建单独抽出来，滚动只做这一件事。
//   栈指针提示沿用上一次的 RSP 快照（g.regVals[7] = RSP，由 UpdateCpuWindow 写入）。
//=============================================================================
static void RefreshDumpPanel() {
  if (g.cpu == nullptr || !IsWindow(g.cpu)) return;
  if (!g.dbg.IsAttached()) return;
  HWND dumpList = Ctrl(g.cpu, IDC_DUMP);
  if (!dumpList || !IsWindow(dumpList)) return;
  if (g.dumpBase == 0) return;
  const ptruint rsp = (ptruint)g.regVals[7];
  RECT drc{};
  ::GetClientRect(dumpList, &drc);
  const int dumpRows = drc.bottom > 34 ? (drc.bottom - 4) / 17 + 1 : 13;
  const ptruint dumpAddr = g.dumpBase;
  static ptruint lastDumpAddr = 0;
  static int lastDumpRows = 0;
  if (dumpAddr == lastDumpAddr && dumpRows == lastDumpRows) {
    DumpBarSync(dumpList, dumpRows);
    return;
  }
  lastDumpAddr = dumpAddr;
  lastDumpRows = dumpRows;
  {
    ::SendMessageW(dumpList, WM_SETREDRAW, FALSE, 0);
    ::SendMessageW(dumpList, LB_RESETCONTENT, 0, 0);
    unsigned char buf[16];
    wchar_t line[384], hexb[64], asc[24];
    for (int r0 = 0; r0 < dumpRows; ++r0) {
      ptruint a = dumpAddr + r0 * 16;
      size_t got = g.proc.ReadPartial(a, buf, 16);
      if (got == 0) {
        std::swprintf(line, 384, L"%012llX  （不可读）", (unsigned long long)a);
        ::SendMessageW(dumpList, LB_ADDSTRING, 0, (LPARAM)line);
        continue;
      }
      hexb[0] = 0; asc[0] = 0;
      for (size_t i = 0; i < got; ++i) {
        wchar_t t[8];
        std::swprintf(t, 8, L"%02X ", buf[i]);
        wcscat_s(hexb, t);
        int c = (buf[i] >= 0x20 && buf[i] < 0x7F) ? buf[i] : L'.';
        size_t l = wcslen(asc);
        asc[l] = (wchar_t)c;
        asc[l + 1] = 0;
      }
      // ---- OD 式注释列 ----
      std::wstring note;
      // 1) 行首 8 字节像代码指针 → 解析 API/模块
      unsigned long long v64 = 0;
      std::memcpy(&v64, buf, 8);
      if (v64 > 0x10000) {
        std::wstring api = ResolveApiName((ptruint)v64);
        if (!api.empty()) note = L"→ " + api;
        else {
          const ModuleEntry* cm = ProcessMemory::FindModule(g.proc.CachedModules(), (ptruint)v64);
          if (cm) {
            note = L"→ " + StripExt(cm->name) + L"+" +
                   ToW([&]{ char b[32];
                           std::snprintf(b, sizeof(b), "%llX",
                                         (unsigned long long)(v64 - cm->base));
                           return std::string(b); }());
          }
        }
      }
      // 2) 是可读字符串 → 显示 "..."
      if (note.empty()) {
        bool printable = true;
        for (size_t i = 0; i < got; ++i)
          if (!(buf[i] >= 0x20 && buf[i] < 0x7F) && buf[i] != 0) { printable = false; break; }
        if (printable && got >= 4 && buf[0] >= 0x20) {
          wchar_t q[64];
          std::swprintf(q, 64, L"\"%hs\"%hs", (const char*)buf,
                        got < 16 ? L"…" : L"");
          note = q;
        }
      }
      // 3) 前 4 字节是栈内指针
      if (note.empty() && rsp) {
        unsigned v32 = 0;
        std::memcpy(&v32, buf, 4);
        if (v32 >= rsp - 0x100000 && v32 <= rsp + 0x100000 && (v32 & 3) == 0)
          note = L"栈指针";
      }
      std::swprintf(line, 384, L"%012llX  %-49s %s  %s",
                    (unsigned long long)a, hexb, asc, note.c_str());
      ::SendMessageW(dumpList, LB_ADDSTRING, 0, (LPARAM)line);
    }
    ::SendMessageW(dumpList, WM_SETREDRAW, TRUE, 0);
    DumpBarSync(dumpList, dumpRows);
    ::InvalidateRect(dumpList, nullptr, FALSE);
  }
}

static void UpdateCpuWindow() {
  if (g.cpu == nullptr || !IsWindow(g.cpu)) return;
  if (!g.dbg.IsAttached()) return;

  DWORD tid = PickFocusTid();
  HWND regsList = Ctrl(g.cpu, IDC_REGS);
  HWND disList = Ctrl(g.cpu, IDC_DISASM);
  HWND dumpList = Ctrl(g.cpu, IDC_DUMP);
  HWND stackList = Ctrl(g.cpu, IDC_STACK);

  ptruint rsp = 0;

  if (tid != 0) {
    HANDLE h = ::OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
    if (h != nullptr) {
      CONTEXT ctx{};
      ctx.ContextFlags = CONTEXT_FULL;
      if (::GetThreadContext(h, &ctx)) {
        g.currentRip = (ptruint)ctx.Rip;          // 真实 RIP 用于高亮
        if (g.followRip) g.disasmBase = (ptruint)ctx.Rip;  // 跟随模式才移动视口
        rsp = (ptruint)ctx.Rsp;
        {   // 底部命令栏 ESP/EBP 红字显示（OD 式 8 位十六进制）
          wchar_t sb[64];
          HWND es = ::GetDlgItem(g.cpu, IDC_CMD_ESP);
          HWND eb = ::GetDlgItem(g.cpu, IDC_CMD_EBP);
          if (es) { std::swprintf(sb, 64, L"ESP=%08llX", (unsigned long long)(ctx.Rsp & 0xFFFFFFFFull)); ::SetWindowTextW(es, sb); }
          if (eb) { std::swprintf(sb, 64, L"EBP=%08llX", (unsigned long long)(ctx.Rbp & 0xFFFFFFFFull)); ::SetWindowTextW(eb, sb); }
        }
        wchar_t line[128];
        const char* names[] = {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                               "R8 ", "R9 ", "R10", "R11", "R12", "R13", "R14", "R15"};
        unsigned long long vals[16] = {ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi,
                                       ctx.Rbp, ctx.Rsp, ctx.R8,  ctx.R9,  ctx.R10, ctx.R11,
                                       ctx.R12, ctx.R13, ctx.R14, ctx.R15};
        // OD 风格寄存器数据（自绘渲染用）：0-15 GPR + RIP + EFL
        // 每个指针寄存器若指向模块/有 API 名则生成灰色标注
        auto fillNote = [&](int idx, ptruint v) {
          g.regNotes[idx][0] = 0;
          if (v < 0x10000) return;
          std::wstring api = ResolveApiName(v);
          if (!api.empty()) {
            wcsncpy_s(g.regNotes[idx], api.c_str(), _TRUNCATE);
            return;
          }
          // 模块+偏移
          const ModuleEntry* mm = ProcessMemory::FindModule(g.proc.CachedModules(), v);
          if (mm) {
            std::swprintf(g.regNotes[idx], 96, L"%hs+%llX",
                          ToA(mm->name).c_str(), (unsigned long long)(v - mm->base));
          } else if (v >= rsp - 0x8000 && v <= rsp + 0x1000) {
            wcscpy_s(g.regNotes[idx], 96, L"栈上");
          }
        };
        for (int i = 0; i < 16; ++i) {
          g.regVals[i] = vals[i];
          fillNote(i, vals[i]);
        }
        g.regVals[16] = ctx.Rip;   fillNote(16, ctx.Rip);
        g.regVals[17] = ctx.EFlags;
        g.regVals[18] = ctx.SegEs; g.regVals[19] = ctx.SegCs;
        g.regVals[20] = ctx.SegSs; g.regVals[21] = ctx.SegDs;
        g.regValid = true;

        // 防闪烁：寄存器值都没变就不重绘（纯自绘面板，无 LISTBOX 条目）
        static unsigned long long lastVals[17] = {};
        bool regsChanged = false;
        for (int i = 0; i < 16; ++i) if (vals[i] != lastVals[i]) { regsChanged = true; break; }
        if (ctx.Rip != lastVals[16] || (unsigned)ctx.EFlags != (unsigned)(lastVals[16] >> 32))
          regsChanged = true;
        if (regsChanged) {
          ::InvalidateRect(regsList, nullptr, FALSE);   // 面板自己 WM_PAINT 全量绘制
          for (int i = 0; i < 16; ++i) lastVals[i] = vals[i];
          lastVals[16] = ctx.Rip | ((unsigned long long)(unsigned)ctx.EFlags << 32);
        }
      }
      ::CloseHandle(h);
    }
  }

  // 反汇编视口：跟随 RIP 或用户滚动位置（轻量函数；滚动条拖动也直接调用它）
  ptruint rip = DisasmRefreshViewport();

  // 内存转储（OD 式：地址 + 十六进制 + ASCII + 注释）——独立滚动基址
  if (g.dumpBase == 0) g.dumpBase = rip & ~0xFULL;
  // 视口行数：按面板实际高度算（每行 17px），至少 12 行，再加 1 行缓冲让滚动条常驻
  RECT drc{};
  if (dumpList && IsWindow(dumpList)) ::GetClientRect(dumpList, &drc);
  const int dumpRows = drc.bottom > 34 ? (drc.bottom - 4) / 17 + 1 : 13;
  const int stackRows = 20;
  // 转储面板构建已抽成独立函数（滚动条拖动/滚轮等高频路径直接复用它，不再全量刷新）
  RefreshDumpPanel();

  // 堆栈（OD 式说明注释）——支持系统滚动条/滚轮：g.stackOff 为相对 RSP 的行偏移
  if (rsp) {
    static ptruint lastRsp = 0;
    static int lastStackOff = 0x7FFFFFFF;
    if (rsp != lastRsp || g.stackOff != lastStackOff) {
      lastRsp = rsp;
      lastStackOff = g.stackOff;
      ::SendMessageW(stackList, WM_SETREDRAW, FALSE, 0);
      ::SendMessageW(stackList, LB_RESETCONTENT, 0, 0);
      wchar_t line[320];
      bool sehChecked = false;
      for (int i = 0; i < stackRows; ++i) {
        const int row = i + g.stackOff;       // 0 = RSP（栈顶行）
        const long long aLL = (long long)rsp + (long long)row * 8;
        if (aLL <= 0) {
          std::swprintf(line, 320, L"%012llX  ????????????????  （不可读）", 0ull);
          ::SendMessageW(stackList, LB_ADDSTRING, 0, (LPARAM)line);
          continue;
        }
        ptruint a = (ptruint)aLL;
        unsigned long long v = 0;
        bool readable = g.proc.ReadPartial(a, (unsigned char*)&v, 8) == 8;
        std::wstring note;

        if (!readable) {
          std::swprintf(line, 320, L"%012llX  ????????????????  （不可读）",
                        (unsigned long long)a);
          ::SendMessageW(stackList, LB_ADDSTRING, 0, (LPARAM)line);
          continue;
        }

        // ---- OD 式语义注释 ----
        if (row == 0) {
          note = L"栈顶";
        } else {
          // x86 SEH 链（仅 32 位目标或 WOW64）：fs:[0] 指向的栈位置
          if (!sehChecked && g.proc.IsTargetWOW64()) {
            // 附加时缓存过 SEH 链头，简单启发：值是栈地址且下一格也是栈地址
            if (v >= rsp - 0x100000 && v <= rsp + 0x100000 && (v & 3) == 0) {
              unsigned long long next = 0, handler = 0;
              if (g.proc.ReadPartial((ptruint)v, (unsigned char*)&next, 8) == 8 &&
                  g.proc.ReadPartial((ptruint)v + 4, (unsigned char*)&handler, 8) == 8) {
                note = L"指向下一个 SEH 记录的指针";
                // 下一行（+4 处 32 位）是 SE 处理程序 —— 标记特殊行
                sehChecked = true;
                std::swprintf(line, 320, L"%012llX  %08llX        %s",
                              (unsigned long long)a, v & 0xFFFFFFFFull, note.c_str());
                ::SendMessageW(stackList, LB_ADDSTRING, 0, (LPARAM)line);
                // SE 处理程序行
                wchar_t l2[320];
                std::wstring hn = ResolveApiName((ptruint)(handler & 0xFFFFFFFFull));
                std::swprintf(l2, 320, L"%012llX  %08llX        SE 处理程序%s%hs",
                              (unsigned long long)a + 4, handler & 0xFFFFFFFFull,
                              hn.empty() ? L"" : L"：",
                              hn.empty() ? "" : ToA(hn).c_str());
                ::SendMessageW(stackList, LB_ADDSTRING, 0, (LPARAM)l2);
                continue;
              }
            }
          }
          // 代码指针 → "返回到 模块.API"
          const ModuleEntry* cm = ProcessMemory::FindModule(g.proc.CachedModules(), (ptruint)v);
          if (cm) {
            std::wstring api = ResolveApiName((ptruint)v);
            std::wstring mn = StripExt(cm->name);
            if (!api.empty()) {
              note = L"返回到 " + api;
              // 若是当前栈帧之上的调用：补"来自"（上一级调用者）
            } else {
              note = L"返回到 " + mn + L"." +
                     ToW([&]{ char b[32];
                             std::snprintf(b, sizeof(b), "%llX",
                                           (unsigned long long)(v - cm->base));
                             return std::string(b); }());
            }
          } else {
            // 值像字符串？
            std::wstring ps = ProbeString((ptruint)v);
            if (!ps.empty()) note = L"指向 " + ps;
            else if (v >= rsp - 0x100000 && v <= rsp + 0x100000 && (v & 3) == 0)
              note = L"栈指针";
          }
        }

        std::swprintf(line, 320, L"%012llX  %016llX  %s",
                      (unsigned long long)a, v, note.c_str());
        ::SendMessageW(stackList, LB_ADDSTRING, 0, (LPARAM)line);
      }
      ::SendMessageW(stackList, WM_SETREDRAW, TRUE, 0);
      ::InvalidateRect(stackList, nullptr, FALSE);
    }
  }

  // 滚动条收尾同步：必须放在**所有列表内容变更之后**。
  // 原因：LISTBOX 自己在内容变化后会重算并覆盖它那条系统滚动条的范围/位置
  // （实测把堆栈面板的行程压回 0..19），所以滑块状态要在整轮刷新结束再写一次。
  if (dumpList && IsWindow(dumpList)) DumpBarSync(dumpList, dumpRows);
  if (stackList && IsWindow(stackList)) StackBarSync(stackList, stackRows);

  UpdateCmdInfoLine();
}

//=============================================================================
// 命令处理
//=============================================================================
static void ToggleBpOnSelectedLine() {
  if (g.cpu == nullptr || !IsWindow(g.cpu)) return;
  // 优先用地址锚点（跨滚动持久）；没有则按视口锚点行
  ptruint addr = g.selAddr;
  if (addr == 0 && g.disasmSel >= 0 && g.disasmSel < (int)g.disasmAddr.size())
    addr = g.disasmAddr[g.disasmSel];
  if (addr == 0) return;
  std::string err;
  // 已有则删除，否则设 INT3
  bool exists = false;
  for (const Breakpoint& bp : g.dbg.ListBp()) {
    if (bp.address == addr) { exists = true; break; }
  }
  if (exists) {
    g.dbg.RemoveBp(addr);
    StatusText(ToW("已删除断点 @" + [&] { char b[32]; std::snprintf(b, sizeof(b), "%012llX",
                                                                 (unsigned long long)addr);
                                     return std::string(b); }()));
  } else {
    g.dbg.SetInt3(addr, &err);
    StatusText(err.empty() ? L"已设置 INT3 断点" : ToW("设置断点失败: " + err));
  }
  UpdateCpuWindow();
}

static void RefreshThreadList() {
  if (g.thr == nullptr || !IsWindow(g.thr)) return;
  HWND list = Ctrl(g.thr, IDC_THRLIST);
  ::SendMessageW(list, LB_RESETCONTENT, 0, 0);
  if (!g.dbg.IsAttached()) return;

  HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return;
  const DWORD pid = g.dbg.Pid();
  THREADENTRY32 te{};
  te.dwSize = sizeof(te);
  wchar_t line[256];
  if (::Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID != pid) continue;
      ptruint rip = 0;
      HANDLE h = ::OpenThread(THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
      if (h != nullptr) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (::GetThreadContext(h, &ctx)) rip = (ptruint)ctx.Rip;
        ::CloseHandle(h);
      }
      std::swprintf(line, 256, L"TID %u    RIP %012llX    Start %012llX", te.th32ThreadID,
                    (unsigned long long)rip, (unsigned long long)te.dwFlags);
      ::SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)line);
    } while (::Thread32Next(snap, &te));
  }
  ::CloseHandle(snap);
}

static void RefreshMapList() {
  if (g.map == nullptr || !IsWindow(g.map)) return;
  HWND list = Ctrl(g.map, IDC_MAPLIST);
  ::SendMessageW(list, LVM_DELETEALLITEMS, 0, 0);
  if (!g.proc.IsOpen()) return;

  SYSTEM_INFO si{};
  ::GetSystemInfo(&si);
  ptruint addr = (ptruint)si.lpMinimumApplicationAddress;
  const ptruint maxAddr = (ptruint)si.lpMaximumApplicationAddress;
  MEMORY_BASIC_INFORMATION mbi{};
  wchar_t line[5][128];
  int count = 0;
  while (addr < maxAddr && count < 4096) {
    if (::VirtualQueryEx(g.proc.Handle(), (LPCVOID)addr, &mbi, sizeof(mbi)) == 0) break;
    if (mbi.State == MEM_COMMIT) {
      LVITEMW it{};
      it.mask = LVIF_TEXT;
      it.iItem = 0x7FFFFFFF;
      std::swprintf(line[0], 128, L"%012llX", (unsigned long long)mbi.BaseAddress);
      std::swprintf(line[1], 128, L"%llX", (unsigned long long)mbi.RegionSize);
      wchar_t prot[64];
      switch (mbi.Protect & 0xFF) {
        case PAGE_NOACCESS: wcscpy_s(prot, L"NOACCESS"); break;
        case PAGE_READONLY: wcscpy_s(prot, L"R"); break;
        case PAGE_READWRITE: wcscpy_s(prot, L"RW"); break;
        case PAGE_WRITECOPY: wcscpy_s(prot, L"WC"); break;
        case PAGE_EXECUTE: wcscpy_s(prot, L"X"); break;
        case PAGE_EXECUTE_READ: wcscpy_s(prot, L"RX"); break;
        case PAGE_EXECUTE_READWRITE: wcscpy_s(prot, L"RWX"); break;
        default: wcscpy_s(prot, L"?"); break;
      }
      if (mbi.Protect & PAGE_GUARD) wcscat_s(prot, L" +GUARD");
      wcscpy_s(line[2], prot);
      wcscpy_s(line[3], mbi.Type == MEM_PRIVATE ? L"PRIVATE"
                        : mbi.Type == MEM_IMAGE ? L"IMAGE"
                                                : mbi.Type == MEM_MAPPED ? L"MAPPED" : L"?");
      const ModuleEntry* m = ProcessMemory::FindModule(g.proc.CachedModules(),
                                                       (ptruint)mbi.BaseAddress);
      if (m) {
        std::swprintf(line[4], 128, L"%s", m->name.c_str());
      } else {
        line[4][0] = 0;
      }
      wchar_t* texts[5] = {line[0], line[1], line[2], line[3], line[4]};
      it.pszText = texts[0];
      int idx = (int)::SendMessageW(list, LVM_INSERTITEMW, 0, (LPARAM)&it);
      for (int c = 1; c < 5; ++c) {
        LVITEMW sub{};
        sub.mask = LVIF_TEXT;          // 不设 mask 的话 pszText 会被忽略（子列全空）
        sub.iItem = idx;               // LVM_SETITEM 的行号取自 iItem，不是 wParam！
        sub.iSubItem = c;
        sub.pszText = texts[c];
        ::SendMessageW(list, LVM_SETITEMW, idx, (LPARAM)&sub);
      }
      ++count;
    }
    addr = (ptruint)mbi.BaseAddress + mbi.RegionSize;
  }
}

static void RefreshBpList() {
  if (g.bps == nullptr || !IsWindow(g.bps)) return;
  HWND list = Ctrl(g.bps, IDC_BPLIST);
  ::SendMessageW(list, LB_RESETCONTENT, 0, 0);
  wchar_t line[256];
  for (const Breakpoint& bp : g.dbg.ListBp()) {
    const wchar_t* kindName = L"?";
    switch (bp.kind) {
      case BpKind::Int3: kindName = L"INT3 执行"; break;
      case BpKind::HardwareExec: kindName = L"硬件执行"; break;
      case BpKind::HardwareWrite: kindName = L"硬件写入"; break;
      case BpKind::HardwareRW: kindName = L"硬件读写"; break;
      case BpKind::Access: kindName = L"页守卫-访问"; break;
      case BpKind::Write: kindName = L"页守卫-写入"; break;
      default: break;
    }
    std::swprintf(line, 256, L"%012llX    %s    %s", (unsigned long long)bp.address, kindName,
                  bp.active ? L"生效" : L"未生效");
    ::SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)line);
  }
}

// 命中记录里的"指令"列原来一直是空的：这里补上反汇编文本与字节
static void FillHitDisasm(HitReport& hit) {
  if (!hit.disasm.empty() && hit.bytes.size() > 1) return;
  if (!g.proc.IsOpen()) return;
  unsigned char code[16] = {};
  SIZE_T got = g.proc.ReadPartial(hit.rip, code, sizeof(code));
  if (!got) return;
  DisasmResult dr;
  Disassemble(code, got, hit.rip, &dr);
  hit.disasm = dr.text;
  if (hit.bytes.size() <= 1)
    hit.bytes.assign(code, code + (dr.length > 0 ? dr.length : 1));
}

static void AppendHitRow(const HitReport& hit) {
  if (g.bps == nullptr || !IsWindow(g.bps)) return;
  HWND list = Ctrl(g.bps, IDC_HITS);
  LVITEMW item{};
  item.mask = LVIF_TEXT;
  item.iItem = 0x7FFFFFFF;
  wchar_t cols[6][256];
  std::swprintf(cols[0], 256, L"%u", hit.tid);
  std::swprintf(cols[1], 256, L"%012llX", (unsigned long long)hit.rip);
  std::swprintf(cols[2], 256, L"%s", ToW(hit.module).c_str());
  const wchar_t* kn = L"?";
  switch (hit.kind) {
    case BpKind::Int3: kn = L"执行"; break;
    case BpKind::HardwareExec: kn = L"执行"; break;
    case BpKind::HardwareWrite: kn = L"写入"; break;
    case BpKind::HardwareRW: kn = L"读写"; break;
    case BpKind::Access: kn = L"访问"; break;
    case BpKind::Write: kn = L"写入"; break;
    default: break;
  }
  std::swprintf(cols[3], 256, L"%s", kn);
  std::swprintf(cols[4], 256, L"%s", ToW(hit.disasm).c_str());
  std::wstring bytes;
  wchar_t t[8];
  for (size_t i = 0; i < hit.bytes.size() && i < 15; ++i) {
    std::swprintf(t, 8, L"%02X ", hit.bytes[i]);
    bytes += t;
  }
  std::swprintf(cols[5], 256, L"%s", bytes.c_str());

  wchar_t* texts[6] = {cols[0], cols[1], cols[2], cols[3], cols[4], cols[5]};
  item.pszText = texts[0];
  int idx = (int)::SendMessageW(list, LVM_INSERTITEMW, 0, (LPARAM)&item);
  for (int c = 1; c < 6; ++c) {
    LVITEMW sub{};
    sub.mask = LVIF_TEXT;              // 不设 mask 的话 pszText 会被忽略（子列全空）
    sub.iItem = idx;                   // LVM_SETITEM 的行号取自 iItem，不是 wParam！
    sub.iSubItem = c;
    sub.pszText = texts[c];
    ::SendMessageW(list, LVM_SETITEMW, idx, (LPARAM)&sub);
  }
  const int n = (int)::SendMessageW(list, LVM_GETITEMCOUNT, 0, 0);
  if (n > 5000) ::SendMessageW(list, LVM_DELETEITEM, n - 1, 0);
}

//=============================================================================
// 附加 / 分离
//=============================================================================
//=============================================================================
// 进程选择对话框（模态）
//=============================================================================
struct ProcDlgState {
  HWND list = nullptr;
  std::vector<ProcessEntry> procs;
  DWORD chosen = 0;
};
static ProcDlgState g_pd;

static void PdRefresh() {
  if (!g_pd.list) return;
  // 先冻结重绘，几百条 LB_ADDSTRING 期间列表不刷屏，填完再一次重绘
  ::SendMessageW(g_pd.list, WM_SETREDRAW, FALSE, 0);
  ::SendMessageW(g_pd.list, LB_RESETCONTENT, 0, 0);
  g_pd.procs = ProcessMemory::ListProcesses();
  wchar_t buf[512];
  for (const ProcessEntry& p : g_pd.procs) {
    if (p.pid == 0) continue;
    std::swprintf(buf, 512, L"%6u   %s", p.pid, p.name.c_str());
    int i = (int)::SendMessageW(g_pd.list, LB_ADDSTRING, 0, (LPARAM)buf);
    ::SendMessageW(g_pd.list, LB_SETITEMDATA, i, (LPARAM)p.pid);
  }
  ::SendMessageW(g_pd.list, WM_SETREDRAW, TRUE, 0);
  ::InvalidateRect(g_pd.list, nullptr, TRUE);
}

//=============================================================================
// 暗色主题按钮：自绘下压钮 / 复选框
//   （系统主题按钮不吃 WM_CTLCOLORBTN，只能整只自绘）
//=============================================================================
static WNDPROC s_oldChkProc = nullptr;

// 自绘复选框：样式位被 BS_OWNERDRAW 覆盖后不再自动切换，这里手动切换选中态
static LRESULT CALLBACK ChkBtnProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  if (m == WM_LBUTTONUP) {
    LRESULT st = ::SendMessageW(h, BM_GETCHECK, 0, 0);
    ::SendMessageW(h, BM_SETCHECK,
                   (WPARAM)(st == BST_CHECKED ? BST_UNCHECKED : BST_CHECKED), 0);
    ::InvalidateRect(h, nullptr, FALSE);
  } else if (m == WM_LBUTTONDOWN || m == WM_SETFOCUS || m == WM_KILLFOCUS) {
    ::InvalidateRect(h, nullptr, FALSE);
  }
  return ::CallWindowProcW(s_oldChkProc, h, m, wp, lp);
}

static void DrawDarkButton(const DRAWITEMSTRUCT* ds) {
  if (!ds) return;
  const LONG_PTR bt = ::GetWindowLongPtrW(ds->hwndItem, GWLP_USERDATA);
  const bool isCheck = (bt == BS_AUTOCHECKBOX) || (bt == BS_CHECKBOX) ||
                       (bt == BS_AUTO3STATE) || (bt == BS_3STATE);
  const bool disabled = (ds->itemState & ODS_DISABLED) != 0;
  const bool pressed = (ds->itemState & ODS_SELECTED) != 0;
  RECT r = ds->rcItem;

  COLORREF face = disabled ? kBtnDisabledBg : (pressed ? kBtnPressed : kBtnFace);
  HBRUSH b = ::CreateSolidBrush(face);
  ::FillRect(ds->hDC, &r, b);
  ::DeleteObject(b);

  if (!isCheck) {  // 下压钮描边
    HPEN p = ::CreatePen(PS_SOLID, 1, pressed ? kBtnBorderHi : kBtnBorder);
    HPEN op = (HPEN)::SelectObject(ds->hDC, p);
    HGDIOBJ ob = ::SelectObject(ds->hDC, ::GetStockObject(NULL_BRUSH));
    ::Rectangle(ds->hDC, r.left, r.top, r.right, r.bottom);
    ::SelectObject(ds->hDC, op);
    ::SelectObject(ds->hDC, ob);
    ::DeleteObject(p);
  }

  wchar_t txt[256] = {0};
  ::GetWindowTextW(ds->hwndItem, txt, 255);
  ::SetBkMode(ds->hDC, TRANSPARENT);
  RECT tr = r;

  if (isCheck) {
    const bool checked = (::SendMessageW(ds->hwndItem, BM_GETCHECK, 0, 0) == BST_CHECKED);
    const int side = 12;
    RECT box{r.left + 3, (r.top + r.bottom) / 2 - side / 2,
             r.left + 3 + side, (r.top + r.bottom) / 2 + side / 2};
    HBRUSH bb = ::CreateSolidBrush(checked ? kBtnCheckTick : kBtnCheckBg);
    ::FillRect(ds->hDC, &box, bb);
    ::DeleteObject(bb);
    HPEN p2 = ::CreatePen(PS_SOLID, 1, kBtnBorderHi);
    HPEN op2 = (HPEN)::SelectObject(ds->hDC, p2);
    HGDIOBJ ob2 = ::SelectObject(ds->hDC, ::GetStockObject(NULL_BRUSH));
    ::Rectangle(ds->hDC, box.left, box.top, box.right, box.bottom);
    ::SelectObject(ds->hDC, op2);
    ::SelectObject(ds->hDC, ob2);
    ::DeleteObject(p2);
    if (checked) {  // 勾
      HPEN cp = ::CreatePen(PS_SOLID, 2, kBtnCheckBorder);
      HPEN ocp = (HPEN)::SelectObject(ds->hDC, cp);
      ::MoveToEx(ds->hDC, box.left + 3, box.top + 6, nullptr);
      ::LineTo(ds->hDC, box.left + 5, box.top + 9);
      ::LineTo(ds->hDC, box.left + 9, box.top + 3);
      ::SelectObject(ds->hDC, ocp);
      ::DeleteObject(cp);
    }
    tr.left = box.right + 6;
    ::SetTextColor(ds->hDC, disabled ? kBtnTextDisabled : kBtnTextSub);
    ::DrawTextW(ds->hDC, txt, -1, &tr,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
  } else {
    tr.left += 4;
    tr.right -= 4;
    ::SetTextColor(ds->hDC, disabled ? kBtnTextDisabled : kBtnText);
    ::DrawTextW(ds->hDC, txt, -1, &tr,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
  }
}

// 把按钮 c 变成暗色自绘；btnType 为原始按钮类型（0=下压钮, 3=自动复选）
static void MakeDarkButton(HWND c, DWORD btnType) {
  if (!c) return;
  ::SetWindowLongPtrW(c, GWLP_USERDATA, (LONG_PTR)btnType);
  if (btnType == BS_AUTOCHECKBOX || btnType == BS_CHECKBOX) {
    if (!s_oldChkProc) s_oldChkProc = (WNDPROC)::GetWindowLongPtrW(c, GWLP_WNDPROC);
    ::SetWindowLongPtrW(c, GWLP_WNDPROC, (LONG_PTR)ChkBtnProc);
  }
}

//=============================================================================
// 地址跳转小窗（反汇编右键菜单-地址跳转）：编辑框 + "地址跳转"按钮
// 回车=跳转，Esc=关闭；预填当前视口地址，全选可直接覆盖输入
//=============================================================================
static void DoGotoJump(HWND dlg) {
  std::string t = Trim(GetText(::GetDlgItem(dlg, 1)));
  if (!t.empty() && (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0)) t = t.substr(2);
  uint64_t a = t.empty() ? 0 : std::strtoull(t.c_str(), nullptr, 16);
  {
    char tb[160];
    std::snprintf(tb, sizeof(tb), "goto jump text='%s' addr=%012llX", t.c_str(),
                  (unsigned long long)a);
    UiTrace(tb);
  }
  // 用户态规范地址范围校验：以前任何非 0 值都直接接受，输入个非法值就静默跳到野地址
  // （视口读不到 → 面板没反应，看起来像"跳转功能坏了"）。这里给明确反馈并留在输入框。
  const uint64_t kUserMax = 0x00007FFFFFFFFFFFULL;
  if (a < 0x1000 || a > kUserMax) {
    wchar_t sb[160];
    std::swprintf(sb, 160, L"地址跳转: 输入 '%hs' 不是有效的用户态地址（需要 1000 - %llX）",
                  t.c_str(), (unsigned long long)kUserMax);
    StatusText(sb);
    AddLogLine("地址跳转被拒绝: 无效地址 '" + t + "'");
    ::SetFocus(::GetDlgItem(dlg, 1));
    return;                     // 小窗不关，方便直接改
  }
  g.disasmBase = (ptruint)a;
  g.followRip = false;
  DisasmRefreshViewport();       // 读不到时会自己写状态栏/日志（见 ShowDisasmUnreadable）
  {
    wchar_t sb[160];
    if (g.disasmBad) {
      std::swprintf(sb, 160, L"地址跳转: %012llX —— 该地址不可读（视口已定位，面板给出提示）",
                    (unsigned long long)a);
    } else {
      std::swprintf(sb, 160, L"地址跳转: %012llX  OK", (unsigned long long)a);
    }
    StatusText(sb);
    AddLogLine(std::string("地址跳转: ") + std::string(t));
  }
  ::DestroyWindow(dlg);
}

static WNDPROC s_oldGotoEdit = nullptr;
static LRESULT CALLBACK GotoEditProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  // 编辑框里回车=跳转 / Esc=关闭（单行 EDIT 收不到这两个键，子类化转发）
  if (m == WM_KEYDOWN && wp == VK_RETURN) { DoGotoJump(::GetParent(h)); return 0; }
  if (m == WM_KEYDOWN && wp == VK_ESCAPE) { ::DestroyWindow(::GetParent(h)); return 0; }
  return ::CallWindowProcW(s_oldGotoEdit, h, m, wp, lp);
}

static LRESULT CALLBACK GotoDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE: {
      HWND edit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
                                    WS_CHILD | WS_VISIBLE | ES_LEFT | ES_AUTOHSCROLL,
                                    12, 16, 232, 26, hwnd, (HMENU)(INT_PTR)1, g.inst, nullptr);
      ::SendMessageW(edit, WM_SETFONT, (WPARAM)g.monoFont, TRUE);
      HWND btn = ::CreateWindowExW(0, L"BUTTON", L"地址跳转",
                                   WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                   256, 15, 88, 28, hwnd, (HMENU)(INT_PTR)2, g.inst, nullptr);
      ::SendMessageW(btn, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
      MakeDarkButton(btn, BS_PUSHBUTTON);
      wchar_t buf[32];
      std::swprintf(buf, 32, L"%012llX", (unsigned long long)g.disasmBase);
      ::SetWindowTextW(edit, buf);
      ::SendMessageW(edit, EM_SETSEL, 0, -1);
      s_oldGotoEdit = (WNDPROC)::SetWindowLongPtrW(edit, GWLP_WNDPROC, (LONG_PTR)GotoEditProc);
      ::SetFocus(edit);
      return 0;
    }
    case WM_COMMAND:
      if (LOWORD(wp) == 2) DoGotoJump(hwnd);   // "地址跳转"按钮
      return 0;
    case WM_DRAWITEM: {
      DRAWITEMSTRUCT* dsb = (DRAWITEMSTRUCT*)lp;
      if (dsb->CtlType == ODT_BUTTON) { DrawDarkButton(dsb); return TRUE; }
      break;
    }
    case WM_KEYDOWN:
      if (wp == VK_ESCAPE) { ::DestroyWindow(hwnd); return 0; }
      break;
    case WM_ERASEBKGND: {
      RECT rc; ::GetClientRect(hwnd, &rc);
      ::FillRect((HDC)wp, &rc, GetCachedBrush(kPanelBg));
      return 1;
    }
    case WM_CTLCOLOREDIT: {
      HDC dc = (HDC)wp;
      ::SetBkColor(dc, kEditBg);
      ::SetTextColor(dc, kEditText);
      return (LRESULT)GetCachedBrush(kEditBg);
    }
    case WM_CLOSE:
      ::DestroyWindow(hwnd);
      return 0;
  }
  return ::DefWindowProcW(hwnd, msg, wp, lp);
}

// 弹出地址跳转小窗（局部模态，同进程选择对话框的做法）
static void ShowGotoDlg(HWND frame) {
  UiTrace("goto dlg open");
  static const wchar_t* kGotoDlgClass = L"CEScanGotoDlg";
  static bool reg = false;
  if (!reg) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = GotoDlgProc;
    wc.hInstance = g.inst;
    wc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = ::CreateSolidBrush(kPanelBg);
    wc.lpszClassName = kGotoDlgClass;
    ::RegisterClassW(&wc);
    reg = true;
  }
  ::EnableWindow(frame, FALSE);
  RECT work{};
  ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
  const int dw = kGotoW, dh = kGotoH;   // 尺寸见 ThemeColors.h
  int dx = work.left + ((work.right - work.left) - dw) / 2;
  int dy = work.top + ((work.bottom - work.top) - dh) / 2;
  HWND dlg = ::CreateWindowExW(WS_EX_DLGMODALFRAME, kGotoDlgClass, L"地址跳转",
                               WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, dx, dy, dw, dh,
                               frame, nullptr, g.inst, nullptr);
  ::ShowWindow(dlg, SW_SHOW);
  ::UpdateWindow(dlg);
  MSG msg;
  while (::GetMessageW(&msg, nullptr, 0, 0)) {
    if (msg.message == WM_QUIT) { ::PostQuitMessage((int)msg.wParam); break; }
    if (!::IsWindow(dlg)) break;
    ::TranslateMessage(&msg);
    ::DispatchMessageW(&msg);
  }
  ::EnableWindow(frame, TRUE);
  ::SetActiveWindow(frame);
}

// ---- 附加窗口底部 logo 宫格（exe 同级 logo\ 目录）----
// GIF 会动：加载时自解码全部帧（LZW + 逐帧合成），20ms 定时器逐帧播放；
// JPEG / GIF 解码失败 → OleLoadPicture 静态首帧兜底。
struct GifFrameBuf { std::vector<uint32_t> px; int delayMs; };   // 0xAARRGGBB
struct GifAnim {
  int w = 0, h = 0;
  std::vector<GifFrameBuf> frames;
  bool ok = false;
};
struct LogoItem {
  bool      anim = false;    // 多帧动图
  IPicture* pic = nullptr;   // 静态兜底
  GifAnim   gif;
  int       cur = 0;         // 当前帧
  int       accum = 0;       // 帧延时累计（ms）
};
static LogoItem g_pdLogos[16] = {};
static int      g_pdLogoN = 0;

// GIF 位读取器（LSB 优先）
struct GifBits {
  const uint8_t* d; int n; int pos = 0, bit = 0;
  GifBits(const uint8_t* dd, int nn) : d(dd), n(nn) {}
  int read(int cnt) {
    int v = 0;
    for (int i = 0; i < cnt; ++i) {
      if (pos >= n) return -1;
      v |= ((d[pos] >> bit) & 1) << i;
      if (++bit == 8) { bit = 0; ++pos; }
    }
    return v;
  }
};

// GIF LZW 解码：变长码（minSz+1 起步，4096 表上限），输出 outN 个调色板索引
static bool GifLzw(const uint8_t* data, int len, int minSz, uint8_t* out, int outN) {
  if (minSz < 1 || minSz > 11) return false;
  static std::vector<uint8_t> dict[4096];
  const int clear = 1 << minSz, end = clear + 1;
  int next = end + 1, size = minSz + 1, written = 0;
  std::vector<uint8_t> prevStr;   // 上一串（供 KwKwK 与建表）
  GifBits b(data, len);
  for (;;) {
    int code = b.read(size);
    if (code < 0) return false;
    if (code == clear) { for (int i = end + 1; i < 4096; ++i) dict[i].clear();
                         next = end + 1; size = minSz + 1; prevStr.clear(); continue; }
    if (code == end) break;
    std::vector<uint8_t> entry;
    if (code < clear)       entry = { (uint8_t)code };                 // 字面根
    else if (code < 4096 && !dict[code].empty()) entry = dict[code];   // 已有条目
    else if (code == next && !prevStr.empty()) {                       // KwKwK
      entry = prevStr; entry.push_back(prevStr[0]);
    } else return false;
    for (uint8_t c : entry) {
      if (written >= outN) return true;   // 解满即止
      out[written++] = c;
    }
    if (!prevStr.empty() && next < 4096) {
      dict[next] = prevStr;
      dict[next].push_back(entry[0]);
      if (++next == (1 << size) && size < 12) ++size;
    }
    prevStr.swap(entry);   // 上一串 = 本串
  }
  return true;
}

// 解码 GIF：逻辑屏 → 全局色表 → 块循环（GCE 延时/透明/处置法 + 图像描述符）
// 帧合成到画布后整帧快照（透明=透出画布；disposal 2=清背景 3=恢复前帧）
static bool DecodeGif(const std::vector<uint8_t>& f, GifAnim& a) {
  if (f.size() < 13 || f[0] != 'G' || f[1] != 'I' || f[2] != 'F') return false;
  const int w = f[6] | f[7] << 8, h = f[8] | f[9] << 8;
  if (w <= 0 || h <= 0 || w > 512 || h > 512) return false;
  const int packed = f[10];
  size_t p = 13;
  uint32_t gct[256] = {};
  if (packed & 0x80) {
    int n = 2 << (packed & 7);
    if (p + (size_t)n * 3 > f.size()) return false;
    for (int i = 0; i < n; ++i)
      gct[i] = 0xFF000000u | (f[p + i*3] << 16) | (f[p + i*3 + 1] << 8) | f[p + i*3 + 2];
    p += (size_t)n * 3;
  }
  a.w = w; a.h = h;
  std::vector<uint32_t> canvas((size_t)w * h, 0xFF000000u);
  int delayMs = 100, tidx = -1, disposal = 0;
  while (p < f.size()) {
    const int b = f[p++];
    if (b == 0x3B) break;                        // 结束
    if (b == 0x21) {                             // 扩展
      if (p >= f.size()) return false;
      const int label = f[p++];
      if (label == 0xF9 && p + 5 <= f.size()) {  // 图形控制：延时/透明/处置法
        const int pk = f[p + 1];
        delayMs = (f[p + 2] | f[p + 3] << 8) * 10;
        if (delayMs <= 0) delayMs = 100;
        tidx = (pk & 1) ? (int)f[p + 4] : -1;
        disposal = (pk >> 2) & 7;
        p += 5;
        while (p < f.size() && f[p] != 0) p += 1 + f[p];   // 跳过剩余子块
        ++p;
      } else {                                   // 注释/应用/纯文本：整段跳过
        while (p < f.size()) {
          const int sl = f[p++];
          if (sl == 0) break;
          p += sl;
        }
      }
    } else if (b == 0x2C) {                      // 图像描述符
      if (p + 10 > f.size()) return false;
      const int ix = f[p] | f[p+1] << 8, iy = f[p+2] | f[p+3] << 8;
      const int iw = f[p+4] | f[p+5] << 8, ih = f[p+6] | f[p+7] << 8;
      const int pk = f[p + 8];
      p += 9;
      uint32_t pal[256];
      ::memcpy(pal, gct, sizeof pal);
      if (pk & 0x80) {
        int n = 2 << (pk & 7);
        if (p + (size_t)n * 3 > f.size()) return false;
        for (int i = 0; i < n; ++i)
          pal[i] = 0xFF000000u | (f[p + i*3] << 16) | (f[p + i*3 + 1] << 8) | f[p + i*3 + 2];
        p += (size_t)n * 3;
      }
      if (p >= f.size()) return false;
      const int minSz = f[p++];
      std::vector<uint8_t> data;                 // 收集 LZW 数据子块
      while (p < f.size()) {
        const int sl = f[p++];
        if (sl == 0) break;
        if (p + sl > f.size()) return false;
        data.insert(data.end(), f.begin() + p, f.begin() + p + sl);
        p += sl;
      }
      std::vector<uint8_t> idx((size_t)iw * ih, 0);
      if (!GifLzw(data.data(), (int)data.size(), minSz, idx.data(), (int)idx.size()))
        return false;
      if (pk & 0x40) {                           // 交织 → 逐行还原
        std::vector<uint8_t> lin(idx.size());
        size_t src = 0;
        const int stepY[4] = {8, 8, 4, 2}, start[4] = {0, 4, 2, 1};
        for (int pass = 0; pass < 4; ++pass)
          for (int y = start[pass]; y < ih; y += stepY[pass])
            for (int x = 0; x < iw && src < idx.size(); ++x)
              lin[(size_t)y * iw + x] = idx[src++];
        idx.swap(lin);
      }
      std::vector<uint32_t> saved;               // disposal 3 需要恢复前帧
      if (disposal == 3) saved = canvas;
      for (int y = 0; y < ih; ++y) {             // 合成到画布（透明=保留原样）
        const int dy = iy + y;
        if (dy < 0 || dy >= h) continue;
        for (int x = 0; x < iw; ++x) {
          const int dx = ix + x;
          if (dx < 0 || dx >= w) continue;
          const uint8_t ci = idx[(size_t)y * iw + x];
          if (ci == tidx) continue;
          canvas[(size_t)dy * w + dx] = pal[ci];
        }
      }
      if ((int)a.frames.size() < 256)
        a.frames.push_back({ canvas, delayMs });
      if (disposal == 2) {                       // 恢复为背景（黑，同面板底色）
        for (int y = 0; y < ih; ++y) {
          const int dy = iy + y;
          if (dy < 0 || dy >= h) continue;
          for (int x = 0; x < iw; ++x) {
            const int dx = ix + x;
            if (dx < 0 || dx >= w) continue;
            canvas[(size_t)dy * w + dx] = 0xFF000000u;
          }
        }
      } else if (disposal == 3) {
        canvas.swap(saved);
      }
      delayMs = 100; tidx = -1; disposal = 0;    // GCE 只作用一帧
    } else {
      return false;                              // 未知块标识
    }
  }
  a.ok = !a.frames.empty();
  return a.ok;
}

// 读取文件字节 + 逐个加载（GIF→动图解码，JPEG/失败→IPicture 静态兜底）
static void LoadLogoPictures() {
  static bool done = false;
  if (done) return;
  done = true;
  ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  wchar_t dir[MAX_PATH];
  ::GetModuleFileNameW(nullptr, dir, MAX_PATH);
  std::wstring base = dir;
  size_t pos = base.find_last_of(L'\\');
  if (pos != std::wstring::npos) base = base.substr(0, pos + 1);
  base += L"logo\\";
  for (int i = 1; i <= 14 && g_pdLogoN < 16; ++i) {
    const std::wstring path = base + std::to_wstring(i) + L".gif";
    HANDLE f = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) continue;
    DWORD size = ::GetFileSize(f, nullptr);
    std::vector<uint8_t> bytes(size > 0 ? size : 1);
    DWORD rd = 0;
    ::ReadFile(f, bytes.data(), size, &rd, nullptr);
    ::CloseHandle(f);
    bytes.resize(rd);
    // GIF：多帧解码成动图；失败再走静态兜底
    if (bytes.size() > 6 && bytes[0] == 'G' && bytes[1] == 'I') {
      GifAnim ga;
      if (DecodeGif(bytes, ga)) {
        LogoItem& it = g_pdLogos[g_pdLogoN++];
        it.anim = true;
        it.gif = ga;
        continue;
      }
    }
    // 静态兜底（JPEG / 解码失败）：内存流 → OleLoadPicture 首帧
    HGLOBAL mem = ::GlobalAlloc(GMEM_MOVEABLE, bytes.size());
    if (!mem) continue;
    void* mp = ::GlobalLock(mem);
    ::memcpy(mp, bytes.data(), bytes.size());
    ::GlobalUnlock(mem);
    LPSTREAM st = nullptr;
    if (SUCCEEDED(::CreateStreamOnHGlobal(mem, TRUE, &st))) {
      IPicture* pic = nullptr;
      if (SUCCEEDED(::OleLoadPicture(st, 0, FALSE, IID_IPicture, (void**)&pic)) && pic) {
        LogoItem& it = g_pdLogos[g_pdLogoN++];
        it.anim = false;
        it.pic = pic;
      }
      st->Release();          // 流释放时连带释放 mem(fDeleteOnRelease=TRUE)
    } else {
      ::GlobalFree(mem);
    }
  }
}

static LRESULT CALLBACK ProcDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE: {
      g_pd.list = ::CreateWindowExW(
          WS_EX_CLIENTEDGE, L"LISTBOX", nullptr,
          WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
          10, 10, 430, 372, hwnd, (HMENU)(INT_PTR)IDC_PD_LIST, g.inst, nullptr);
      ::SendMessageW(g_pd.list, WM_SETFONT, (WPARAM)g.monoFont, TRUE);

      auto btn = [&](int id, const wchar_t* text, int x, int w) {
        HWND b = ::CreateWindowExW(0, L"BUTTON", text,
                                   WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, x, 392, w, 28,
                                   hwnd, (HMENU)(INT_PTR)id, g.inst, nullptr);
        ::SendMessageW(b, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
        MakeDarkButton(b, BS_PUSHBUTTON);
      };
      btn(IDC_PD_REFRESH, L"刷新(F5)", 10, 100);
      btn(IDC_PD_ATTACH, L"附加", 250, 90);
      btn(IDC_PD_CANCEL, L"取消", 350, 90);

      HWND hint = ::CreateWindowExW(0, L"STATIC",
                                    L"双击进程即可附加", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                    116, 398, 128, 20, hwnd, nullptr, g.inst, nullptr);
      ::SendMessageW(hint, WM_SETFONT, (WPARAM)g.uiFont, TRUE);

      PdRefresh();
      LoadLogoPictures();   // 底部 logo 宫格（首次打开时加载，之后走缓存）
      ::SetTimer(hwnd, 7, 20, nullptr);   // GIF 逐帧播放时钟
      return 0;
    }

    case WM_PAINT: {
      PAINTSTRUCT ps;
      HDC dc = ::BeginPaint(hwnd, &ps);
      RECT rc; ::GetClientRect(hwnd, &rc);

      // 双缓冲：先在内存 DC 画完整背景 + logo 宫格，再一次 BitBlt 上屏，
      // 消除“擦背景 + 逐个 StretchDIBits 上屏”造成的严重闪烁。
      HDC mem = ::CreateCompatibleDC(dc);
      HBITMAP bmp = ::CreateCompatibleBitmap(dc, rc.right, rc.bottom);
      HGDIOBJ ob = ::SelectObject(mem, bmp);
      ::FillRect(mem, &rc, GetCachedBrush(kPanelBg));

      if (g_pdLogoN > 0) {
        const int cols = kLogoCols, cw = kLogoW, ch = kLogoH;
        const int x0 = 10, y0 = 430;   // 与列表左缘对齐；按钮行(392+28)下方留 10px
        BITMAPINFO bi{};
        bi.bmiHeader.biSize     = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biPlanes   = 1;
        bi.bmiHeader.biBitCount = 32;
        for (int i = 0; i < g_pdLogoN; ++i) {
          const int cx = x0 + (i % cols) * cw;
          const int cy = y0 + (i / cols) * ch;
          if (g_pdLogos[i].anim && !g_pdLogos[i].gif.frames.empty()) {
            const GifFrameBuf& fr = g_pdLogos[i].gif.frames[g_pdLogos[i].cur];
            bi.bmiHeader.biWidth = g_pdLogos[i].gif.w;
            bi.bmiHeader.biHeight = -g_pdLogos[i].gif.h;
            ::StretchDIBits(mem, cx, cy, cw, ch, 0, 0,
                            g_pdLogos[i].gif.w, g_pdLogos[i].gif.h,
                            fr.px.data(), &bi, DIB_RGB_COLORS, SRCCOPY);
          } else if (g_pdLogos[i].pic) {
            long hmW = 0, hmH = 0;
            g_pdLogos[i].pic->get_Width(&hmW);
            g_pdLogos[i].pic->get_Height(&hmH);
            g_pdLogos[i].pic->Render(mem, cx, cy, cw, ch, 0, hmH, hmW, -hmH, nullptr);
          }
        }
      }

      ::BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
      ::SelectObject(mem, ob);
      ::DeleteObject(bmp);
      ::DeleteDC(mem);
      ::EndPaint(hwnd, &ps);
      return 0;
    }

    case WM_TIMER:
      if (wp == 7) {   // GIF 逐帧播放：按各图自身帧延时推进
        bool any = false;
        for (int i = 0; i < g_pdLogoN; ++i) {
          LogoItem& it = g_pdLogos[i];
          if (!it.anim || it.gif.frames.empty()) continue;
          it.accum += 20;
          if (it.accum >= it.gif.frames[it.cur].delayMs) {
            it.accum = 0;
            it.cur = (it.cur + 1) % (int)it.gif.frames.size();
            any = true;
          }
        }
        if (any) {
          // 只失效 logo 宫格区域，不整窗重绘（整窗重绘是闪烁主因）
          const int cols = kLogoCols, cw = kLogoW, ch = kLogoH;
          const int rows = (g_pdLogoN + cols - 1) / cols;
          RECT r{10, 430, 10 + cols * cw + (cols - 1) * kLogoGapX,
                 430 + rows * ch + (rows - 1) * kLogoGapY};
          ::InvalidateRect(hwnd, &r, FALSE);
        }
      }
      return 0;

    case WM_KEYDOWN:
      if (wp == VK_ESCAPE) { ::DestroyWindow(hwnd); return 0; }
      if (wp == VK_F5) { PdRefresh(); return 0; }
      break;

    case WM_COMMAND: {
      int id = LOWORD(wp);
      if (id == IDC_PD_LIST && HIWORD(wp) == LBN_DBLCLK) id = IDC_PD_ATTACH;
      if (id == IDC_PD_REFRESH) {
        PdRefresh();
      } else if (id == IDC_PD_ATTACH) {
        int sel = (int)::SendMessageW(g_pd.list, LB_GETCURSEL, 0, 0);
        if (sel >= 0) g_pd.chosen = (DWORD)::SendMessageW(g_pd.list, LB_GETITEMDATA, sel, 0);
        ::DestroyWindow(hwnd);
      } else if (id == IDC_PD_CANCEL || id == IDCANCEL) {
        ::DestroyWindow(hwnd);
      }
      return 0;
    }

    case WM_DRAWITEM: {
      DRAWITEMSTRUCT* dsb = (DRAWITEMSTRUCT*)lp;
      if (dsb->CtlType == 4 /*ODT_BUTTON*/) { DrawDarkButton(dsb); return TRUE; }
      break;
    }
    case WM_ERASEBKGND:
      // 背景由 WM_PAINT 双缓冲整幅覆盖，这里不擦，避免“擦→画”两次刷屏
      return 1;
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
      HDC dc = (HDC)wp;
      ::SetBkColor(dc, kEditBg);
      ::SetTextColor(dc, kEditText);
      return (LRESULT)GetCachedBrush(kEditBg);
    }
    case WM_CTLCOLORSTATIC: {
      HDC dc = (HDC)wp;
      ::SetBkColor(dc, kPanelBg);
      ::SetTextColor(dc, kEditTextSub);
      return (LRESULT)GetCachedBrush(kPanelBg);
    }

    case WM_CLOSE:
      ::DestroyWindow(hwnd);
      return 0;
  }
  return ::DefWindowProcW(hwnd, msg, wp, lp);
}

static void AttachProcess(HWND parent) {
  if (g.dbg.IsAttached()) {
    ::MessageBoxW(parent, L"已附加到目标进程。请先\"文件-分离\"再附加其他进程。",
                  L"提示", MB_OK | MB_ICONINFORMATION);
    return;
  }

  // 注册对话框窗口类（仅一次）
  static const wchar_t* kProcDlgClass = L"CEScanProcDlg";
  static bool clsRegistered = false;
  if (!clsRegistered) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = ProcDlgProc;
    wc.hInstance = g.inst;
    wc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = ::CreateSolidBrush(kPanelBg);
    wc.lpszClassName = kProcDlgClass;
    ::RegisterClassW(&wc);
    clsRegistered = true;
  }

  // 模态弹出
  g_pd = ProcDlgState{};
  ::EnableWindow(parent, FALSE);

  RECT work{};
  ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
  const int dw = kProcDlgW, dh = kProcDlgH;   // 尺寸见 ThemeColors.h（底部留 logo 宫格区）
  int dx = work.left + ((work.right - work.left) - dw) / 2;
  int dy = work.top + ((work.bottom - work.top) - dh) / 2;

  HWND dlg = ::CreateWindowExW(WS_EX_DLGMODALFRAME, kProcDlgClass, L"选择目标进程",
                               WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, dx, dy, dw, dh,
                               parent, nullptr, g.inst, nullptr);
  ::ShowWindow(dlg, SW_SHOW);
  ::UpdateWindow(dlg);
  ::SetFocus(dlg);

  MSG msg;
  while (::GetMessageW(&msg, nullptr, 0, 0)) {
    if (msg.message == WM_QUIT) {
      ::PostQuitMessage((int)msg.wParam);
      break;
    }
    if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE && msg.hwnd == dlg) {
      ::DestroyWindow(dlg);
    }
    if (!::IsWindow(dlg)) break;
    ::TranslateMessage(&msg);
    ::DispatchMessageW(&msg);
  }

  ::EnableWindow(parent, TRUE);
  ::SetActiveWindow(parent);
  if (!::IsWindow(dlg) == false) { /* dlg 已销毁 */ }

  if (g_pd.chosen == 0) return;
  DWORD targetPid = g_pd.chosen;

  // 打开内存访问句柄（扫描用）
  g.proc.Close();
  std::string err;
  if (!g.proc.Open(targetPid, &err)) {
    ::MessageBoxW(parent, ToW(err).c_str(), L"打开进程失败", MB_OK | MB_ICONWARNING);
    return;
  }
  if (!g.dbg.Attach(targetPid, &err)) {
    ::MessageBoxW(parent, ToW(err).c_str(), L"附加失败", MB_OK | MB_ICONWARNING);
    return;
  }
  g.uiRunning = true;
  wchar_t buf[512];
  std::swprintf(buf, 256, L"目标: PID %u %s    [运行中]", targetPid,
                g.proc.IsTargetWOW64() ? L"(32位)" : L"(64位)");
  StatusText(buf);
  AddLogLine("已附加 PID " + std::to_string(targetPid));
  // OD 式：附加即列全模块清单进日志数据窗口
  LogDataAdd(L"", L"进程附加");
  {
    wchar_t hb[16];
    for (const ModuleEntry& m : g.proc.CachedModules()) {
      std::swprintf(hb, 16, L"%012llX", (unsigned long long)m.base);
      LogDataAdd(hb, L"Module " + (m.path.empty() ? m.name : m.path));
    }
  }

  // 确保 CPU / 断点 / 日志 窗口已打开
  if (!g.cpu || !IsWindow(g.cpu))
    NewChild(kChildCpu, L"CPU — 反汇编 / 寄存器 / 数据 / 堆栈", kDefCpuW, kDefCpuH);
  // OD 式初始视口：主模块入口点（对应 OD 打开程序的 00401000），
  // 而不是断在系统 DLL 里的线程 RIP（7FF8... 那种 ntdll 地址）
  g.disasmBase = 0;
  g.followRip = false;
  bool entryOk = false;
  {
    // 找主模块：映像名与进程名一致；匹配不到就取第一个模块
    const std::vector<ModuleEntry>& mods = g.proc.CachedModules();
    const ModuleEntry* main = nullptr;
    std::wstring imageName = g.proc.Name();
    for (const ModuleEntry& m : mods)
      if (_wcsicmp(m.name.c_str(), imageName.c_str()) == 0) { main = &m; break; }
    if (!main && !mods.empty()) main = &mods[0];
    if (main && main->base != 0) {
      // OD 式初始视口：主模块**第一个区块的起始**（通常 RVA 0x1000，即 00401000 那个位置），
      // 不是入口点——入口在 .text 深处（如 004019E4），OD 打开程序先看到的是代码区开头。
      // 但**加壳 / 受保护目标**（64 位游戏居多）的区块首页常因 PAGE_NOACCESS 或反作弊
      // 拦 RPM 而读不到：那样视口从附加起就是空的，用户看到的就是"反汇编一片空白、
      // 点什么都没反应"。所以这里按 最小区块 -> 入口点 -> 其余区块 依次探测，挑第一个
      // 真的读得到内容的地址（拿到内容才是默认视口的意义）。
      unsigned char pe[0x400];
      size_t got = g.proc.ReadPartial(main->base, pe, sizeof(pe));
      if (got >= 0x40) {
        uint32_t eLfanew = 0, initRva = 0;
        std::memcpy(&eLfanew, pe + 0x3C, 4);
        if (eLfanew >= 0x40 && eLfanew + 0x2C <= got &&
            pe[eLfanew] == 'P' && pe[eLfanew + 1] == 'E') {
          const uint16_t nSec = *(const uint16_t*)(pe + eLfanew + 6);
          const uint16_t optSize = *(const uint16_t*)(pe + eLfanew + 20);
          const uint32_t secTab = eLfanew + 4 + 20 + optSize;
          std::vector<uint32_t> secRvas;
          for (int i = 0; i < (int)nSec; ++i) {
            const uint32_t off = secTab + (uint32_t)i * 40;
            if (off + 40 > got) break;
            const uint32_t va = *(const uint32_t*)(pe + off + 12);
            const uint32_t vsz = *(const uint32_t*)(pe + off + 8);
            if (vsz == 0 || va == 0) continue;
            secRvas.push_back(va);
            if (initRva == 0 || va < initRva) initRva = va;
          }
          uint32_t entryRva = 0;
          std::memcpy(&entryRva, pe + eLfanew + 4 + 20 + 16, 4);
          if (initRva == 0) initRva = entryRva;
          // 候选顺序：首区块（OD 约定）-> 入口点 -> 区块表其余项
          std::vector<uint32_t> cands;
          auto pushCand = [&cands](uint32_t r) {
            if (r == 0) return;
            for (uint32_t x : cands) if (x == r) return;
            cands.push_back(r);
          };
          pushCand(initRva);
          pushCand(entryRva);
          for (uint32_t r : secRvas) pushCand(r);

          ptruint chosen = 0;
          uint32_t chosenRva = 0;
          const char* how = "首区块";
          unsigned char probe[16];
          for (size_t i = 0; i < cands.size() && chosen == 0; ++i) {
            const ptruint a = main->base + cands[i];
            if (g.proc.ReadPartial(a, probe, sizeof(probe)) == 0) continue;
            chosen = a;
            chosenRva = cands[i];
            how = (cands[i] == initRva) ? "首区块"
                  : (cands[i] == entryRva) ? "入口点(首区块不可读)" : "回退区块(前两者不可读)";
          }
          if (chosen == 0) {
            chosen = main->base + (initRva ? initRva : 0x1000);
            chosenRva = initRva ? initRva : 0x1000;
            how = "全部不可读";
          }
          g.disasmBase = chosen;
          entryOk = true;
          char ebuf[80], rbuf[24];
          std::snprintf(ebuf, sizeof(ebuf), "%012llX", (unsigned long long)chosen);
          std::snprintf(rbuf, sizeof(rbuf), "%lX", (unsigned long)chosenRva);
          AddLogLine(std::string("初始视口: ") + ebuf + "  (" + ToA(main->name) + "+0x" +
                     rbuf + ", " + how + ")");
          if (std::string(how) == "全部不可读")
            AddLogLine("初始视口: 该模块代码页读不到（加壳或反作弊拦读）—— "
                       "面板会显示「地址不可读」提示；可先在内存地图里找一个可读区块再跳转");
        }
      }
    }
  }
  if (!entryOk) {
    // 兜底：只要知道主模块基址，就盲用 基址+0x1000（OD 的 00401000 约定位置），
    // 绝不退回 RIP（RIP 常停在指令中间，反汇编出一屏垃圾）。
    // 只有连主模块都找不到时才跟随 RIP。
    const std::vector<ModuleEntry>& mods2 = g.proc.CachedModules();
    ptruint base2 = 0;
    if (!mods2.empty() && mods2[0].base != 0) base2 = mods2[0].base;
    if (base2 != 0) {
      unsigned char probe[16];
      ptruint cand0x1000 = base2 + 0x1000;
      // 约定位置读不到就退到模块基址本身（PE 头总能读到，至少视口不是一片空白）
      g.disasmBase = (g.proc.ReadPartial(cand0x1000, probe, sizeof(probe)) > 0)
                     ? cand0x1000 : base2;
      g.followRip = false;
      entryOk = true;
      char ebuf[80];
      std::snprintf(ebuf, sizeof(ebuf), "%012llX", (unsigned long long)g.disasmBase);
      AddLogLine(std::string("初始视口: PE 头解析失败，按约定定位 ") + std::string(ebuf) +
                 "  (" + ToA(mods2[0].name) + "+0x1000)");
    } else {
      AddLogLine("初始视口: 找不到主模块，退回跟随线程 RIP");
      g.followRip = true;
      DWORD tid = PickFocusTid();
      if (tid != 0) {
        HANDLE h = ::OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
        if (h) {
          CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
          if (::GetThreadContext(h, &ctx)) g.disasmBase = (ptruint)ctx.Rip;
          ::CloseHandle(h);
        }
      }
    }
  }
  g.lastDisasmBase = 0;            // 强制首次重建（视口刚定位）
  g.dumpBase = 0;                  // 数据窗口跟随新视口重新定位
  g.dumpScrollBase = 0;
  g.stackOff = 0;
  ResetApiNameCache();             // 跨目标必须清：否则注释列拿上一个进程的导出表
  UpdateCpuWindow();
  ::PostMessageW(g.cpu ? g.cpu : nullptr, WM_PAINT, 0, 0);
  if (!g.bps || !IsWindow(g.bps)) NewChild(kChildBps, L"断点 / 谁访问谁写入", kDefBpsW, kDefBpsH);
  if (!g.log || !IsWindow(g.log)) NewChild(kChildLog, L"日志", kDefLogW, kDefLogH);
  if (!g.logData || !IsWindow(g.logData))
    NewChild(kChildLogData, L"日志数据", kDefLogDW, kDefLogDH);
  FlushPendingLogData();
  UpdateCpuWindow();
  RefreshThreadList();
  RefreshMapList();
}

static void DetachProcess() {
  // 分离前先把「线程定位」的硬件断点摘掉：DR 是写在目标线程上的，
  // 调试会话一断就没人负责清了，而这段时间目标还在跑（每次访问都吃一次
  // STATUS_SINGLE_STEP，却没有调试器来应答）→ 目标会莫名其妙卡死/退出。
  ce::TlStopMonitor();
  g.dbg.StopFind();
  g.dbg.Detach();
  g.proc.Close();
  g.uiRunning = false;
  StatusText(L"已分离");
  AddLogLine("已分离");
}

//=============================================================================
// 控件创建
//=============================================================================

// ---- CPU 底部 Command 输入框（OD 式命令栏）----
// 语法：直接十六进制地址=跳转；`地址=值`/`地址,值`=写 qword；regs=刷新寄存器
static LRESULT CALLBACK CmdEditProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  if (m == WM_KEYDOWN && wp == VK_RETURN) {
    wchar_t txt[256] = {};
    ::GetWindowTextW(h, txt, 255);
    // 去首尾空白（宽字版本）
    wchar_t* b = txt;
    while (*b == L' ' || *b == L'\t') ++b;
    wchar_t* e = b + wcslen(b);
    while (e > b && (e[-1] == L' ' || e[-1] == L'\t')) --e;
    *e = L'\0';
    std::wstring t = b;
    if (!t.empty()) {
      // 解析十六进制地址/数值（忽略 0x 前缀）
      auto parseAddr = [](const std::wstring& s) -> ptruint {
        std::string a = ToA(s.c_str());
        return (ptruint)std::strtoull(a.c_str(), nullptr, 16);
      };
      size_t eq = t.find(L'=');
      size_t cm = t.find(L',');
      size_t sep = (eq != std::wstring::npos) ? eq : cm;
      if (sep != std::wstring::npos) {
        // 写内存：addr=值
        ptruint addr = parseAddr(t.substr(0, sep));
        ptruint val  = parseAddr(t.substr(sep + 1));
        if (addr > 0x10000) {
          unsigned long long v = (unsigned long long)val;
          size_t wr = 0;
          if (g.proc.Write(addr, (const unsigned char*)&v, 8, &wr) && wr == 8) {
            StatusText(L"已写入");
          } else {
            StatusText(L"写入失败（内存不可写?）");
          }
          UpdateCpuWindow();
        }
      } else if (_wcsnicmp(t.c_str(), L"regs", 4) == 0) {
        UpdateCpuWindow();
      } else {
        // 跳转：十六进制地址
        ptruint addr = parseAddr(t);
        if (addr >= 0x1000) {
          g.disasmBase = addr;
          g.followRip = false;
          UpdateCpuWindow();      // 读不到时 ShowDisasmUnreadable 会写状态栏/日志提示
          if (!g.disasmBad) {
            wchar_t sb[160];
            std::swprintf(sb, 160, L"地址跳转: %012llX  OK", (unsigned long long)addr);
            StatusText(sb);
          }
          AddLogLine("命令行跳转: " + ToA(t.substr(0, 32)));
        } else {
          StatusText(L"地址跳转: 无效地址（需要 >= 1000）");
        }
      }
    }
    return 0;
  }
  if (m == WM_KEYDOWN && wp == VK_ESCAPE) {
    ::SetWindowTextW(h, L"");
    return 0;
  }
  return ::CallWindowProcW(s_oldCmdEdit, h, m, wp, lp);
}

static void CreateCpuControls(HWND child) {
  auto mk = [&](int id, const wchar_t* cls, const wchar_t* text, DWORD style) {
    // 暗色主题：BUTTON 一律自绘（系统主题按钮无法改底色）
    const bool isBtn = cls && ::wcscmp(cls, L"BUTTON") == 0;
    const DWORD btnType = style & 0x0F;   // 原按钮类型（0=下压,3=自动复选）
    if (isBtn) style |= BS_OWNERDRAW;
    HWND c = ::CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10,
                               child, (HMENU)(INT_PTR)id, g.inst, nullptr);
    if (isBtn) MakeDarkButton(c, btnType);
    // Win10 1809+：套暗色主题，使系统滚动条/边框不再是浅色
    if (cls && (::wcscmp(cls, L"LISTBOX") == 0 || ::wcscmp(cls, WC_LISTVIEWW) == 0))
      ;  // 滚动条保持系统默认配色与经典凹凸外观（用户要求，不套暗色主题）
    if (cls && ::wcscmp(cls, WC_LISTVIEWW) == 0) {   // ListView 空白区/文字底色
      ::SendMessageW(c, LVM_SETBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTCOLOR, 0, (LPARAM)kListText);
    }
    ::SendMessageW(c, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
    return c;
  };
  // 顶部跳转框已删（点击无反馈、占地方）：地址跳转改走反汇编右键菜单-地址跳转
  // 系统滚动条拖动无效（列表内容即视口，没有真实滚动范围），不创建：
  // 滚动一律走滚轮 / OD 式虚拟滚动条 / 拖动刷选自动滚边
  mk(IDC_DISASM, L"LISTBOX", nullptr, WS_BORDER | LBS_NOINTEGRALHEIGHT | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS);
  {
    static bool regClsDone = false;
    if (!regClsDone) {
      WNDCLASSW wc{};
      wc.lpfnWndProc = RegPanelProc;
      wc.hInstance = g.inst;
      wc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
      wc.hbrBackground = nullptr;
      wc.lpszClassName = kRegPanelClass;
      ::RegisterClassW(&wc);
      regClsDone = true;
    }
  }
  HWND regs = mk(IDC_REGS, kRegPanelClass, nullptr, WS_BORDER | WS_VISIBLE);
  // 转储改自绘：画 OD 式列分隔线（地址|机器码 红、机器码|备注 绿）并支持拖动调列宽
  HWND dump = mk(IDC_DUMP, L"LISTBOX", nullptr,
                 WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_OWNERDRAWFIXED |
                     LBS_HASSTRINGS);
  HWND stk = mk(IDC_STACK, L"LISTBOX", nullptr,
                WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_OWNERDRAWFIXED |
                    LBS_HASSTRINGS);
  for (HWND h : {regs, dump, stk}) ::SendMessageW(h, WM_SETFONT, (WPARAM)g.monoFont, TRUE);
  // 转储/堆栈子类化：列分隔线拖动（ColDragListProc，转储再透传 DumpListProc 滚动联动）
  s_oldDumpProc = (WNDPROC)::SetWindowLongPtrW(dump, GWLP_WNDPROC, (LONG_PTR)ColDragListProc);
  s_oldStkProc  = (WNDPROC)::SetWindowLongPtrW(stk, GWLP_WNDPROC, (LONG_PTR)ColDragListProc);
  // 滚轮动态反汇编：子类化列表拦截 WM_MOUSEWHEEL
  {
    HWND dis = ::GetDlgItem(child, IDC_DISASM);
    if (dis) s_oldDisProc = (WNDPROC)::SetWindowLongPtrW(dis, GWLP_WNDPROC, (LONG_PTR)DisasmListProc);
  }
  // OD 式相对虚拟滚动条：反汇编面板右缘竖条（拖动=平移视口地址，松手滑块回中、地址保持）
  {
    static bool regVsDone = false;
    if (!regVsDone) {
      WNDCLASSW wc{};
      wc.lpfnWndProc = VScrollProc;
      wc.hInstance = g.inst;
      wc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
      wc.hbrBackground = nullptr;
      wc.lpszClassName = kVScrollClass;
      ::RegisterClassW(&wc);
      regVsDone = true;
    }
    ::CreateWindowExW(0, kVScrollClass, nullptr, WS_CHILD | WS_VISIBLE,
                      0, 0, 14, 14, child, (HMENU)(INT_PTR)IDC_VSCROLL, g.inst, nullptr);
    {
      HWND vs = ::GetDlgItem(child, IDC_VSCROLL);
      char tb[80];
      std::snprintf(tb, sizeof(tb), "vscroll create hwnd=%p", (void*)vs);
      UiTrace(tb);
    }
  }
  // ---- OD 式底部命令栏：Command 标签 + 输入框 + ESP/EBP + 信息行 ----
  // 字体：9 号宋体（集中配置 kFontCmdName/kFontCmdHeight，见 ThemeColors.h）
  static HFONT g_cmdFont = nullptr;
  if (!g_cmdFont) {
    g_cmdFont = ::CreateFontW(kFontCmdHeight, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                              GB2312_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, kFontCmdName);
  }
  mk(IDC_CMDLABEL, L"STATIC", L"Command:", SS_LEFT);
  mk(IDC_CMD, L"EDIT", nullptr, WS_BORDER | ES_AUTOHSCROLL);
  mk(IDC_CMD_ESP, L"STATIC", L"ESP=--------", SS_LEFT);
  mk(IDC_CMD_EBP, L"STATIC", L"EBP=--------", SS_LEFT);
  g_cmdEdit = ::GetDlgItem(child, IDC_CMD);
  for (HWND c : {Ctrl(child, IDC_CMDLABEL), Ctrl(child, IDC_CMD), Ctrl(child, IDC_CMD_ESP),
                 Ctrl(child, IDC_CMD_EBP)})
    ::SendMessageW(c, WM_SETFONT, (WPARAM)g_cmdFont, TRUE);
  if (g_cmdEdit)
    s_oldCmdEdit = (WNDPROC)::SetWindowLongPtrW(g_cmdEdit, GWLP_WNDPROC,
                                                (LONG_PTR)CmdEditProc);
}

static void CreateScanControls(HWND child) {
  auto mk = [&](int id, const wchar_t* cls, const wchar_t* text, DWORD style) {
    // 暗色主题：BUTTON 一律自绘（系统主题按钮无法改底色）
    const bool isBtn = cls && ::wcscmp(cls, L"BUTTON") == 0;
    const DWORD btnType = style & 0x0F;   // 原按钮类型（0=下压,3=自动复选）
    if (isBtn) style |= BS_OWNERDRAW;
    HWND c = ::CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10,
                               child, (HMENU)(INT_PTR)id, g.inst, nullptr);
    if (isBtn) MakeDarkButton(c, btnType);
    // Win10 1809+：套暗色主题，使系统滚动条/边框不再是浅色
    if (cls && (::wcscmp(cls, L"LISTBOX") == 0 || ::wcscmp(cls, WC_LISTVIEWW) == 0))
      ;  // 滚动条保持系统默认配色与经典凹凸外观（用户要求，不套暗色主题）
    if (cls && ::wcscmp(cls, WC_LISTVIEWW) == 0) {   // ListView 空白区/文字底色
      ::SendMessageW(c, LVM_SETBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTCOLOR, 0, (LPARAM)kListText);
    }
    ::SendMessageW(c, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
    return c;
  };
  mk(IDC_S_TYPE, L"STATIC", L"类型:", SS_LEFT);
  HWND typeCombo = mk(IDC_TYPE, L"COMBOBOX", nullptr, CBS_DROPDOWNLIST | WS_VSCROLL);
  mk(IDC_S_OPT, L"STATIC", L"方式:", SS_LEFT);
  HWND optCombo = mk(IDC_OPTION, L"COMBOBOX", nullptr, CBS_DROPDOWNLIST | WS_VSCROLL);
  mk(IDC_S_VAL, L"STATIC", L"数值:", SS_LEFT);
  mk(IDC_V1, L"EDIT", nullptr, WS_BORDER | ES_AUTOHSCROLL);
  mk(IDC_S_TILDE, L"STATIC", L"~", SS_CENTER);
  mk(IDC_V2, L"EDIT", nullptr, WS_BORDER | ES_AUTOHSCROLL);
  mk(IDC_HEX, L"BUTTON", L"十六进制", BS_AUTOCHECKBOX);
  mk(IDC_S_EXCM, L"STATIC", L"排除模块(逗号分隔):", SS_LEFT);
  mk(IDC_EXCMODS, L"EDIT", nullptr, WS_BORDER | ES_AUTOHSCROLL);
  mk(IDC_S_EXCR, L"STATIC", L"排除区间(十六进制 a-b):", SS_LEFT);
  mk(IDC_EXCRANGE, L"EDIT", nullptr, WS_BORDER | ES_AUTOHSCROLL);
  mk(IDC_WRONLY, L"BUTTON", L"只扫描可写内存", BS_AUTOCHECKBOX);
  mk(IDC_FIRST, L"BUTTON", L"首次扫描", BS_PUSHBUTTON);
  mk(IDC_NEXT, L"BUTTON", L"再次扫描", BS_PUSHBUTTON);
  mk(IDC_NEW, L"BUTTON", L"新扫描", BS_PUSHBUTTON);
  mk(IDC_PROG, PROGRESS_CLASSW, nullptr, 0);
  mk(IDC_COUNT, L"STATIC", L"结果数: 0", SS_LEFT);
  HWND results = mk(IDC_RESULTS, WC_LISTVIEWW, nullptr,
                    LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS | WS_BORDER | WS_VSCROLL);
  ListView_SetExtendedListViewStyle(results,
                                    LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
  AddListColumn(results, L"地址", 150);
  AddListColumn(results, L"数值(扫描时)", 240);
  AddListColumn(results, L"数值(当前)", 240);
  mk(IDC_S_WV, L"STATIC", L"写入数值:", SS_LEFT);
  mk(IDC_WV, L"EDIT", nullptr, WS_BORDER | ES_AUTOHSCROLL);
  mk(IDC_WRITEV, L"BUTTON", L"写入到选中地址", BS_PUSHBUTTON);

  struct { const wchar_t* name; VariableType t; } types[] = {
      {L"Byte", VariableType::vtByte},      {L"2 Bytes", VariableType::vtWord},
      {L"4 Bytes", VariableType::vtDword},  {L"8 Bytes", VariableType::vtQword},
      {L"Float", VariableType::vtSingle},   {L"Double", VariableType::vtDouble},
      {L"String", VariableType::vtString},  {L"Unicode", VariableType::vtUnicodeString},
      {L"AOB", VariableType::vtByteArray},  {L"Binary", VariableType::vtBinary},
  };
  for (auto& t : types) {
    int i = (int)::SendMessageW(typeCombo, CB_ADDSTRING, 0, (LPARAM)t.name);
    ::SendMessageW(typeCombo, CB_SETITEMDATA, i, (LPARAM)t.t);
  }
  ::SendMessageW(typeCombo, CB_SETCURSEL, 2, 0);

  const wchar_t* opts[] = {L"精确的数值",   L"大于",     L"小于",      L"介于",
                           L"增大了的数值", L"增大了...", L"减小了的数值", L"减小了...",
                           L"变动的数值",   L"未变动",    L"未知初始值"};
  for (const wchar_t* o : opts) ::SendMessageW(optCombo, CB_ADDSTRING, 0, (LPARAM)o);
  ::SendMessageW(optCombo, CB_SETCURSEL, 0, 0);
}

static void CreateMapControls(HWND child) {
  auto mk = [&](int id, const wchar_t* cls, const wchar_t* text, DWORD style) {
    // 暗色主题：BUTTON 一律自绘（系统主题按钮无法改底色）
    const bool isBtn = cls && ::wcscmp(cls, L"BUTTON") == 0;
    const DWORD btnType = style & 0x0F;   // 原按钮类型（0=下压,3=自动复选）
    if (isBtn) style |= BS_OWNERDRAW;
    HWND c = ::CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10,
                               child, (HMENU)(INT_PTR)id, g.inst, nullptr);
    if (isBtn) MakeDarkButton(c, btnType);
    // Win10 1809+：套暗色主题，使系统滚动条/边框不再是浅色
    if (cls && (::wcscmp(cls, L"LISTBOX") == 0 || ::wcscmp(cls, WC_LISTVIEWW) == 0))
      ;  // 滚动条保持系统默认配色与经典凹凸外观（用户要求，不套暗色主题）
    if (cls && ::wcscmp(cls, WC_LISTVIEWW) == 0) {   // ListView 空白区/文字底色
      ::SendMessageW(c, LVM_SETBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTCOLOR, 0, (LPARAM)kListText);
    }
    ::SendMessageW(c, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
    return c;
  };
  mk(IDC_MAPREFRESH, L"BUTTON", L"刷新", BS_PUSHBUTTON);
  HWND list = mk(IDC_MAPLIST, WC_LISTVIEWW, nullptr,
                 LVS_REPORT | LVS_SHOWSELALWAYS | WS_BORDER | WS_VSCROLL);
  ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
  AddListColumn(list, L"基址", 130);
  AddListColumn(list, L"大小", 130);
  AddListColumn(list, L"保护", 110);
  AddListColumn(list, L"类型", 90);
  AddListColumn(list, L"所属模块", 220);
}

static void CreateThreadsControls(HWND child) {
  auto mk = [&](int id, const wchar_t* cls, const wchar_t* text, DWORD style) {
    // 暗色主题：BUTTON 一律自绘（系统主题按钮无法改底色）
    const bool isBtn = cls && ::wcscmp(cls, L"BUTTON") == 0;
    const DWORD btnType = style & 0x0F;   // 原按钮类型（0=下压,3=自动复选）
    if (isBtn) style |= BS_OWNERDRAW;
    HWND c = ::CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10,
                               child, (HMENU)(INT_PTR)id, g.inst, nullptr);
    if (isBtn) MakeDarkButton(c, btnType);
    // Win10 1809+：套暗色主题，使系统滚动条/边框不再是浅色
    if (cls && (::wcscmp(cls, L"LISTBOX") == 0 || ::wcscmp(cls, WC_LISTVIEWW) == 0))
      ;  // 滚动条保持系统默认配色与经典凹凸外观（用户要求，不套暗色主题）
    if (cls && ::wcscmp(cls, WC_LISTVIEWW) == 0) {   // ListView 空白区/文字底色
      ::SendMessageW(c, LVM_SETBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTCOLOR, 0, (LPARAM)kListText);
    }
    ::SendMessageW(c, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
    return c;
  };
  mk(IDC_THRREFRESH, L"BUTTON", L"刷新", BS_PUSHBUTTON);
  HWND list = mk(IDC_THRLIST, L"LISTBOX", nullptr, WS_BORDER | WS_VSCROLL);
  ::SendMessageW(list, WM_SETFONT, (WPARAM)g.monoFont, TRUE);
}

static void CreateBpsControls(HWND child) {
  auto mk = [&](int id, const wchar_t* cls, const wchar_t* text, DWORD style) {
    // 暗色主题：BUTTON 一律自绘（系统主题按钮无法改底色）
    const bool isBtn = cls && ::wcscmp(cls, L"BUTTON") == 0;
    const DWORD btnType = style & 0x0F;   // 原按钮类型（0=下压,3=自动复选）
    if (isBtn) style |= BS_OWNERDRAW;
    HWND c = ::CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10,
                               child, (HMENU)(INT_PTR)id, g.inst, nullptr);
    if (isBtn) MakeDarkButton(c, btnType);
    // Win10 1809+：套暗色主题，使系统滚动条/边框不再是浅色
    if (cls && (::wcscmp(cls, L"LISTBOX") == 0 || ::wcscmp(cls, WC_LISTVIEWW) == 0))
      ;  // 滚动条保持系统默认配色与经典凹凸外观（用户要求，不套暗色主题）
    if (cls && ::wcscmp(cls, WC_LISTVIEWW) == 0) {   // ListView 空白区/文字底色
      ::SendMessageW(c, LVM_SETBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTCOLOR, 0, (LPARAM)kListText);
    }
    ::SendMessageW(c, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
    return c;
  };
  mk(IDC_S_BADDR, L"STATIC", L"地址(十六进制):", SS_LEFT);
  mk(IDC_BADDR, L"EDIT", nullptr, WS_BORDER | ES_AUTOHSCROLL);
  mk(IDC_S_BKIND, L"STATIC", L"监视类型:", SS_LEFT);
  HWND kind = mk(IDC_BKIND, L"COMBOBOX", nullptr, CBS_DROPDOWNLIST | WS_VSCROLL);
  mk(IDC_BTN_INT3, L"BUTTON", L"INT3 执行断点", BS_PUSHBUTTON);
  mk(IDC_BTN_HW, L"BUTTON", L"硬件断点", BS_PUSHBUTTON);
  mk(IDC_BTN_PG, L"BUTTON", L"页守卫断点", BS_PUSHBUTTON);
  mk(IDC_BTN_DELBP, L"BUTTON", L"删除断点", BS_PUSHBUTTON);
  mk(IDC_BTN_FINDACC, L"BUTTON", L"谁访问了它", BS_PUSHBUTTON);
  mk(IDC_BTN_FINDWR, L"BUTTON", L"谁写入了它", BS_PUSHBUTTON);
  mk(IDC_BTN_STOPFIND, L"BUTTON", L"停止监控", BS_PUSHBUTTON);
  mk(IDC_S_BPS, L"STATIC", L"断点列表:", SS_LEFT);
  mk(IDC_BPLIST, L"LISTBOX", nullptr, WS_BORDER | WS_VSCROLL);
  mk(IDC_S_HITS, L"STATIC", L"命中记录(最近在前):", SS_LEFT);
  HWND hits = mk(IDC_HITS, WC_LISTVIEWW, nullptr,
                 LVS_REPORT | LVS_SHOWSELALWAYS | WS_BORDER | WS_VSCROLL);
  ListView_SetExtendedListViewStyle(hits, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
  AddListColumn(hits, L"线程", 70);
  AddListColumn(hits, L"指令地址", 130);
  AddListColumn(hits, L"模块", 180);
  AddListColumn(hits, L"访问", 50);
  AddListColumn(hits, L"指令", 260);
  AddListColumn(hits, L"字节", 160);

  ::SendMessageW(kind, CB_ADDSTRING, 0, (LPARAM)L"执行");
  ::SendMessageW(kind, CB_ADDSTRING, 0, (LPARAM)L"读写");
  ::SendMessageW(kind, CB_ADDSTRING, 0, (LPARAM)L"写入");
  ::SendMessageW(kind, CB_SETCURSEL, 0, 0);
}

static void CreateLogControls(HWND child) {
  auto mk = [&](int id, const wchar_t* cls, const wchar_t* text, DWORD style) {
    // 暗色主题：BUTTON 一律自绘（系统主题按钮无法改底色）
    const bool isBtn = cls && ::wcscmp(cls, L"BUTTON") == 0;
    const DWORD btnType = style & 0x0F;   // 原按钮类型（0=下压,3=自动复选）
    if (isBtn) style |= BS_OWNERDRAW;
    HWND c = ::CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10,
                               child, (HMENU)(INT_PTR)id, g.inst, nullptr);
    if (isBtn) MakeDarkButton(c, btnType);
    // Win10 1809+：套暗色主题，使系统滚动条/边框不再是浅色
    if (cls && (::wcscmp(cls, L"LISTBOX") == 0 || ::wcscmp(cls, WC_LISTVIEWW) == 0))
      ;  // 滚动条保持系统默认配色与经典凹凸外观（用户要求，不套暗色主题）
    if (cls && ::wcscmp(cls, WC_LISTVIEWW) == 0) {   // ListView 空白区/文字底色
      ::SendMessageW(c, LVM_SETBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTCOLOR, 0, (LPARAM)kListText);
    }
    ::SendMessageW(c, WM_SETFONT, (WPARAM)g.monoFont, TRUE);
    return c;
  };
  // LBS_HASSTRINGS：让列表真正保存字符串，否则 LB_GETTEXT 一律返回 LB_ERR
  // （自动化脚本读不到输出窗口内容；反汇编等自绘列表都显式带了这个样式）
  mk(IDC_LOGLIST, L"LISTBOX", nullptr,
     WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_HASSTRINGS);
}

//-----------------------------------------------------------------------------
// 日志数据窗口控件：自绘列表（复制反汇编窗口的框）+ 表头「地址 | 消息」
// 列分隔绿线可拖动调地址列宽（与转储/堆栈同交互）
//-----------------------------------------------------------------------------
static LRESULT CALLBACK LogDataListProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  switch (m) {
    case WM_SETCURSOR: {
      if ((HWND)wp == h) {
        POINT pt{};
        ::GetCursorPos(&pt);
        ::ScreenToClient(h, &pt);
        RECT rc{};
        ::GetClientRect(h, &rc);
        if (pt.x >= g.ldAddrW - 4 && pt.x <= g.ldAddrW + 4 && pt.y < rc.bottom) {
          ::SetCursor(::LoadCursor(nullptr, IDC_SIZEWE));
          return 0;
        }
      }
      break;
    }
    case WM_LBUTTONDOWN: {
      POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
      if (pt.x >= g.ldAddrW - 4 && pt.x <= g.ldAddrW + 4) {
        g.ldDrag = true;
        ::SetCapture(h);
        return 0;
      }
      break;
    }
    case WM_MOUSEMOVE: {
      if (g.ldDrag && ::GetCapture() == h) {
        const int mx = (short)LOWORD(lp);
        RECT rc{};
        ::GetClientRect(h, &rc);
        int nx = mx < 44 ? 44 : (mx > rc.right - 120 ? rc.right - 120 : mx);
        if (nx != g.ldAddrW) {
          g.ldAddrW = nx;
          ::InvalidateRect(h, nullptr, TRUE);
          ::InvalidateRect(::GetParent(h), nullptr, TRUE);   // 表头同步
        }
        return 0;
      }
      break;
    }
    case WM_LBUTTONUP: {
      if (g.ldDrag) {
        g.ldDrag = false;
        ::ReleaseCapture();
        return 0;
      }
      break;
    }
  }
  return ::CallWindowProcW(g.ldPrev, h, m, wp, lp);
}

static void CreateLogDataControls(HWND child) {
  HWND c = ::CreateWindowExW(
      0, L"LISTBOX", nullptr,
      WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL |
          LBS_NOINTEGRALHEIGHT | LBS_HASSTRINGS | LBS_OWNERDRAWFIXED | LBS_NOTIFY,
      0, 0, 10, 10, child, (HMENU)(INT_PTR)IDC_LDLIST, g.inst, nullptr);
  ::SendMessageW(c, WM_SETFONT, (WPARAM)g.monoFont, TRUE);
  ::SendMessageW(c, LB_SETITEMHEIGHT, 0, 18);
  g.ldPrev = (WNDPROC)::SetWindowLongPtrW(c, GWLP_WNDPROC, (LONG_PTR)LogDataListProc);
}

//=============================================================================
// MCP 输出栏窗口控件
//=============================================================================
static void McpLog(const std::string& line) {
  std::string* copy = new std::string(line);
  ::PostMessageW(g.frame, WM_APP_MCP_LOG, 0, (LPARAM)copy);
}

static void McpStatusPart(const std::wstring& text) {
  StatusOwnerSet(1, text);
}

static void McpUpdateStatusPart() {
  if (g.mcpConnected) {
    const auto& c = g.mcpClient.config();
    McpStatusPart(ToW(std::string("MCP: 已连接 ") +
                      (c.useTcp ? c.host + ":" + std::to_string(c.port) : c.pipeName)));
  } else {
    McpStatusPart(L"MCP: 未连接");
  }
}

static void McpConnect() {
  ce::McpClient::Config cfg;
  ce::McpClient* c = &g.mcpClient;
  c->SetStatusCb([](bool up) {
    g.mcpConnected = up;
    ::PostMessageW(g.frame, WM_APP_MCP_STATUS, up ? 1 : 0, 0);
  });
  c->SetLogCb([](const std::string& line) { McpLog(line); });
  std::string err;
  if (c->Connect(cfg, &err)) {
    McpLog("[MCP] 已连接: " + cfg.pipeName);
    McpLog("[MCP] 链接协议: 4字节长度前缀 + JSON-RPC（与 ce_mcp_bridge.lua 一致）");
    McpLog("[MCP] 前提: Cheat Engine 已执行 MCP_Server/ce_mcp_bridge.lua");
    McpLog("[MCP] 菜单: MCP -> ping / 进程信息 可测试");
  } else {
    McpLog("[MCP] 连接失败: " + err);
    ::MessageBoxW(g.frame, ToW(err).c_str(), L"MCP 连接失败", MB_OK | MB_ICONWARNING);
  }
  McpUpdateStatusPart();
}

static void McpDisconnect() {
  g.mcpClient.Disconnect();
  McpLog("[MCP] 已断开");
  McpUpdateStatusPart();
}

static void McpSendCmd(const std::string& method, const std::string& params = "{}") {
  if (!g.mcpClient.IsConnected()) {
    McpLog("[MCP] 未连接，请先 菜单 MCP -> 连接");
    return;
  }
  McpLog(">> " + method + " " + params);
  // 后台线程同步等待响应
  std::thread([method, params]() {
    std::string resp, err;
    if (g.mcpClient.SendWait(method, params, &resp, 8000, &err)) {
      McpLog("<< " + resp);
    } else {
      McpLog("[MCP] 请求失败: " + err);
    }
  }).detach();
}

static void McpRunQuick(int sel) {
  struct Q { const char* label; const char* method; const char* params; };
  static const Q qs[] = {
    {"ping", "ping", "{}"},
    {"进程信息", "get_process_info", "{}"},
    {"枚举模块", "enum_modules", "{}"},
    {"内存区域", "get_memory_regions", "{}"},
    {"dword读取 [当前RIP]", "read_integer", "{}"},   // 参数留空由 CE 侧报错提示
  };
  if (sel < 0 || sel >= 5) return;
  McpSendCmd(qs[sel].method, qs[sel].params);
}

static void CreateMcpControls(HWND child) {
  auto mk = [&](int id, const wchar_t* cls, const wchar_t* text, DWORD style) {
    // 暗色主题：BUTTON 一律自绘（系统主题按钮无法改底色）
    const bool isBtn = cls && ::wcscmp(cls, L"BUTTON") == 0;
    const DWORD btnType = style & 0x0F;   // 原按钮类型（0=下压,3=自动复选）
    if (isBtn) style |= BS_OWNERDRAW;
    HWND c = ::CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10,
                               child, (HMENU)(INT_PTR)id, g.inst, nullptr);
    if (isBtn) MakeDarkButton(c, btnType);
    // Win10 1809+：套暗色主题，使系统滚动条/边框不再是浅色
    if (cls && (::wcscmp(cls, L"LISTBOX") == 0 || ::wcscmp(cls, WC_LISTVIEWW) == 0))
      ;  // 滚动条保持系统默认配色与经典凹凸外观（用户要求，不套暗色主题）
    if (cls && ::wcscmp(cls, WC_LISTVIEWW) == 0) {   // ListView 空白区/文字底色
      ::SendMessageW(c, LVM_SETBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTCOLOR, 0, (LPARAM)kListText);
    }
    ::SendMessageW(c, WM_SETFONT, (WPARAM)g.monoFont, TRUE);
    return c;
  };
  mk(IDC_MCP_LOG, L"LISTBOX", nullptr, WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT);
  mk(IDC_MCP_CMD, L"EDIT", nullptr, WS_BORDER | ES_AUTOHSCROLL);
  mk(IDC_MCP_SEND, L"BUTTON", L"发送", WS_CHILD);
  mk(IDC_MCP_CONNECT, L"BUTTON", L"连接", WS_CHILD);
  mk(IDC_MCP_DISCONNECT, L"BUTTON", L"断开", WS_CHILD);
  HWND q = mk(IDC_MCP_QUICK, L"COMBOBOX", nullptr,
              WS_BORDER | CBS_DROPDOWNLIST | WS_VSCROLL);
  ::SendMessageW(q, CB_ADDSTRING, 0, (LPARAM)L"快速命令...");
  ::SendMessageW(q, CB_ADDSTRING, 0, (LPARAM)L"ping");
  ::SendMessageW(q, CB_ADDSTRING, 0, (LPARAM)L"进程信息");
  ::SendMessageW(q, CB_ADDSTRING, 0, (LPARAM)L"枚举模块");
  ::SendMessageW(q, CB_ADDSTRING, 0, (LPARAM)L"内存区域");
  ::SendMessageW(q, CB_SETCURSEL, 0, 0);
  McpUpdateStatusPart();
}

//=============================================================================
// 中文搜索引擎（OD 复刻）—— 窗口控件
//=============================================================================
static void StrStatusText(const std::wstring& t) {
  // 显示在状态栏第一段
  StatusText(t);
}

static void StrSearchRun(int mode) {
  if (!g.proc.IsOpen()) {
    ::MessageBoxW(g.frame, L"请先附加进程", L"中文搜索引擎", MB_OK | MB_ICONINFORMATION);
    return;
  }
  if (g.strSearchRunning) return;
  g.strSearchRunning = true;
  g.strMode = mode;
  g.strHits.clear();
  HWND list = g.strs ? Ctrl(g.strs, IDC_STR_LIST) : nullptr;
  if (list) ::SendMessageW(list, LVM_DELETEALLITEMS, 0, 0);
  StrStatusText(L"中文搜索引擎: 扫描中...");

  std::thread([mode]() {
    ce::StrSearchOptions opt;
    opt.mode = mode;
    opt.minLength = 4;
    opt.requireChinese = (mode == 3);  // 预留：强制中文模式
    std::vector<ce::StrHit> hits;
    std::string err;
    auto progress = [](int pct) -> bool {
      wchar_t buf[64];
      std::swprintf(buf, 64, L"中文搜索引擎: 扫描中... %d%%", pct);
      StrStatusText(buf);
      return true;  // 暂不提供中止
    };
    bool ok = ce::StrSearch::Run(g.proc.Handle(), opt, hits, progress, &err);
    ::PostMessageW(g.frame, WM_APP_STR_DONE, ok ? 1 : 0, (LPARAM)new std::vector<ce::StrHit>(std::move(hits)));
  }).detach();
}

static void RefreshStrList() {
  if (!g.strs || !IsWindow(g.strs)) return;
  HWND list = Ctrl(g.strs, IDC_STR_LIST);
  // 虚拟列表（LVS_OWNERDATA）：只设条数，内容由 LVN_GETDISPINFO 回调供给
  ::SendMessageW(list, LVM_SETITEMCOUNT, (WPARAM)g.strHits.size(),
                 LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
  wchar_t st[128];
  const wchar_t* modeName = g.strMode == 0 ? L"ASCII Mode" : g.strMode == 1 ? L"UNICODE Mode" : L"智能模式";
  std::swprintf(st, 128, L"共找到字符串：%d 个 - 中文搜索引擎 (%s)",
                (int)g.strHits.size(), modeName);
  StrStatusText(st);
}

static void CreateStrsControls(HWND child) {
  auto mk = [&](int id, const wchar_t* cls, const wchar_t* text, DWORD style) {
    // 暗色主题：BUTTON 一律自绘（系统主题按钮无法改底色）
    const bool isBtn = cls && ::wcscmp(cls, L"BUTTON") == 0;
    const DWORD btnType = style & 0x0F;   // 原按钮类型（0=下压,3=自动复选）
    if (isBtn) style |= BS_OWNERDRAW;
    HWND c = ::CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10,
                               child, (HMENU)(INT_PTR)id, g.inst, nullptr);
    if (isBtn) MakeDarkButton(c, btnType);
    // Win10 1809+：套暗色主题，使系统滚动条/边框不再是浅色
    if (cls && (::wcscmp(cls, L"LISTBOX") == 0 || ::wcscmp(cls, WC_LISTVIEWW) == 0))
      ;  // 滚动条保持系统默认配色与经典凹凸外观（用户要求，不套暗色主题）
    if (cls && ::wcscmp(cls, WC_LISTVIEWW) == 0) {   // ListView 空白区/文字底色
      ::SendMessageW(c, LVM_SETBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(c, LVM_SETTEXTCOLOR, 0, (LPARAM)kListText);
    }
    ::SendMessageW(c, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
    return c;
  };
  mk(IDC_STR_SEARCH, L"BUTTON", L"重新搜索", BS_PUSHBUTTON);
  HWND mode = mk(IDC_STR_MODE, L"COMBOBOX", nullptr, WS_BORDER | CBS_DROPDOWNLIST | WS_VSCROLL);
  ::SendMessageW(mode, CB_ADDSTRING, 0, (LPARAM)L"搜索 ASCII");
  ::SendMessageW(mode, CB_ADDSTRING, 0, (LPARAM)L"搜索 UNICODE");
  ::SendMessageW(mode, CB_ADDSTRING, 0, (LPARAM)L"智能搜索");
  ::SendMessageW(mode, CB_SETCURSEL, g.strMode, 0);
  HWND list = mk(IDC_STR_LIST, WC_LISTVIEWW, nullptr,
                 LVS_REPORT | LVS_SHOWSELALWAYS | WS_BORDER | LVS_OWNERDATA | WS_VSCROLL);
  ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
  AddListColumn(list, L"地址", 130);
  AddListColumn(list, L"长度", 70);
  AddListColumn(list, L"字符串", 600);
}


//=============================================================================
// 子窗口布局
//=============================================================================
static void LayoutChild(HWND child, ChildType type, int w, int h) {
  // 不允许低于全局最小尺寸（GuiConfig.h）
  if (w < kMdiMinWidth) w = kMdiMinWidth;
  if (h < kMdiMinHeight) h = kMdiMinHeight;
  // 分割条辅助：默认隐藏，用到时才显示（每根条厚度 6px，中心对齐给定坐标）
  ::ShowWindow(Ctrl(child, IDC_SPLIT_V), SW_HIDE);
  ::ShowWindow(Ctrl(child, IDC_SPLIT_H), SW_HIDE);
  auto putV = [&](int x, int y, int hh) {
    HWND s = Ctrl(child, IDC_SPLIT_V);
    if (!s) return;
    ::MoveWindow(s, x, y, 6, hh, TRUE);
    ::ShowWindow(s, SW_SHOW);
  };
  auto putH = [&](int x, int y, int ww) {
    HWND s = Ctrl(child, IDC_SPLIT_H);
    if (!s) return;
    ::MoveWindow(s, x, y, ww, 6, TRUE);
    ::ShowWindow(s, SW_SHOW);
  };
  switch (type) {
    case kChildCpu: {
      // 顶部跳转框已删（右键菜单-地址跳转代替）
      // 底部 OD 式命令栏一行（Command 输入行；起始/结束/当前值已并入主窗口状态栏）
      const int cmdH = 26;
      const int tb = kCpuTopGap, margin = kMargin;
      // 四面板（比例可拖动：cpuSplitX / cpuSplitY）
      const int areaW = w - margin * 2;
      const int areaH = h - margin - tb - cmdH;
      int splitX = (int)(areaW * g.cpuSplitX);
      int splitY = (int)(areaH * g.cpuSplitY);
      if (splitX < kCpuMinW) splitX = kCpuMinW;
      if (splitX > areaW - kCpuMinW) splitX = areaW - kCpuMinW;
      if (splitY < kCpuMinH) splitY = kCpuMinH;
      if (splitY > areaH - kCpuMinH) splitY = areaH - kCpuMinH;
      const int barV = kSplitBar, barH = kSplitBar;  // 分割条厚度
      // 反汇编面板右缘留出虚拟滚动条（OD 式竖条）宽度
      const int vsW = kVsW;
      ::MoveWindow(Ctrl(child, IDC_DISASM), margin, tb, splitX - barV / 2 - vsW, splitY - barH / 2, TRUE);
      ::MoveWindow(Ctrl(child, IDC_REGS), margin + splitX + barV / 2, tb,
                   areaW - splitX - barV / 2, splitY - barH / 2, TRUE);
      ::MoveWindow(Ctrl(child, IDC_DUMP), margin, tb + splitY + barH / 2,
                   splitX - barV / 2, areaH - splitY - barH / 2, TRUE);
      ::MoveWindow(Ctrl(child, IDC_STACK), margin + splitX + barV / 2, tb + splitY + barH / 2,
                   areaW - splitX - barV / 2, areaH - splitY - barH / 2, TRUE);
      // 分割条本体（覆盖在缝隙上，供左右/上下拖动）
      putV(margin + splitX - barV / 2, tb, areaH);
      putH(margin, tb + splitY - barH / 2, areaW);
      // 虚拟滚动条：反汇编面板右缘竖条（拖动=平移视口地址，松手滑块回中、地址保持）
      ::MoveWindow(Ctrl(child, IDC_VSCROLL), margin + splitX - barV / 2 - vsW, tb,
                   vsW, splitY - barH / 2, TRUE);
      g.vscrollRect = {margin + splitX - barV / 2 - vsW, tb, vsW, splitY - barH / 2};
      // ---- 底部命令栏（OD 式）：Command 行 + 信息行 ----
      {
        const int cmdY = h - margin - cmdH;
        const int rowH = 22;
        // Command 靠左；ESP/EBP 红字提示右对齐到窗口右缘（一行排布不留大空隙）
        ::MoveWindow(Ctrl(child, IDC_CMDLABEL), margin, cmdY + 2, 62, 20, TRUE);
        ::MoveWindow(Ctrl(child, IDC_CMD), margin + 64, cmdY, 120, rowH, TRUE);
        ::MoveWindow(Ctrl(child, IDC_CMD_ESP), w - margin - 206, cmdY + 2, 96, 18, TRUE);
        ::MoveWindow(Ctrl(child, IDC_CMD_EBP), w - margin - 100, cmdY + 2, 96, 18, TRUE);
      }
      break;
    }
    case kChildScan: {
      const int margin = kMargin, rowH = kRowScanH;
      const int W = w - margin * 2;
      int y = margin;

      // 第一行: 类型 [combo] 方式 [combo] 数值 [v1] ~ [v2]
      auto PutRow = [&](int id, int x, int cw) {
        ::MoveWindow(Ctrl(child, id), x, y, cw, rowH - 4, TRUE);
      };
      auto PutCombo = [&](int id, int x, int cw) {
        ::MoveWindow(Ctrl(child, id), x, y - 2, cw, 200, TRUE);
      };
      int lx = margin;
      ::MoveWindow(Ctrl(child, IDC_S_TYPE), lx, y + 2, 36, 18, TRUE); lx += 38;
      PutCombo(IDC_TYPE, lx, 96); lx += 100;
      ::MoveWindow(Ctrl(child, IDC_S_OPT), lx, y + 2, 36, 18, TRUE); lx += 38;
      PutCombo(IDC_OPTION, lx, 118); lx += 122;
      ::MoveWindow(Ctrl(child, IDC_S_VAL), lx, y + 2, 36, 18, TRUE); lx += 38;
      int remain = w - lx - 110;
      PutRow(IDC_V1, lx, remain / 2 - 14); lx += remain / 2;
      ::MoveWindow(Ctrl(child, IDC_S_TILDE), lx, y + 2, 12, 18, TRUE); lx += 14;
      PutRow(IDC_V2, lx, remain / 2 - 14); lx += remain / 2;
      ::MoveWindow(Ctrl(child, IDC_HEX), lx + 4, y + 2, 100, 20, TRUE);

      y += rowH + 4;
      // 第二行: 排除模块 / 排除区间 / 只扫可写
      lx = margin;
      ::MoveWindow(Ctrl(child, IDC_S_EXCM), lx, y + 2, 118, 18, TRUE); lx += 120;
      int modW = (W - 118 - 150 - 130) / 2;
      PutRow(IDC_EXCMODS, lx, modW); lx += modW + 6;
      ::MoveWindow(Ctrl(child, IDC_S_EXCR), lx, y + 2, 140, 18, TRUE); lx += 142;
      PutRow(IDC_EXCRANGE, lx, w - lx - 136);
      ::MoveWindow(Ctrl(child, IDC_WRONLY), w - 130, y + 2, 126, 20, TRUE);

      y += rowH + 4;
      // 第三行: 按钮 + 进度 + 计数
      ::MoveWindow(Ctrl(child, IDC_FIRST), margin, y, 92, 26, TRUE);
      ::MoveWindow(Ctrl(child, IDC_NEXT), margin + 98, y, 92, 26, TRUE);
      ::MoveWindow(Ctrl(child, IDC_NEW), margin + 196, y, 82, 26, TRUE);
      int btnEnd = margin + 284;
      ::MoveWindow(Ctrl(child, IDC_PROG), btnEnd, y + 4, 220, 18, TRUE);
      ::MoveWindow(Ctrl(child, IDC_COUNT), btnEnd + 228, y + 4, w - btnEnd - 236, 20, TRUE);

      y += rowH + 6;
      // 结果列表（竖条左右拉宽度，横条上下拉高度）
      const int listTop = y;
      const int botY = h - margin - rowH;
      int listW = (int)(W * WinSplitX(kChildScan));
      if (listW < 120) listW = 120;
      if (listW > W) listW = W;
      int regH = botY - listTop;
      if (regH < 60) regH = 60;
      int listBot = listTop + (int)(regH * WinSplitY(kChildScan));
      if (listBot < listTop + 60) listBot = listTop + 60;
      if (listBot > botY) listBot = botY;
      ::MoveWindow(Ctrl(child, IDC_RESULTS), margin, listTop, listW - 3, listBot - listTop - 3, TRUE);
      putV(margin + listW - 3, listTop, botY - listTop);
      putH(margin, listBot - 3, listW);
      // 底行: 写入
      int by = botY;
      ::MoveWindow(Ctrl(child, IDC_S_WV), margin, by + 4, 64, 18, TRUE);
      ::MoveWindow(Ctrl(child, IDC_WV), margin + 66, by + 2, 200, rowH - 6, TRUE);
      ::MoveWindow(Ctrl(child, IDC_WRITEV), margin + 274, by, 150, 26, TRUE);
      break;
    }
    case kChildMap: {
      const int margin = kMargin;
      ::MoveWindow(Ctrl(child, IDC_MAPREFRESH), margin, 6, 70, 24, TRUE);
      int lw = (int)((w - margin * 2) * WinSplitX(kChildMap));
      if (lw < 160) lw = 160;
      if (lw > w - margin * 2) lw = w - margin * 2;
      ::MoveWindow(Ctrl(child, IDC_MAPLIST), margin, 36, lw - 3, h - 44, TRUE);
      putV(margin + lw - 3, 36, h - 44);
      break;
    }
    case kChildThreads: {
      const int margin = kMargin;
      ::MoveWindow(Ctrl(child, IDC_THRREFRESH), margin, 6, 70, 24, TRUE);
      int lw = (int)((w - margin * 2) * WinSplitX(kChildThreads));
      if (lw < 160) lw = 160;
      if (lw > w - margin * 2) lw = w - margin * 2;
      ::MoveWindow(Ctrl(child, IDC_THRLIST), margin, 36, lw - 3, h - 44, TRUE);
      putV(margin + lw - 3, 36, h - 44);
      break;
    }
    case kChildBps: {
      const int margin = kMargin, rowH = kRowBpsH;
      int y = margin;
      // 第一行: 地址 / 监视类型
      ::MoveWindow(Ctrl(child, IDC_S_BADDR), margin, y + 4, 100, 18, TRUE);
      ::MoveWindow(Ctrl(child, IDC_BADDR), margin + 102, y + 2, 180, rowH - 6, TRUE);
      ::MoveWindow(Ctrl(child, IDC_S_BKIND), margin + 292, y + 4, 64, 18, TRUE);
      ::MoveWindow(Ctrl(child, IDC_BKIND), margin + 358, y, 90, 200, TRUE);
      // 第二行: 断点按钮（4 个一排，可换行）
      y += rowH + 2;
      {
        int x = margin;
        const int bw[] = {116, 92, 108, 92, 104, 104, 88};
        const int ids[] = {IDC_BTN_INT3, IDC_BTN_HW, IDC_BTN_PG, IDC_BTN_DELBP,
                           IDC_BTN_FINDACC, IDC_BTN_FINDWR, IDC_BTN_STOPFIND};
        for (int i = 0; i < 7; ++i) {
          if (x + bw[i] > w - margin) { x = margin; y += rowH; }
          ::MoveWindow(Ctrl(child, ids[i]), x, y, bw[i], 24, TRUE);
          x += bw[i] + 6;
        }
        y += rowH + 4;
      }
      // 标签 + 两个列表（中间横条上下拉，右侧竖条左右拉）
      const int listTop = y + 20;
      const int regBot = h - margin - 8;
      int lw = (int)((w - margin * 2) * WinSplitX(kChildBps));
      if (lw < 200) lw = 200;
      if (lw > w - margin * 2) lw = w - margin * 2;
      int mid = listTop + (int)((regBot - listTop) * WinSplitY(kChildBps));
      if (mid < listTop + 70) mid = listTop + 70;
      if (mid > regBot - 70) mid = regBot - 70;
      ::MoveWindow(Ctrl(child, IDC_S_BPS), margin, y, 200, 18, TRUE);
      ::MoveWindow(Ctrl(child, IDC_BPLIST), margin, listTop, lw - 3, mid - 3 - listTop, TRUE);
      putV(margin + lw - 3, listTop, regBot - listTop);
      putH(margin, mid - 3, lw);
      ::MoveWindow(Ctrl(child, IDC_S_HITS), margin, mid + 6, 220, 18, TRUE);
      ::MoveWindow(Ctrl(child, IDC_HITS), margin, mid + 26, lw - 3,
                   h - margin - (mid + 26), TRUE);
      break;
    }
    case kChildLogData: {
      // 表头条(高 kLogDataHdrH) + 列表铺满其余
      const int margin = kMargin;
      ::MoveWindow(Ctrl(child, IDC_LDLIST), margin, kLogDataHdrH,
                   w - margin * 2, h - kLogDataHdrH - margin, TRUE);
      break;
    }
    case kChildLog: {
      const int margin = kMargin;
      int lw = (int)((w - margin * 2) * WinSplitX(kChildLog));
      if (lw < 160) lw = 160;
      if (lw > w - margin * 2) lw = w - margin * 2;
      ::MoveWindow(Ctrl(child, IDC_LOGLIST), margin, 6, lw - 3, h - 14, TRUE);
      putV(margin + lw - 3, 6, h - 14);
      break;
    }
    case kChildMcp: {
      const int margin = kMargin, rowH = kRowMcpH;
      // 第一行: [连接] [断开] [快速命令combo]
      ::MoveWindow(Ctrl(child, IDC_MCP_CONNECT), margin, 6, 64, 24, TRUE);
      ::MoveWindow(Ctrl(child, IDC_MCP_DISCONNECT), margin + 70, 6, 64, 24, TRUE);
      ::MoveWindow(Ctrl(child, IDC_MCP_QUICK), margin + 144, 5, 200, 200, TRUE);
      // 输出日志区（竖条左右拉宽度，横条上下拉高度）
      const int logY = rowH + 8;
      const int cmdH = 26;
      const int regBot = h - cmdH - margin;
      int lw = (int)((w - margin * 2) * WinSplitX(kChildMcp));
      if (lw < 160) lw = 160;
      if (lw > w - margin * 2) lw = w - margin * 2;
      int logBot = logY + (int)((regBot - logY) * WinSplitY(kChildMcp));
      if (logBot < logY + 60) logBot = logY + 60;
      if (logBot > regBot) logBot = regBot;
      ::MoveWindow(Ctrl(child, IDC_MCP_LOG), margin, logY, lw - 3, logBot - logY - 3, TRUE);
      putV(margin + lw - 3, logY, regBot - logY);
      putH(margin, logBot - 3, lw);
      // 底部命令行 + 发送
      ::MoveWindow(Ctrl(child, IDC_MCP_CMD), margin, h - cmdH - margin / 2,
                   w - margin * 2 - 70, cmdH, TRUE);
      ::MoveWindow(Ctrl(child, IDC_MCP_SEND), w - 66, h - cmdH - margin / 2, 58, cmdH, TRUE);
      break;
    }
    case kChildStrs: {
      const int margin = kMargin, rowH = kRowMcpH;
      // 第一行: [重新搜索] [模式combo]
      ::MoveWindow(Ctrl(child, IDC_STR_SEARCH), margin, 6, 90, 24, TRUE);
      ::MoveWindow(Ctrl(child, IDC_STR_MODE), margin + 98, 5, 160, 200, TRUE);
      // 列表（竖条左右拉宽度）
      {
        const int listTop = rowH + 8;
        const int listBot = h - margin;
        int lw = (int)((w - margin * 2) * WinSplitX(kChildStrs));
        if (lw < 160) lw = 160;
        if (lw > w - margin * 2) lw = w - margin * 2;
        ::MoveWindow(Ctrl(child, IDC_STR_LIST), margin, listTop, lw - 3, listBot - listTop, TRUE);
        putV(margin + lw - 3, listTop, listBot - listTop);
      }
      break;
    }
  }
}

//=============================================================================
// MDI 子窗口过程
//=============================================================================
// 监视窗口调试开关（定义提前：ChildProc 的 WM_NOTIFY 需要读取 g_wNoCd）
static bool g_wNoCd = false, g_wNoInfo = false;
static LRESULT CALLBACK ChildProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  const ChildType type = (ChildType)::GetWindowLongPtrW(hwnd, GWLP_USERDATA);

  switch (msg) {
    case WM_CREATE: {
      LPCREATESTRUCTW cs = (LPCREATESTRUCTW)lp;
      const ChildType t = (ChildType)((MDICREATESTRUCTW*)cs->lpCreateParams)->lParam;
      ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)t);
      switch (t) {
        case kChildCpu: CreateCpuControls(hwnd); break;
        case kChildScan: CreateScanControls(hwnd); break;
        case kChildMap: CreateMapControls(hwnd); break;
        case kChildThreads: CreateThreadsControls(hwnd); break;
        case kChildBps: CreateBpsControls(hwnd); break;
        case kChildLog: CreateLogControls(hwnd); break;
        case kChildLogData: CreateLogDataControls(hwnd); break;
        case kChildMcp: CreateMcpControls(hwnd); break;
        case kChildStrs: CreateStrsControls(hwnd); break;
      }
      // 所有子窗口统一挂两根分割条（用不到的由 LayoutChild 隐藏）
      MakeSplitter(hwnd, IDC_SPLIT_V);
      MakeSplitter(hwnd, IDC_SPLIT_H);
      RECT rc;
      ::GetClientRect(hwnd, &rc);
      LayoutChild(hwnd, t, rc.right, rc.bottom);
      return 0;
    }

    case WM_SIZE:
      if (wp != SIZE_MINIMIZED) {
        LayoutChild(hwnd, type, LOWORD(lp), HIWORD(lp));
      }
      break;

    case WM_GETMINMAXINFO: {
      // MDI 子窗口最小尺寸限制（常量定义于 GuiConfig.h）
      MINMAXINFO* mmi = (MINMAXINFO*)lp;
      mmi->ptMinTrackSize.x = kMdiMinWidth;
      mmi->ptMinTrackSize.y = kMdiMinHeight;
      break;
    }

    case WM_CONTEXTMENU: {
      // ---- 内存搜索结果列表右键：CE 主列表同款「查找写入/访问此地址的内容」----
      if (type == kChildScan && (HWND)wp == Ctrl(hwnd, IDC_RESULTS)) {
        HWND list = (HWND)wp;
        int sel = (int)::SendMessageW(list, LVM_GETNEXTITEM, (WPARAM)-1,
                                     MAKELPARAM(LVNI_SELECTED, 0));
        if (sel < 0) return 0;
        ptruint a = g.scan.AddressAt((size_t)sel);
        POINT pt{(short)LOWORD(lp), (short)HIWORD(lp)};
        HMENU m = ::CreatePopupMenu();
        ::AppendMenuW(m, MF_STRING, 5107, L"查找写入此地址的内容\tF6");
        ::AppendMenuW(m, MF_STRING, 5108, L"查找访问此地址的内容\tF5");
        ::AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(m, MF_STRING, 5109, L"停止监控");
        ::AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(m, MF_STRING, 5101, L"断点 F2 (INT3)");
        int cmd = ::TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, 0,
                                   hwnd, nullptr);
        ::DestroyMenu(m);
        std::string err;
        switch (cmd) {
          case 5101: {
            g.dbg.SetInt3(a, &err);
            StatusText(err.empty() ? L"已设置 INT3 断点" : ToW("失败: " + err));
            RefreshBpList();
            break;
          }
          case 5107: StartWatch(true, a); break;
          case 5108: StartWatch(false, a); break;
          case 5109: WatchStopFind(L"已停止监控"); break;
          default: break;
        }
        return 0;
      }
      if ((HWND)wp == Ctrl(hwnd, IDC_DISASM)) {
        HWND list = Ctrl(hwnd, IDC_DISASM);
        int sel = (int)::SendMessageW(list, LB_GETCURSEL, 0, 0);
        if (sel < 0) {
          // 右键时若无选中，按鼠标位置选行
          POINT pt{(short)LOWORD(lp), (short)HIWORD(lp)};
          ::ScreenToClient(list, &pt);
          sel = (int)(pt.y / 18);
          if (sel >= 0 && sel < (int)g.disasmAddr.size()) {
            ::SendMessageW(list, LB_SETCURSEL, sel, 0);
            g.disasmSel = sel;
            ::InvalidateRect(list, nullptr, TRUE);
          }
        }
        // 右键行地址（按鼠标位置定）
        ptruint menuAddr = 0;
        {
          POINT pt{(short)LOWORD(lp), (short)HIWORD(lp)};
          if (pt.x == -1 && pt.y == -1) {  // 键盘菜单键
            if (g.selAddr) menuAddr = g.selAddr;
          } else {
            ::ScreenToClient(list, &pt);
            int mi = (int)(pt.y / 18) + (int)::SendMessageW(list, LB_GETTOPINDEX, 0, 0);
            if (mi >= 0 && mi < (int)g.disasmAddr.size()) menuAddr = g.disasmAddr[mi];
          }
          if (menuAddr == 0 && g.selAddr) menuAddr = g.selAddr;
          if (menuAddr) {
            g.selAddr = menuAddr;   // 右键即设锚点
          }
        }
        // 收集目标地址（多选优先，否则锚点单行）——地址跨滚动持久
        std::vector<ptruint> targets;
        if (!g.multiAddrs.empty()) {
          for (ptruint a : g.multiAddrs) targets.push_back(a);
        } else if (menuAddr) targets.push_back(menuAddr);
        if (menuAddr) {
          HMENU m = ::CreatePopupMenu();
          wchar_t bpLabel[64];
          std::swprintf(bpLabel, 64, L"断点 F2 (INT3)%hs", targets.size() > 1 ? "  [多选]" : "");
          ::AppendMenuW(m, MF_STRING, 5001, bpLabel);
          ::AppendMenuW(m, MF_STRING, 5002, L"硬件执行断点");
          ::AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
          ::AppendMenuW(m, MF_STRING, 5003, L"填充 NOP");
          ::AppendMenuW(m, MF_STRING, 5004, L"替换为 JMP");
          ::AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
          ::AppendMenuW(m, MF_STRING, 5005, L"运行到此");
          ::AppendMenuW(m, MF_STRING, 5006, L"跟随到该地址");
          ::AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
          // CE 内存视图右键同款：查找写入/访问此地址的内容 (F6/F5)
          ::AppendMenuW(m, MF_STRING, 5007, L"查找写入此地址的内容\tF6");
          ::AppendMenuW(m, MF_STRING, 5008, L"查找访问此地址的内容\tF5");
          ::AppendMenuW(m, MF_STRING, 5009, L"停止监控");
          // 《VM还原档案》：对当前指令自动找出被 HOOK 覆盖的原始字节
          ::AppendMenuW(m, MF_STRING, 5010, L"查找还原字节 (VM/HOOK)");
          POINT pt{(short)LOWORD(lp), (short)HIWORD(lp)};
          int cmd = ::TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_RETURNCMD,
                                     pt.x, pt.y, 0, hwnd, nullptr);
          ::DestroyMenu(m);
          std::string err;
          switch (cmd) {
            case 5001: {
              // 批量（地址集合）：有则全删，无则全设
              bool anyExists = false;
              for (ptruint a : targets) {
                for (const Breakpoint& bp : g.dbg.ListBp())
                  if (bp.address == a) { anyExists = true; break; }
                if (anyExists) break;
              }
              int done = 0;
              for (ptruint a : targets) {
                if (anyExists) g.dbg.RemoveBp(a);
                else { g.dbg.SetInt3(a, &err); if (err.empty()) ++done; }
              }
              StatusText(anyExists ? ToW("已删除 " + std::to_string(targets.size()) + " 个断点")
                                   : ToW("已设置 " + std::to_string(done) + " 个 INT3 断点"));
              break;
            }
            case 5002: {
              g.dbg.SetHardware(menuAddr, BpKind::HardwareExec, &err);
              StatusText(err.empty() ? L"已设硬件断点" : ToW("失败: " + err));
              break;
            }
            case 5003: {
              // NOP 填充（批量）：需要当前视口指令长度——按地址查视口行
              {
                int okCount = 0;
                for (ptruint a : targets) {
                  int len = 0;
                  for (size_t i = 0; i < g.disasmAddr.size(); ++i)
                    if (g.disasmAddr[i] == a) { len = g.disasmLines[i].length; break; }
                  if (len <= 0) {
                    // 不在视口内：现场反汇编求长度
                    unsigned char code[16];
                    SIZE_T got = g.proc.ReadPartial(a, code, sizeof(code));
                    if (got) { DisasmResult dr; Disassemble(code, got, a, &dr); len = dr.length; }
                  }
                  if (len <= 0 || len > 64) continue;
                  std::vector<ubyte> nops(len, 0x90);
                  size_t wr = 0;
                  if (g.proc.Write(a, nops.data(), (size_t)len, &wr) && wr == (size_t)len) ++okCount;
                }
                if (okCount > 0) {
                  StatusText(ToW("已填充 NOP x" + std::to_string(okCount)));
                  AddLogLine("[填充] NOP x" + std::to_string(okCount));
                } else StatusText(L"NOP 填充失败（内存只读?）");
              }
              break;
            }
            case 5004: {
              // 替换为 JMP rel32（批量，按地址现场反汇编）
              {
                int okCount = 0;
                for (ptruint a : targets) {
                  unsigned char code[16];
                  SIZE_T got = g.proc.ReadPartial(a, code, sizeof(code));
                  if (!got) continue;
                  DisasmResult dr;
                  Disassemble(code, got, a, &dr);
                  if (dr.jumpTarget == 0 || dr.length < 5) continue;
                  ubyte buf5[5];
                  buf5[0] = 0xE9;
                  std::int32_t rel = (std::int32_t)(dr.jumpTarget - (a + 5));
                  std::memcpy(buf5 + 1, &rel, 4);
                  size_t wr = 0;
                  if (g.proc.Write(a, buf5, 5, &wr) && wr == 5) ++okCount;
                }
                StatusText(okCount > 0 ? ToW("已替换 JMP x" + std::to_string(okCount))
                                       : L"没有可替换的指令（需跳转目标且长度≥5）");
              }
              break;
            }
            case 5005: {
              // 运行到此
              g.dbg.SetInt3(menuAddr, &err);
              if (err.empty()) { g.dbg.Run(); g.uiRunning = true; StatusText(L"运行到此..."); }
              break;
            }
            case 5006: {
              g.disasmBase = menuAddr;
              UpdateCpuWindow();
              break;
            }
            case 5007: StartWatch(true, menuAddr); break;
            case 5008: StartWatch(false, menuAddr); break;
            case 5009: WatchStopFind(L"已停止监控"); break;
            case 5010: StartRestoreAnalyze(menuAddr); break;
          }
          UpdateCpuWindow();
        }
        return 0;
      }
      break;
    }

    case WM_PAINT: {
      if (type == kChildLogData) {
        // 表头条：「地址 | 消息」（列位置与行绘制、拖动线完全一致）
        PAINTSTRUCT ps{};
        HDC dc = ::BeginPaint(hwnd, &ps);
        RECT rc{};
        ::GetClientRect(hwnd, &rc);
        RECT hdr = { 0, 0, rc.right, kLogDataHdrH };
        HBRUSH hb2 = ::CreateSolidBrush(kLogDataHdrBg);
        ::FillRect(dc, &hdr, hb2);
        ::DeleteObject(hb2);
        const wchar_t* ha = L"地址";
        const wchar_t* hm = L"消息";
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, kListText);
        ::TextOutW(dc, 8, 3, ha, 2);
        ::TextOutW(dc, g.ldAddrW + 8, 3, hm, 2);
        HPEN hgp = ::CreatePen(PS_SOLID, 1, kLogDataLine);
        HPEN hop = (HPEN)::SelectObject(dc, hgp);
        ::MoveToEx(dc, g.ldAddrW, 0, nullptr);
        ::LineTo(dc, g.ldAddrW, kLogDataHdrH);
        ::SelectObject(dc, hop);
        ::DeleteObject(hgp);
        ::EndPaint(hwnd, &ps);
        return 0;
      }
      break;
    }
    case WM_DRAWITEM: {
      DRAWITEMSTRUCT* dsb = (DRAWITEMSTRUCT*)lp;
      if (dsb->CtlType == 4 /*ODT_BUTTON*/) { DrawDarkButton(dsb); return TRUE; }
      // 日志数据行自绘：地址（左，灰白）| 绿线 | 消息（OD 绿）
      if (dsb->CtlID == IDC_LDLIST && dsb->itemID != (UINT)-1) {
        wchar_t lbuf[1200] = {};
        ::SendMessageW(dsb->hwndItem, LB_GETTEXT, (WPARAM)dsb->itemID, (LPARAM)lbuf);
        std::wstring ltxt(lbuf);
        const size_t lbar = ltxt.find(L'|');
        const std::wstring laddr = (lbar == std::wstring::npos) ? L"" : ltxt.substr(0, lbar);
        const std::wstring lmsg  = (lbar == std::wstring::npos) ? ltxt : ltxt.substr(lbar + 1);
        const bool lsel = (dsb->itemState & ODS_SELECTED) != 0;
        HBRUSH lb = ::CreateSolidBrush(lsel ? kUiStackSelBg : kListBg);
        ::FillRect(dsb->hDC, &dsb->rcItem, lb);
        ::DeleteObject(lb);
        ::SetBkMode(dsb->hDC, TRANSPARENT);
        ::SetTextColor(dsb->hDC, kLogDataAddrFg);
        if (!laddr.empty())
          ::TextOutW(dsb->hDC, dsb->rcItem.left + 6, dsb->rcItem.top + 1, laddr.c_str(), (int)laddr.size());
        HPEN lgp = ::CreatePen(PS_SOLID, 1, kLogDataLine);
        HPEN lop = (HPEN)::SelectObject(dsb->hDC, lgp);
        ::MoveToEx(dsb->hDC, g.ldAddrW, dsb->rcItem.top, nullptr);
        ::LineTo(dsb->hDC, g.ldAddrW, dsb->rcItem.bottom);
        ::SelectObject(dsb->hDC, lop);
        ::DeleteObject(lgp);
        ::SetTextColor(dsb->hDC, kLogDataMsgFg);
        if (!lmsg.empty())
          ::TextOutW(dsb->hDC, g.ldAddrW + 8, dsb->rcItem.top + 1, lmsg.c_str(), (int)lmsg.size());
        if (lsel) ::DrawFocusRect(dsb->hDC, &dsb->rcItem);
        return TRUE;
      }
      // 转储窗口自绘：地址|机器码（红线）|备注（绿线），列宽可拖动
      if (dsb->CtlID == IDC_DUMP && dsb->itemID != (UINT)-1) {
        const bool sel = (dsb->itemState & ODS_SELECTED) != 0;
        const COLORREF dbg = sel ? kUiStackSelBg : kListBg;
        HBRUSH db = ::CreateSolidBrush(dbg);
        ::FillRect(dsb->hDC, &dsb->rcItem, db);
        ::DeleteObject(db);
        wchar_t buf[512] = {};
        ::SendMessageW(dsb->hwndItem, LB_GETTEXT, (WPARAM)dsb->itemID, (LPARAM)buf);
        const std::wstring txt(buf);
        const int nn = (int)txt.size();
        // 行格式固定：地址(12) + 2空格 + 机器码字段(49 宽，含空格) + 1空格 + ASCII + 2空格 + 备注
        // （"（不可读）"行不足 64 字符，整行按备注画）
        int a1 = 12;                                  // 地址固定 12 个十六进制字符
        int hs = 14, he = hs + 49;                    // 机器码字段（含尾部填充空格）
        int rs = 64;                                  // ASCII+备注起点
        if (nn < rs) { hs = nn; he = nn; rs = nn; }   // 不可读行：无机器码/备注分段
        else { while (he > hs && txt[he - 1] == L' ') --he; }
        RECT rc = dsb->rcItem;
        int e1, e2;
        DumpCols(rc.right, e1, e2);
        HFONT of = (HFONT)::SelectObject(dsb->hDC, g.monoFont);
        ::SetBkColor(dsb->hDC, dbg);
        auto put = [&](int x, int limL, int limR, int from, int to, COLORREF fg) {
          if (to <= from || limR <= limL) return;
          RECT clip{limL, rc.top, limR, rc.bottom};
          ::SetTextColor(dsb->hDC, fg);
          ::ExtTextOutW(dsb->hDC, x, rc.top + 1, ETO_CLIPPED, &clip,
                        txt.c_str() + from, to - from, nullptr);
        };
        put(rc.left + 4, rc.left + 2, e1 - 2, 0, a1, kDisAddrFg);    // 地址（白）
        put(e1 + 6, e1 + 4, e2 - 2, hs, he, kListText);              // 机器码（整个字段）
        put(e2 + 6, e2 + 4, rc.right, rs, nn, kDisCommentFg);        // ASCII+备注
        // OD 式列分隔线：地址|机器码=红，机器码|备注=绿
        HPEN p1 = ::CreatePen(PS_SOLID, 1, kColAddrLine);
        HPEN o1 = (HPEN)::SelectObject(dsb->hDC, p1);
        ::MoveToEx(dsb->hDC, e1, rc.top, nullptr);
        ::LineTo(dsb->hDC, e1, rc.bottom);
        ::SelectObject(dsb->hDC, o1);
        ::DeleteObject(p1);
        HPEN p2 = ::CreatePen(PS_SOLID, 1, kColDataLine);
        HPEN o2 = (HPEN)::SelectObject(dsb->hDC, p2);
        ::MoveToEx(dsb->hDC, e2, rc.top, nullptr);
        ::LineTo(dsb->hDC, e2, rc.bottom);
        ::SelectObject(dsb->hDC, o2);
        ::DeleteObject(p2);
        ::SelectObject(dsb->hDC, of);
        return TRUE;
      }
      // 堆栈窗口自绘：地址|数值（红线）|注释（绿线），列宽可拖动；「返回到」红色高亮
      if (dsb->CtlID == IDC_STACK && dsb->itemID != (UINT)-1) {
        const bool sel = (dsb->itemState & ODS_SELECTED) != 0;
        const COLORREF sbg = sel ? kUiStackSelBg : kUiStackBg;
        HBRUSH sb = ::CreateSolidBrush(sbg);
        ::FillRect(dsb->hDC, &dsb->rcItem, sb);
        ::DeleteObject(sb);
        wchar_t buf[512] = {};
        ::SendMessageW(dsb->hwndItem, LB_GETTEXT, (WPARAM)dsb->itemID, (LPARAM)buf);
        const std::wstring txt(buf);
        const int nn = (int)txt.size();
        // 行格式：地址 空白 数值 空白 注释
        int a0 = 0; while (a0 < nn && txt[a0] == L' ') ++a0;
        int a1 = a0; while (a1 < nn && txt[a1] != L' ') ++a1;   // 地址
        int v0 = a1; while (v0 < nn && txt[v0] == L' ') ++v0;
        int v1 = v0; while (v1 < nn && txt[v1] != L' ') ++v1;   // 数值
        int c1 = v1; while (c1 < nn && txt[c1] == L' ') ++c1;   // 注释起点
        RECT rc = dsb->rcItem;
        int e1, e2;
        StkCols(rc.right, e1, e2);
        HFONT of = (HFONT)::SelectObject(dsb->hDC, g.monoFont);
        ::SetBkColor(dsb->hDC, sbg);
        auto put = [&](int x, int limL, int limR, int from, int to, COLORREF fg) {
          if (to <= from || limR <= limL) return;
          RECT clip{limL, rc.top, limR, rc.bottom};
          ::SetTextColor(dsb->hDC, fg);
          ::ExtTextOutW(dsb->hDC, x, rc.top + 1, ETO_CLIPPED, &clip,
                        txt.c_str() + from, to - from, nullptr);
        };
        put(rc.left + 4, rc.left + 2, e1 - 2, a0, a1, kUiStackFg);   // 地址
        put(e1 + 6, e1 + 4, e2 - 2, v0, v1, kUiStackFg);             // 数值
        if (c1 < nn) {
          const std::wstring note = txt.substr(c1);
          COLORREF nc = kUiStackFg;
          if (note.rfind(L"返回到", 0) == 0) {
            nc = kUiStackRetFg;                   // ★ 返回到 … 红色高亮
          } else if (note.rfind(L"SE 处理程序", 0) == 0 ||
                     note.rfind(L"指向下一个 SEH", 0) == 0) {
            nc = kUiStackSehFg;
          } else if (note.rfind(L"指向", 0) == 0 || note.rfind(L"栈指针", 0) == 0) {
            nc = kUiStackPtrFg;
          }
          put(e2 + 6, e2 + 4, rc.right, c1, nn, nc);               // 注释
        }
        // OD 式列分隔线：地址|数值=红，数值|注释=绿
        HPEN p1 = ::CreatePen(PS_SOLID, 1, kColAddrLine);
        HPEN o1 = (HPEN)::SelectObject(dsb->hDC, p1);
        ::MoveToEx(dsb->hDC, e1, rc.top, nullptr);
        ::LineTo(dsb->hDC, e1, rc.bottom);
        ::SelectObject(dsb->hDC, o1);
        ::DeleteObject(p1);
        HPEN p2 = ::CreatePen(PS_SOLID, 1, kColDataLine);
        HPEN o2 = (HPEN)::SelectObject(dsb->hDC, p2);
        ::MoveToEx(dsb->hDC, e2, rc.top, nullptr);
        ::LineTo(dsb->hDC, e2, rc.bottom);
        ::SelectObject(dsb->hDC, o2);
        ::DeleteObject(p2);
        ::SelectObject(dsb->hDC, of);
        return TRUE;
      }
      // 反汇编行自绘：暗色配色 + 断点标记 + 当前RIP高亮 + 流程线标记
      // （寄存器面板已改为独立自绘窗口类 RegPanelProc，不再走 DRAWITEM）
      DRAWITEMSTRUCT* ds = dsb;
      if (ds->CtlID != IDC_DISASM || ds->itemID == (UINT)-1) break;
      const int idx = (int)ds->itemID;
      const int lineH = ds->rcItem.bottom - ds->rcItem.top;

      // 不可读提示行（g.disasmAddr 此时是空的，必须在下面越界判断之前处理）
      if (g.disasmBad && idx == 0 && !g.disasmHint.empty()) {
        HBRUSH hb0 = ::CreateSolidBrush(kDisBg);
        ::FillRect(ds->hDC, &ds->rcItem, hb0);
        ::DeleteObject(hb0);
        ::SetBkColor(ds->hDC, kDisBg);
        ::SetTextColor(ds->hDC, kDisAddrFg);
        ::TextOutW(ds->hDC, ds->rcItem.left + 4, ds->rcItem.top + 2,
                   g.disasmHintAddr.c_str(), (int)g.disasmHintAddr.size());
        ::SetTextColor(ds->hDC, kDisJumpFg);   // 红字警告，和跳转行同色系
        ::TextOutW(ds->hDC, ds->rcItem.left + 108, ds->rcItem.top + 2,
                   g.disasmHint.c_str(), (int)g.disasmHint.size());
        return TRUE;
      }
      if (idx >= (int)g.disasmAddr.size()) return 0;
      const ptruint lineAddr = g.disasmAddr[idx];
      const DisasmResult* dr = idx < (int)g.disasmLines.size() ? &g.disasmLines[idx] : nullptr;

      // 背景（配色见 ThemeColors.h）
      // 跳转黄底 / retn 藏青底不再铺满整行，只框住助记符字符（像被框选）
      COLORREF bg = kDisBg;             // 整行默认纯黑底
      const bool multiSel = g.multiAddrs.count(g.disasmAddr[idx]) != 0;
      const bool anchorSel = (g.selAddr != 0 && g.disasmAddr[idx] == g.selAddr);
      // 提取助记符（第一个空格前的 token）
      std::wstring mn;
      if (dr) {
        const std::string& t = dr->text;
        size_t sp = t.find(' ');
        mn = ToW(t.substr(0, sp == std::string::npos ? t.size() : sp));
      }
      const bool isJumpMn = (mn == L"jmp" || mn == L"jz" || mn == L"jnz" ||
                             (dr && dr->isJump));
      const bool isRetMn = (mn == L"retn" || mn == L"ret");
      if (g.disasmAddr[idx] == g.currentRip) bg = kDisRipBg;       // 当前 RIP（最高优先）
      else if (anchorSel || multiSel) bg = kDisSelBg;              // 紫色选中
      // 助记符局部底色（0 = 无；仅跳转/retn 且整行未选中时生效）
      COLORREF mnBg = kDisBg;
      bool mnBoxed = false;
      if (bg == kDisBg) {
        if (isRetMn)      { mnBg = kDisRetBg;  mnBoxed = true; }   // 藏青框
        else if (isJumpMn){ mnBg = kDisJumpBg; mnBoxed = true; }   // 黄框
      }
      HBRUSH br = ::CreateSolidBrush(bg);
      ::FillRect(ds->hDC, &ds->rcItem, br);
      ::DeleteObject(br);

      int x = ds->rcItem.left + 4;
      auto draw = [&](const std::wstring& t, COLORREF c, int w) {
        ::SetBkColor(ds->hDC, bg);
        ::SetTextColor(ds->hDC, c);
        ::TextOutW(ds->hDC, x, ds->rcItem.top + 2, t.c_str(), (int)t.size());
        x += w;
      };

      // 断点标记（红点）
      bool hasBp = false;
      for (const Breakpoint& bp : g.dbg.ListBp())
        if (bp.address == lineAddr) { hasBp = true; break; }
      if (hasBp) {
        HBRUSH rb = ::CreateSolidBrush(kDisBpDot);
        HBRUSH ob = (HBRUSH)::SelectObject(ds->hDC, rb);
        ::Ellipse(ds->hDC, ds->rcItem.left + 2, ds->rcItem.top + lineH / 2 - 4,
                  ds->rcItem.left + 10, ds->rcItem.top + lineH / 2 + 4);
        ::SelectObject(ds->hDC, ob);
        ::DeleteObject(rb);
      }
      x = ds->rcItem.left + 16;

      // 地址列（淡紫）
      wchar_t ab[32];
      std::swprintf(ab, 32, L"%012llX", (unsigned long long)lineAddr);
      draw(ab, kDisAddrFg, 104);

      // 流程线列（OD 式跨行折线）
      // jmp/jcc：目标在视口内 → 画竖线到目标行+横向箭头；目标不在 → 单箭头符号
      // call  → 横向短线+箭头（跳去别处）
      if (dr && (dr->isJump || dr->isCall) && dr->jumpTarget) {
        // 找目标行
        int tgt = -1;
        for (int k = 0; k < (int)g.disasmAddr.size(); ++k)
          if (g.disasmAddr[k] == dr->jumpTarget) { tgt = k; break; }
        const int lineH = 18;
        const int barX = x + 8;                      // 流程线列中线
        COLORREF lineC = dr->isJump ? kDisFlowJmp : kDisFlowCall;  // jmp 蓝 / call 紫
        HPEN pen = ::CreatePen(PS_SOLID, 1, lineC);
        HPEN op = (HPEN)::SelectObject(ds->hDC, pen);
        if (dr->isJump && tgt >= 0) {
          const int y1 = ds->rcItem.top + lineH / 2;
          const int y2 = (tgt * lineH) + lineH / 2;  // 目标行中心（列表坐标≈绘制坐标）
          // 本行横向出发
          ::MoveToEx(ds->hDC, x, y1, nullptr);
          ::LineTo(ds->hDC, barX, y1);
          // 竖线连到目标行（向上或向下）
          ::MoveToEx(ds->hDC, barX, (y1 < y2 ? y1 : y2), nullptr);
          ::LineTo(ds->hDC, barX, (y1 > y2 ? y1 : y2));
          // 到目标行横向 + 箭头
          ::MoveToEx(ds->hDC, barX, y2, nullptr);
          ::LineTo(ds->hDC, x + 2, y2);
          // 箭头头
          ::MoveToEx(ds->hDC, x + 2, y2, nullptr);
          ::LineTo(ds->hDC, x + 6, y2 - 3);
          ::MoveToEx(ds->hDC, x + 2, y2, nullptr);
          ::LineTo(ds->hDC, x + 6, y2 + 3);
          x += 22;
        } else {
          // 目标不在视口或 call：短横线+箭头
          const int y1 = ds->rcItem.top + lineH / 2;
          ::MoveToEx(ds->hDC, x, y1, nullptr);
          ::LineTo(ds->hDC, x + 12, y1);
          ::MoveToEx(ds->hDC, x + 12, y1, nullptr);
          ::LineTo(ds->hDC, x + 8, y1 - 3);
          ::MoveToEx(ds->hDC, x + 12, y1, nullptr);
          ::LineTo(ds->hDC, x + 8, y1 + 3);
          x += 22;
        }
        ::SelectObject(ds->hDC, op);
        ::DeleteObject(pen);
      } else {
        draw(L" ", bg, 22);
      }

      // 字节列（灰）
      std::wstring bytes;
      {
        unsigned char raw[16] = {};
        SIZE_T rd = g.proc.ReadPartial(lineAddr, raw, sizeof(raw));
        for (int k = 0; k < ((dr ? dr->length : 1) < (int)rd ? (dr ? dr->length : 1) : (int)rd) && k < 8; ++k) {
          wchar_t t[8];
          std::swprintf(t, 8, L"%02X ", raw[k]);
          bytes += t;
        }
      }
      // 有效列分隔位置（与拖动命中同一套钳制）
      // 列布局：地址 16..ea(红，可拖动) ｜流程线｜ 机器码 ea..e1(绿) ｜ 指令 e1..e3(橙) ｜ 备注 e3..
      int ea, e1, e3;
      DisasmCols(ds->rcItem.right, ea, e1, e3);
      // 机器码列从红线 ea 起（=地址列+流程线区终点，拖红线可调地址栏宽度），保证对齐
      x = ea;
      ::SetBkColor(ds->hDC, bg);
      ::SetTextColor(ds->hDC, kDisBytesFg);
      ::TextOutW(ds->hDC, x + 4, ds->rcItem.top + 2, bytes.c_str(), (int)bytes.size());

      // 指令列（OD 式 token 分色：助记符红 / 寄存器青 / 立即数青绿 / API·符号黄）
      std::wstring text = dr ? ToW(dr->text) : L"";
      // 注释列（API 名 / 字符串，OllyDbg 式备注列）——列位置由可拖动分隔线决定
      // （与命中检测同一套钳制），长指令按列宽截断，避免压到备注列上
      // 指令列严格从 e1（线1）之后开始，与分隔线对齐
      const int instrX = e1 + 6;
      x = instrX;
      const bool hasCmt = idx < (int)g.disasmComments.size() && !g.disasmComments[idx].empty();
      int cmtX = e3 + 6;
      if (cmtX < instrX + 120 + 8) cmtX = instrX + 120 + 8;
      if (cmtX > ds->rcItem.right - 60) cmtX = -1;      // 空间不足则不显示注释
      if (hasCmt && cmtX > 0) {
        const int maxIns = (cmtX - 8 - instrX) / 7;
        if (maxIns > 0 && (int)text.size() > maxIns) text.resize((size_t)maxIns);
      }
      // —— token 着色绘制（按用户指定配色）——
      // 跳转指令：红字 + 黄底仅框住助记符；retn：黑字 + 藏青框仅框住助记符；
      // dword ptr ds 品红；寄存器(ecx/al)绿；db 00 灰；
      // mov/lea/dec/cmp/leave 黄字黑底；0x 立即数黄褐
      {
        // 助记符局部底色：像被框选一样，只包住字符长度（前后各留 2px）
        // 先统计助记符字符数
        int p = 0;
        const int n = (int)text.size();
        while (p < n && text[p] != L' ') ++p;
        if (mnBoxed && p > 0) {
          RECT mnRc{ x - 2, ds->rcItem.top, x + p * 7 + 2, ds->rcItem.bottom };
          HBRUSH mb = ::CreateSolidBrush(mnBg);
          ::FillRect(ds->hDC, &mnRc, mb);
          ::DeleteObject(mb);
        }
        // 助记符范围用局部底色，其余 token 用整行底色
        const COLORREF mnBk = mnBoxed ? mnBg : bg;
        ::SetBkColor(ds->hDC, mnBk);
        const bool onYellow = isJumpMn;   // 黄框内特殊配色
        const bool onNavy = isRetMn;      // 藏青框内黑字
        // 1) 助记符
        {
          COLORREF mc;
          if (onNavy)        mc = kDisRetFg;            // retn 黑字
          else if (onYellow) mc = kDisJumpFg;           // 跳转红字
          else if (mn == L"mov" || mn == L"lea" || mn == L"dec" ||
                   mn == L"cmp" || mn == L"leave" || mn == L"inc" ||
                   mn == L"add" || mn == L"sub" || mn == L"xor" ||
                   mn == L"and" || mn == L"or" || mn == L"nop" ||
                   mn == L"push" || mn == L"pop" || mn == L"test" ||
                   mn == L"xchg" || mn == L"cdq" || mn == L"cwde")
            mc = kDisDataMn;                            // 指定类指令黄字
          else
            mc = kDisPlainMn;                           // 其余白
          ::SetTextColor(ds->hDC, mc);
          ::TextOutW(ds->hDC, x, ds->rcItem.top + 2, text.c_str(), p);
        }
        // 2) 逐 token 扫描剩余部分
        const wchar_t* regs[] = {L"eax",L"ebx",L"ecx",L"edx",L"esi",L"edi",L"ebp",L"esp",
                                 L"rax",L"rbx",L"rcx",L"rdx",L"rsi",L"rdi",L"rbp",L"rsp",
                                 L"r8",L"r9",L"r10",L"r11",L"r12",L"r13",L"r14",L"r15",
                                 L"al",L"bl",L"cl",L"dl",L"ah",L"bh",L"ch",L"dh",
                                 L"ax",L"bx",L"cx",L"dx",L"sil",L"dil",L"bpl",L"spl"};
        auto isRegTok = [&](const std::wstring& t) {
          for (const wchar_t* r : regs) if (t == r) return true;
          return false;
        };
        // 段/大小描述符：dword ptr / word ptr / byte ptr / ds / es / ss / cs / fs / gs
        auto isSegTok = [&](const std::wstring& t) {
          return t == L"dword" || t == L"word" || t == L"byte" || t == L"qword" ||
                 t == L"ptr" || t == L"ds" || t == L"es" || t == L"ss" ||
                 t == L"cs" || t == L"fs" || t == L"gs";
        };
        auto isHexNum = [&](const std::wstring& t) {
          if (t.size() < 1) return false;
          size_t i = (t[0] == L'0' && t.size() > 1 && (t[1] == L'x' || t[1] == L'X')) ? 2 : 0;
          if (i >= t.size()) return false;
          for (; i < t.size(); ++i) {
            wchar_t c = t[i];
            if (!((c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F') ||
                  (c >= L'a' && c <= L'f')))
              return false;
          }
          return true;
        };
        auto tokColor = [&](const std::wstring& t) {
          if (onNavy) return kDisRetFg;                      // retn 行全黑字
          if (onYellow) {                                    // 黄底行：红主色 + 深色辅
            if (isHexNum(t)) return kDisJumpHexFg;
            return kDisJumpFg;
          }
          // db 00（无效字节/数据行）→ 灰
          if (mn == L"db") return kDisDbFg;
          // API/符号名（<>）→ 黄
          if (t.find(L'<') != std::wstring::npos || t.find(L'>') != std::wstring::npos)
            return kDisApiFg;
          // dword ptr / ds 等段描述符 → 品红
          if (isSegTok(t)) return kDisSegFg;
          // 寄存器 → 绿
          if (isRegTok(t)) return kDisRegFg;
          // 0x 十六进制 → 黄褐
          if (isHexNum(t)) return kDisHexFg;
          return kDisPunctFg;
        };
        const bool splitTok = kHighlightOperands;  // 关闭"高亮操作数"则整体一色
        int cx = x + p * 7;   // 等宽字体按字符宽推进
        ::SetBkColor(ds->hDC, bg);   // 助记符之后的 token 恢复整行底色
        while (splitTok && p < n) {
          int sp = p;
          while (p < n && text[p] == L' ') ++p;
          if (p > sp) cx += (p - sp) * 7;
          if (p >= n) break;
          int s = p;
          while (p < n && text[p] != L' ' && text[p] != L',' && text[p] != L'[' &&
                 text[p] != L']' && text[p] != L'+' && text[p] != L'*')
            ++p;
          std::wstring tok = text.substr(s, p - s);
          if (!tok.empty()) {
            COLORREF c = tokColor(tok);
            ::SetTextColor(ds->hDC, c);
            ::TextOutW(ds->hDC, cx, ds->rcItem.top + 2, tok.c_str(), (int)tok.size());
            cx += (int)tok.size() * 7;
          }
          while (splitTok && p < n && (text[p] == L',' || text[p] == L'[' || text[p] == L']' ||
                           text[p] == L'+' || text[p] == L'*')) {
            ::SetTextColor(ds->hDC, onNavy ? kDisRetFg : kDisPunctFg);
            ::TextOutW(ds->hDC, cx, ds->rcItem.top + 2, &text[p], 1);
            ++p; ++cx;
          }
        }
      }
      if (hasCmt && cmtX > 0) {
        const std::wstring& cmt = g.disasmComments[idx];
        int maxCh = (ds->rcItem.right - cmtX - 4) / 7;
        int n = (int)cmt.size();
        if (maxCh > 0 && n > maxCh) n = maxCh;
        if (n > 0) {
          ::SetBkColor(ds->hDC, bg);
          ::SetTextColor(ds->hDC, kDisCommentFg);
          ::TextOutW(ds->hDC, cmtX, ds->rcItem.top + 2, cmt.c_str(), n);
        }
      }

      // 列分隔竖线：红=地址栏右缘(可拖动) 绿=机器码右缘(可拖动) 橙=备注起点(可拖动)
      // （蓝色"指令列右缘"线已删——用户确认多余；配色见 ThemeColors.h 的 disColLine1/2/4）
      const int colXs[3] = { ea, e1, e3 };
      const COLORREF colCs[3] = { kDisColLine1, kDisColLine2, kDisColLine4 };
      for (int i = 0; i < 3; ++i) {
        const int cx = colXs[i];
        if (cx > ds->rcItem.left + 16 && cx < ds->rcItem.right - 8) {
          HPEN vpen = ::CreatePen(PS_SOLID, 1, colCs[i]);
          HPEN ov = (HPEN)::SelectObject(ds->hDC, vpen);
          ::MoveToEx(ds->hDC, cx, ds->rcItem.top, nullptr);
          ::LineTo(ds->hDC, cx, ds->rcItem.bottom);
          ::SelectObject(ds->hDC, ov);
          ::DeleteObject(vpen);
        }
      }
      return 0;
    }

    case WM_MEASUREITEM:
      if (((MEASUREITEMSTRUCT*)lp)->CtlID == IDC_DISASM) {
        ((MEASUREITEMSTRUCT*)lp)->itemHeight = 18;
        return 0;
      }
      if (((MEASUREITEMSTRUCT*)lp)->CtlID == IDC_DUMP) {
        // 与 UpdateCpuWindow 的 dumpRows 估算（每行 17px）保持一致
        ((MEASUREITEMSTRUCT*)lp)->itemHeight = 17;
        return 0;
      }
      if (((MEASUREITEMSTRUCT*)lp)->CtlID == IDC_STACK) {
        HDC dc = ::GetDC(nullptr);
        HFONT of = (HFONT)::SelectObject(dc, g.monoFont);
        TEXTMETRICW tm{};
        ::GetTextMetricsW(dc, &tm);
        ::SelectObject(dc, of);
        ::ReleaseDC(nullptr, dc);
        ((MEASUREITEMSTRUCT*)lp)->itemHeight = tm.tmHeight + 4;
        return 0;
      }
      break;

    case WM_NOTIFY: {
      NMHDR* nm = (NMHDR*)lp;
      // ---- ListView 全局暗色（搜索结果/内存地图/命中记录/中文搜索）----
      if (nm->code == NM_CUSTOMDRAW && !(g_wNoCd && nm->idFrom == IDC_W_LIST)) {
        NMLVCUSTOMDRAW* lvcd = (NMLVCUSTOMDRAW*)lp;
        if (lvcd->nmcd.dwDrawStage == CDDS_PREPAINT) {
          // 子项绘制前设背景/文字色
          lvcd->clrTextBk = kListBg;
          lvcd->clrText   = kListText;
          ::SetWindowLongPtrW(hwnd, DWLP_MSGRESULT, CDRF_NOTIFYITEMDRAW);
          return TRUE;
        }
        if (lvcd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
          lvcd->clrTextBk = kListBg;
          lvcd->clrText   = kListText;
          ::SetWindowLongPtrW(hwnd, DWLP_MSGRESULT, CDRF_DODEFAULT);
          return TRUE;
        }
        if (lvcd->nmcd.dwDrawStage == CDDS_SUBITEM | CDDS_ITEMPREPAINT) {
          lvcd->clrTextBk = kListBg;
          lvcd->clrText   = kListText;
          ::SetWindowLongPtrW(hwnd, DWLP_MSGRESULT, CDRF_DODEFAULT);
          return TRUE;
        }
      }
      if (type == kChildStrs && nm->idFrom == IDC_STR_LIST &&
          nm->code == LVN_GETDISPINFOW) {
        NMLVDISPINFOW* di = (NMLVDISPINFOW*)lp;
        size_t idx = (size_t)di->item.iItem;
        if (idx < g.strHits.size() && (di->item.mask & LVIF_TEXT)) {
          const ce::StrHit& h = g.strHits[idx];
          switch (di->item.iSubItem) {
            case 0: std::swprintf(di->item.pszText, (size_t)di->item.cchTextMax,
                    L"%012llX", (unsigned long long)h.address); break;
            case 1: std::swprintf(di->item.pszText, (size_t)di->item.cchTextMax,
                    L"%d", h.length); break;
            case 2: wcsncpy_s(di->item.pszText, (size_t)di->item.cchTextMax,
                    h.text.c_str(), _TRUNCATE); break;
          }
        }
        return 0;
      }
      if (type == kChildScan && nm->idFrom == IDC_RESULTS) {
        if (nm->code == LVN_GETDISPINFOW) {
          NMLVDISPINFOW* di = (NMLVDISPINFOW*)lp;
          if ((size_t)di->item.iItem < g.scan.ResultCount()) {
            const size_t idx = (size_t)di->item.iItem;
            wchar_t buf[256];
            if (di->item.iSubItem == 0) {
              std::swprintf(buf, 256, L"%012llX",
                            (unsigned long long)g.scan.AddressAt(idx));
            } else {
              std::vector<ubyte> v = (di->item.iSubItem == 1) ? g.scan.ValueAt(idx)
                                                              : g.scan.ReadCurrent(idx);
              VariableType vt = g.scan.CurrentType();
              bool hex = ::SendMessageW(Ctrl(hwnd, IDC_HEX), BM_GETCHECK, 0, 0) ==
                         BST_CHECKED;
              std::swprintf(buf, 256, L"%s",
                            ToW(FormatValueBytes(vt, hex, v.data(), (int)v.size())).c_str());
            }
            di->item.pszText = buf;
          }
        } else if (nm->code == NM_DBLCLK) {
          NMITEMACTIVATE* ia = (NMITEMACTIVATE*)lp;
          if (ia->iItem >= 0 && (size_t)ia->iItem < g.scan.ResultCount()) {
            wchar_t buf[64];
            std::swprintf(buf, 64, L"%012llX",
                          (unsigned long long)g.scan.AddressAt((size_t)ia->iItem));
            ::SetWindowTextW(Ctrl(hwnd, IDC_WV), buf);
            if (g.bps && IsWindow(g.bps))
              ::SetWindowTextW(Ctrl(g.bps, IDC_BADDR), buf);
          }
        }
      }
      break;
    }

    case WM_COMMAND: {
      const int id = LOWORD(wp);
      switch (type) {
        case kChildCpu:
          switch (id) {
            case IDC_DISASM:
              if (HIWORD(wp) == LBN_SELCHANGE) {
                UpdateCmdInfoLine();
                g.disasmSel = (int)::SendMessageW(Ctrl(hwnd, IDC_DISASM), LB_GETCURSEL, 0, 0);
                ::InvalidateRect(Ctrl(hwnd, IDC_DISASM), nullptr, TRUE);
              }
              break;
            case IDC_BTN_RUN: g.dbg.Run(); g.uiRunning = true; StatusText(L"运行中"); break;
            case IDC_BTN_PAUSE:
              g.dbg.Pause(); g.uiRunning = false; StatusText(L"已暂停");
              UpdateCpuWindow();
              break;
            case IDC_BTN_STEPIN:
              g.followRip = true;
              g.dbg.StepInto(); g.uiRunning = false;
              ::Sleep(120);  // 等待单步事件
              UpdateCpuWindow();
              break;
            case IDC_BTN_STEPOVER:
              g.followRip = true;
              g.dbg.StepOver(); g.uiRunning = false;
              ::Sleep(120);
              UpdateCpuWindow();
              break;
            case IDC_BTN_RUNRET:
              g.dbg.ExecuteUntilReturn(); g.uiRunning = false;
              ::Sleep(150);
              UpdateCpuWindow();
              break;
            case IDC_BTN_BP: ToggleBpOnSelectedLine(); break;
            // 顶部跳转框已删：地址跳转走反汇编右键菜单（ShowGotoDlg）
          }
          break;

        case kChildScan:
          switch (id) {
            case IDC_FIRST: StartScan(false, hwnd); break;
            case IDC_NEXT: StartScan(true, hwnd); break;
            case IDC_NEW:
              g.scan.Reset();
              RefreshResultList(hwnd);
              break;
            case IDC_WRITEV: {
              HWND list = Ctrl(hwnd, IDC_RESULTS);
              int sel = (int)::SendMessageW(list, LVM_GETNEXTITEM, (WPARAM)-1,
                                            MAKELPARAM(LVNI_SELECTED, 0));
              if (sel < 0 || !g.proc.IsOpen()) break;
              std::string text = Trim(GetText(Ctrl(hwnd, IDC_WV)));
              if (text.empty()) break;
              ptruint addr = g.scan.AddressAt((size_t)sel);
              VariableType vt = g.scan.CurrentType();
              bool hex = ::SendMessageW(Ctrl(hwnd, IDC_HEX), BM_GETCHECK, 0, 0) ==
                         BST_CHECKED;
              std::vector<ubyte> data;
              int base = hex ? 16 : 10;
              switch (vt) {
                case VariableType::vtByte:
                  data.push_back((ubyte)std::strtoul(text.c_str(), nullptr, base));
                  break;
                case VariableType::vtWord: {
                  unsigned short v = (unsigned short)std::strtoul(text.c_str(), nullptr,
                                                                  base);
                  data.resize(2);
                  std::memcpy(data.data(), &v, 2);
                  break;
                }
                case VariableType::vtDword: {
                  unsigned v = (unsigned)std::strtoul(text.c_str(), nullptr, base);
                  data.resize(4);
                  std::memcpy(data.data(), &v, 4);
                  break;
                }
                case VariableType::vtQword: {
                  unsigned long long v = std::strtoull(text.c_str(), nullptr, base);
                  data.resize(8);
                  std::memcpy(data.data(), &v, 8);
                  break;
                }
                case VariableType::vtSingle: {
                  float v = (float)std::atof(text.c_str());
                  data.resize(4);
                  std::memcpy(data.data(), &v, 4);
                  break;
                }
                case VariableType::vtDouble: {
                  double v = std::atof(text.c_str());
                  data.resize(8);
                  std::memcpy(data.data(), &v, 8);
                  break;
                }
                case VariableType::vtString:
                  for (char c : text) data.push_back((ubyte)c);
                  data.push_back(0);
                  break;
                case VariableType::vtByteArray: {
                  AobPattern p = ParseAobPattern(text, true);
                  if (p.valid)
                    for (std::int32_t b : p.bytes) data.push_back((ubyte)(b & 0xFF));
                  break;
                }
                default: break;
              }
              std::string err;
              if (!data.empty() && g.scan.WriteRaw(addr, data, &err)) {
                StatusText(L"写入成功");
              } else {
                StatusText(ToW("写入失败: " + err));
              }
              break;
            }
          }
          break;

        case kChildBps:
          switch (id) {
            case IDC_BTN_INT3: {
              std::string t = Trim(GetText(Ctrl(hwnd, IDC_BADDR)));
              if (!t.empty()) {
                std::string err;
                g.dbg.SetInt3(std::strtoull(t.c_str(), nullptr, 16), &err);
                RefreshBpList();
              }
              break;
            }
            case IDC_BTN_HW: {
              std::string t = Trim(GetText(Ctrl(hwnd, IDC_BADDR)));
              int k = (int)::SendMessageW(Ctrl(hwnd, IDC_BKIND), CB_GETCURSEL, 0, 0);
              BpKind kind = k == 0   ? BpKind::HardwareExec
                            : k == 1 ? BpKind::HardwareRW
                                     : BpKind::HardwareWrite;
              if (!t.empty()) {
                std::string err;
                g.dbg.SetHardware(std::strtoull(t.c_str(), nullptr, 16), kind, &err);
                RefreshBpList();
              }
              break;
            }
            case IDC_BTN_PG: {
              std::string t = Trim(GetText(Ctrl(hwnd, IDC_BADDR)));
              int k = (int)::SendMessageW(Ctrl(hwnd, IDC_BKIND), CB_GETCURSEL, 0, 0);
              BpKind kind = k == 2 ? BpKind::Write : BpKind::Access;
              if (!t.empty()) {
                std::string err;
                g.dbg.SetPageGuard(std::strtoull(t.c_str(), nullptr, 16), kind, 8, &err);
                RefreshBpList();
              }
              break;
            }
            case IDC_BTN_DELBP: {
              std::string t = Trim(GetText(Ctrl(hwnd, IDC_BADDR)));
              if (!t.empty()) g.dbg.RemoveBp(std::strtoull(t.c_str(), nullptr, 16));
              RefreshBpList();
              break;
            }
            case IDC_BTN_FINDACC: {
              std::string t = Trim(GetText(Ctrl(hwnd, IDC_BADDR)));
              if (!t.empty())
                StartWatch(false, std::strtoull(t.c_str(), nullptr, 16));
              break;
            }
            case IDC_BTN_FINDWR: {
              std::string t = Trim(GetText(Ctrl(hwnd, IDC_BADDR)));
              if (!t.empty())
                StartWatch(true, std::strtoull(t.c_str(), nullptr, 16));
              break;
            }
            case IDC_BTN_STOPFIND: WatchStopFind(L"已停止监控"); break;
          }
          break;

        case kChildThreads:
          if (id == IDC_THRREFRESH) RefreshThreadList();
          break;
        case kChildMcp:
          if (id == IDC_MCP_CONNECT) McpConnect();
          else if (id == IDC_MCP_DISCONNECT) McpDisconnect();
          else if (id == IDC_MCP_SEND) {
            char buf[4096] = {};
            ::GetWindowTextA(Ctrl(hwnd, IDC_MCP_CMD), buf, sizeof(buf));
            std::string cmd = Trim(std::string(buf));
            if (!cmd.empty()) {
              // 约定：输入 "方法 参数JSON" 或纯 "方法"；也支持直接输入 JSON-RPC
              std::string method = cmd, params = "{}";
              size_t sp = cmd.find(' ');
              if (sp != std::string::npos) {
                method = cmd.substr(0, sp);
                std::string rest = Trim(cmd.substr(sp + 1));
                if (!rest.empty() && (rest[0] == '{' || rest[0] == '[')) params = rest;
                else params = "{\"value\":\"" + rest + "\"}";
              }
              McpSendCmd(method, params);
              ::SetWindowTextA(Ctrl(hwnd, IDC_MCP_CMD), "");
            }
          }
          else if (id == IDC_MCP_QUICK) {
            if (HIWORD(wp) == CBN_SELCHANGE) {
              int sel = (int)::SendMessageW(Ctrl(hwnd, IDC_MCP_QUICK), CB_GETCURSEL, 0, 0);
              if (sel > 0) {
                McpRunQuick(sel - 1);
                ::SendMessageW(Ctrl(hwnd, IDC_MCP_QUICK), CB_SETCURSEL, 0, 0);
              }
            }
          }
          break;
        case kChildMap:
          if (id == IDC_MAPREFRESH) RefreshMapList();
          break;
        case kChildStrs:
          if (id == IDC_STR_SEARCH && HIWORD(wp) == BN_CLICKED) {
            int sel = (int)::SendMessageW(Ctrl(hwnd, IDC_STR_MODE), CB_GETCURSEL, 0, 0);
            StrSearchRun(sel < 0 ? 2 : sel);
          }
          break;
      }
      break;
    }

    case WM_DESTROY: {
      switch (type) {
        case kChildCpu: g.cpu = nullptr; break;
        case kChildScan: g.scanWnd = nullptr; break;
        case kChildMap: g.map = nullptr; break;
        case kChildThreads: g.thr = nullptr; break;
        case kChildBps: g.bps = nullptr; break;
        case kChildLog: g.log = nullptr; break;
    case kChildLogData: g.logData = nullptr; break;
        case kChildMcp: g.mcp = nullptr; break;
        case kChildStrs: g.strs = nullptr; break;
      }
      break;
    }

    // ---- 全局暗色主题：MDI 内所有子控件黑底 + 适配文字色 ----
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
      HDC dc = (HDC)wp;
      ::SetBkColor(dc, kListBg);
      ::SetTextColor(dc, kListText);
      /* darkBr removed */
      return (LRESULT)GetCachedBrush(kListBg);
    }
    case WM_CTLCOLORSTATIC: {
      HDC dc = (HDC)wp;
      // 底部命令栏：系统默认灰底（与 Win32 经典状态栏一致的外观）
      // ESP/EBP 保留红字强调，其余黑字
      const HWND ctl = (HWND)lp;
      if (ctl == ::GetDlgItem(hwnd, IDC_CMD_ESP) || ctl == ::GetDlgItem(hwnd, IDC_CMD_EBP)) {
        ::SetBkColor(dc, ::GetSysColor(COLOR_BTNFACE));
        ::SetTextColor(dc, RGB(200, 0, 0));
        return (LRESULT)GetCachedBrush(::GetSysColor(COLOR_BTNFACE));
      }
      if (ctl == ::GetDlgItem(hwnd, IDC_CMDLABEL)) {
        ::SetBkColor(dc, ::GetSysColor(COLOR_BTNFACE));
        ::SetTextColor(dc, ::GetSysColor(COLOR_WINDOWTEXT));
        return (LRESULT)GetCachedBrush(::GetSysColor(COLOR_BTNFACE));
      }
      ::SetBkColor(dc, kEditBg);
      ::SetTextColor(dc, kEditTextSub);
      /* stBr removed */
      return (LRESULT)GetCachedBrush(kEditBg);
    }
    case WM_CTLCOLORBTN: {
      /* btnBr removed */
      return (LRESULT)GetCachedBrush(kBtnFace);
    }
  }
  return ::DefMDIChildProcW(hwnd, msg, wp, lp);
}

//=============================================================================
// 菜单
//=============================================================================
//=============================================================================
// 设置API断点（仿吾爱破解版 OD 工具）——按类别批量对 API 名下 INT3 断点
//=============================================================================
struct ApbCategory {
  const wchar_t* label;
  const wchar_t* keys[24];   // 导出函数名关键字（前缀匹配，不区分大小写）
  int keyCount;
};

static const ApbCategory kApbCategories[] = {
  {L"字符串", {L"MessageBox", L"lstrcpy", L"lstrcat", L"lstrlen", L"wsprintf",
               L"MultiByteToWideChar", L"WideCharToMultiByte", L"CharUpper", L"CharLower",
               L"GetWindowText"}, 10},
  {L"消息框", {L"MessageBox"}, 1},
  {L"对话框", {L"DialogBox", L"CreateDialog", L"GetOpenFileName", L"GetSaveFileName",
               L"MessageBoxIndirect"}, 5},
  {L"文件", {L"CreateFile", L"ReadFile", L"WriteFile", L"DeleteFile", L"CopyFile",
             L"MoveFile", L"FindFirstFile", L"FindNextFile", L"SetFilePointer",
             L"CloseHandle", L"OpenFile"}, 11},
  {L"库函数", {L"LoadLibrary", L"GetProcAddress", L"FreeLibrary", L"GetModuleHandle",
               L"GetModuleFileName"}, 5},
  {L"内存管理", {L"VirtualAlloc", L"VirtualFree", L"VirtualProtect", L"HeapAlloc",
                 L"HeapFree", L"GlobalAlloc", L"GlobalFree", L"LocalAlloc", L"LocalFree",
                 L"CreateFileMapping", L"MapViewOfFile"}, 11},
  {L"注册表", {L"RegOpenKey", L"RegQueryValue", L"RegSetValue", L"RegCreateKey",
               L"RegDeleteKey", L"RegCloseKey", L"RegEnumKey"}, 7},
  {L"目录及路径", {L"CreateDirectory", L"RemoveDirectory", L"GetCurrentDirectory",
                   L"SetCurrentDirectory", L"GetTempPath", L"GetWindowsDirectory",
                   L"GetSystemDirectory"}, 7},
  {L"驱动器", {L"GetDriveType", L"GetLogicalDrives", L"GetVolumeInformation",
               L"QueryDosDevice"}, 4},
  {L"时间", {L"GetTickCount", L"GetLocalTime", L"GetSystemTime", L"QueryPerformanceCounter",
             L"timeGetTime", L"GetTickCount64"}, 6},
  {L"其它杂类(nags...)", {L"GetCommandLine", L"GetStartupInfo", L"GetCurrentProcess",
                          L"GetCurrentThread", L"Sleep", L"GetVersion", L"IsDebuggerPresent",
                          L"CheckRemoteDebuggerPresent", L"OutputDebugString"}, 9},
  {L"VB APIs", {L"rtcMsgBox", L"rtcShell", L"__vbaStrCmp", L"__vbaStrCopy", L"__vbaFreeStr",
                L"__vbaObjSet", L"rtcGetDateValue"}, 7},
  {L"Custom APIs", {nullptr}, 0},   // 占位：弹出输入框手动输 API 名
};
static const int kApbCategoryCount = sizeof(kApbCategories) / sizeof(kApbCategories[0]);

// 在目标进程所有模块导出表中按关键字前缀匹配 API，批量下 INT3 断点
static int ApbApplyByKeys(const ApbCategory& cat, std::string* errOut) {
  int total = 0;
  const auto& mods = g.proc.CachedModules();
  for (const ModuleEntry& m : mods) {
    auto em = BuildExportMap(m);
    for (auto& kv : em) {
      const std::wstring& fname = kv.second;
      // 模块名.函数名 形式键入断点（避免同名冲突）
      for (int k = 0; k < cat.keyCount; ++k) {
        // 不区分大小写前缀匹配
        std::wstring key = cat.keys[k];
        if (fname.size() >= key.size() &&
            _wcsnicmp(fname.c_str(), key.c_str(), key.size()) == 0) {
          std::string err;
          g.dbg.SetInt3(kv.first, &err);
          if (err.empty()) ++total;
          break;
        }
      }
    }
  }
  (void)errOut;
  return total;
}

// 手动输入 API 名设置断点
static void ApbCustomInput() {
  if (!g.dbg.IsAttached()) {
    ::MessageBoxW(g.frame, L"请先附加进程", L"设置API断点", MB_OK | MB_ICONINFORMATION);
    return;
  }
  // 简单输入对话框（复用编辑框风格）
  static const wchar_t* kCls = L"CEScanApbInput";
  static bool reg = false;
  if (!reg) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = g.inst;
    wc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = kCls;
    ::RegisterClassW(&wc);
    reg = true;
  }
  wchar_t buf[256] = L"";
  // 用简单的 MessageBox 输入替代（用 GetUserNameA 风格不适用）——改为小窗口+Edit
  HWND dlg = ::CreateWindowExW(WS_EX_DLGMODALFRAME, kCls, L"输入 API 名称（如 MessageBoxA）",
                               WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                               400, 300, 420, 130, g.frame, nullptr, g.inst, nullptr);
  HWND edit = ::CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                10, 20, 390, 24, dlg, (HMENU)1, g.inst, nullptr);
  HWND ok = ::CreateWindowExW(0, L"BUTTON", L"确定", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                              220, 55, 80, 26, dlg, (HMENU)IDOK, g.inst, nullptr);
  HWND cancel = ::CreateWindowExW(0, L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                  310, 55, 80, 26, dlg, (HMENU)IDCANCEL, g.inst, nullptr);
  ::SendMessageW(edit, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
  ::SendMessageW(ok, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
  ::SendMessageW(cancel, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
  ::ShowWindow(dlg, SW_SHOW);
  ::SetFocus(edit);

  MSG msg;
  bool done = false, okClicked = false;
  while (!done && ::GetMessageW(&msg, nullptr, 0, 0)) {
    if (msg.message == WM_QUIT) { ::PostQuitMessage((int)msg.wParam); break; }
    if (msg.message == WM_COMMAND) {
      if (LOWORD(msg.wParam) == IDOK) { okClicked = true; done = true; }
      if (LOWORD(msg.wParam) == IDCANCEL) done = true;
    }
    if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) done = true;
    if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN &&
        (msg.hwnd == edit || ::GetParent(msg.hwnd) == dlg)) { okClicked = true; done = true; }
    if (!::IsWindow(dlg)) break;
    ::TranslateMessage(&msg);
    ::DispatchMessageW(&msg);
  }
  if (!okClicked || !::IsWindow(edit)) { if (::IsWindow(dlg)) ::DestroyWindow(dlg); return; }
  ::GetWindowTextW(edit, buf, 256);
  if (::IsWindow(dlg)) ::DestroyWindow(dlg);

  std::wstring key = buf;
  if (key.empty()) return;
  // 扫描所有模块导出表找匹配
  int total = 0;
  const auto& mods = g.proc.CachedModules();
  for (const ModuleEntry& m : mods) {
    auto em = BuildExportMap(m);
    for (auto& kv : em) {
      if (_wcsnicmp(kv.second.c_str(), key.c_str(), key.size()) == 0) {
        std::string err;
        g.dbg.SetInt3(kv.first, &err);
        if (err.empty()) ++total;
      }
    }
  }
  wchar_t msg2[128];
  std::swprintf(msg2, 128, L"已对 %d 个匹配『%s』的 API 设置 INT3 断点", total, key.c_str());
  ::MessageBoxW(g.frame, msg2, L"设置API断点", MB_OK | MB_ICONINFORMATION);
  AddLogLine("[API断点] 自定义: " + ToA(key) + " x" + std::to_string(total));
}

static void ApbApply(int catIdx) {
  if (!g.dbg.IsAttached()) {
    ::MessageBoxW(g.frame, L"请先附加进程", L"设置API断点", MB_OK | MB_ICONINFORMATION);
    return;
  }
  if (catIdx < 0 || catIdx >= kApbCategoryCount) return;
  const ApbCategory& cat = kApbCategories[catIdx];
  if (wcscmp(cat.label, L"Custom APIs") == 0) { ApbCustomInput(); return; }
  int n = ApbApplyByKeys(cat, nullptr);
  wchar_t msg[160];
  std::swprintf(msg, 160, L"已对 %d 个『%s』类 API 设置 INT3 断点", n, cat.label);
  ::MessageBoxW(g.frame, msg, L"设置API断点", MB_OK | MB_ICONINFORMATION);
  AddLogLine("[API断点] " + ToA(cat.label) + " x" + std::to_string(n));
}

static void ApbClearAll() {
  // 只删本工具 API 断点功能设置的：无法精确区分，提供全部清除断点（INT3类）
  int removed = 0;
  auto bps = g.dbg.ListBp();
  for (const Breakpoint& bp : bps) {
    if (bp.kind == BpKind::Int3) { g.dbg.RemoveBp(bp.address); ++removed; }
  }
  wchar_t msg[128];
  std::swprintf(msg, 128, L"已清除 %d 个 INT3 断点", removed);
  ::MessageBoxW(g.frame, msg, L"设置API断点", MB_OK | MB_ICONINFORMATION);
}

// 「DBVM 检测」：CPU 厂商 / VMX-SVM 支持 / DBVM 是否在场（vmcall GETVERSION）
// 与 CE 的「DBVM 是否激活」菜单对应。不在场时不崩溃（vmcall #UD 被 SEH 捕获）。
static void DbvmDetectDialog() {
  int regs[4] = {0, 0, 0, 0};
  __cpuidex(regs, 0, 0);
  char vendor[13];
  std::memcpy(vendor, &regs[1], 4);
  std::memcpy(vendor + 4, &regs[3], 4);
  std::memcpy(vendor + 8, &regs[2], 4);
  vendor[12] = '\0';

  ce::Dbvm& dbvm = ce::Dbvm::Instance();
  const bool vmcall = ce::Dbvm::CpuSupportsVmcall();
  const bool detected = dbvm.Detect();

  wchar_t msg[1024];
  std::swprintf(msg, 1024,
                L"CPU 厂商           : %S\n"
                L"vmcall 支持(VMX/SVM) : %s\n"
                L"DBVM 在场          : %s\n"
                L"DBVM 版本          : 0x%08X\n"
                L"----------------------------------------\n"
                L"%ls",
                vendor,
                vmcall ? L"是" : L"否",
                detected ? L"是" : L"否",
                dbvm.Version(),
                ToW(dbvm.LastError()).c_str());
  ::MessageBoxW(g.frame, msg, L"DBVM 检测", MB_OK | MB_ICONINFORMATION);
}

// 程序所在目录（带结尾反斜杠），用于定位 dbk64.sys / vmdisk.img
static std::wstring GuiExeDir() {
  wchar_t path[MAX_PATH];
  ::GetModuleFileNameW(nullptr, path, MAX_PATH);
  std::wstring dir = path;
  size_t pos = dir.find_last_of(L'\\');
  if (pos != std::wstring::npos) dir = dir.substr(0, pos + 1);
  return dir;
}

// 「加载并启动 DBVM」：SCM 加载 dbk64.sys → 注册表配置 → StartService →
// 打开设备 → IOCTL_CE_LAUNCHDBVM 启动 hypervisor → 改默认密码 → 复检。
// 对应 CE 的 loaddbvmifneeded + internal_LaunchDBVM + configure_vmx。
// 需要 dbk64.sys 与 vmdisk.img（从 Cheat Engine 安装目录复制到本程序目录），
// 且进程需以管理员身份运行、驱动签名有效（或处于测试签名模式）。
// 跨菜单点击共享的 DBVM 加载器单例：loaded_/launched_ 标志持久，
// 重复点「加载并启动 DBVM」不会二次拉起驱动或二次触发 LAUNCHDBVM。
static ce::DbvmLoader& SharedDbvmLoader() {
  static ce::DbvmLoader loader;
  return loader;
}

static void LoadDbvmDialog() {
  ce::DbvmLoader& loader = SharedDbvmLoader();
  loader.cfg().driverPath = GuiExeDir() + L"dbk64.sys";
  loader.cfg().vmdiskPath = GuiExeDir() + L"vmdisk.img";

  // 防重复：服务已由本进程加载过（loaded_ 持久）→ 直接 done
  if (loader.IsDriverLoaded()) {
    ::MessageBoxW(g.frame, L"dbk64.sys 已加载，无需重复加载。",
                  L"加载 DBVM 驱动", MB_OK | MB_ICONINFORMATION);
    return;
  }

  std::string err;
  if (!loader.LoadDriver(&err)) {
    ::MessageBoxW(g.frame, ToW(err).c_str(), L"加载 DBVM 驱动",
                  MB_OK | MB_ICONERROR);
    return;
  }
  // 防重复：DBVM hypervisor 已在场 → 跳过 LAUNCHDBVM（避免二次拉起导致崩溃）
  ce::Dbvm& dbvm = ce::Dbvm::Instance();
  const bool alreadyUp = dbvm.Detect();
  if (!alreadyUp) {
    if (!loader.Launch(&err)) {
      ::MessageBoxW(g.frame, ToW(err).c_str(), L"启动 DBVM",
                    MB_OK | MB_ICONERROR);
      return;
    }
  }

  // 启动成功后把密码换回默认值（对应 CE 的 configure_vmx），再复检是否在场
  ce::DbvmPassword np;
  dbvm.ChangePassword(np);

  const bool detected = dbvm.Detect();
  wchar_t msg[512];
  std::swprintf(msg, 512,
                L"DBVM %s（IOCTL_CE_LAUNCHDBVM %s）。\n"
                L"复检：DBVM 在场 = %s，版本 0x%08X",
                alreadyUp ? L"已在运行，跳过重复启动" : L"已启动",
                alreadyUp ? L"跳过" : L"成功",
                detected ? L"是" : L"否", dbvm.Version());
  ::MessageBoxW(g.frame, msg, L"DBVM 启动", MB_OK | MB_ICONINFORMATION);
}

// 「卸载 DBVM 驱动」：停服务 + 删服务（DeleteService 一并删注册表键）。
// DBVM 本体仍在运行（hypervisor 一旦载入只能重启系统卸载），CE 同款行为。
static void UnloadDbvmDialog() {
  ce::DbvmLoader& loader = SharedDbvmLoader();
  std::string err;
  if (!loader.Unload(&err)) {
    ::MessageBoxW(g.frame, ToW(err).c_str(), L"卸载 DBVM 驱动",
                  MB_OK | MB_ICONERROR);
    return;
  }
  ::MessageBoxW(g.frame, L"dbk 驱动服务已停止并删除。\n"
                        L"（注意：DBVM hypervisor 一旦启动只能重启系统卸载，与 CE 行为一致。）",
                L"卸载 DBVM 驱动", MB_OK | MB_ICONINFORMATION);
}

// ============================================================================
//  DBVM 断点 + 保护 界面入口（插件(P) 菜单）
// ============================================================================

// DBVM 断点命中回调：目标线程被 DBVM 冻结在断点上，通知界面。
static void DbvmOnHit(const ce::DbvmBpHit& hit) {
  char va[32], rip[32];
  std::snprintf(va, sizeof(va), "%012llX", (unsigned long long)hit.va);
  std::snprintf(rip, sizeof(rip), "%012llX", (unsigned long long)hit.rip);
  AddLogLine("[DBVM断点] 命中 @" + std::string(va) + "  RIP=" + rip +
             "  watchId=" + std::to_string(hit.watchId) +
             "  线程已冻结（目标端不可感知）");
  StatusText(ToW("[DBVM断点] 命中 @" + std::string(va) + "  RIP=" + rip));
}

// DBVM 断点：对目标进程当前反汇编选中行下断（WatchExecutes + kEptoDbvmBp）。
// 命中后目标线程被 DBVM 冻结（不写字节 / 不占 DR / 不改页属性，目标不可感知）。
static void DbvmBreak() {
  ce::Dbvm& dbvm = ce::Dbvm::Instance();
  if (!dbvm.Available()) {
    ::MessageBoxW(g.frame, L"需要 DBVM 才能下 DBVM 断点。\n"
                          L"请先在 插件(P) 里「加载并启动 DBVM」。",
                  L"DBVM 断点", MB_OK | MB_ICONINFORMATION);
    return;
  }
  if (!g.dbg.IsAttached()) {
    ::MessageBoxW(g.frame, L"请先附加目标进程。", L"DBVM 断点", MB_OK | MB_ICONINFORMATION);
    return;
  }
  if (!g.selAddr) {  // CPU 窗口当前选中行
    StatusText(L"请先在 CPU 窗口的反汇编里选中一行，再下 DBVM 断点");
    return;
  }
  std::string err;
  const int id = ce::DbvmTools::Instance().SetBreakpoint(g.dbg.Pid(), g.selAddr, &err);
  if (id > 0) {
    char b[48]; std::snprintf(b, sizeof(b), "%012llX", (unsigned long long)g.selAddr);
    AddLogLine("[DBVM断点] 已设置 @" + std::string(b) + "（watchId=" +
               std::to_string(id) + "），命中即冻结线程");
    StatusText(L"已设 DBVM 断点（目标不可感知）");
  } else {
    StatusText(ToW("DBVM 断点设置失败: " + err));
  }
}

// 续跑全部 DBVM 冻结的线程（继续运行；带断点，下次命中再冻）
static void DbvmResumeAll() {
  if (!ce::Dbvm::Instance().Available()) {
    StatusText(L"DBVM 不在场");
    return;
  }
  const int resumed = ce::DbvmTools::Instance().ResumeAllFrozen(true);
  AddLogLine("[DBVM] 已续跑 " + std::to_string(resumed) + " 个冻结线程");
  StatusText(ToW("DBVM 续跑 " + std::to_string(resumed) + " 个线程"));
}

// 删除所有 DBVM 断点
static void DbvmClearBp() {
  const size_t n = ce::DbvmTools::Instance().BreakpointCount();
  ce::DbvmTools::Instance().ClearAllBreakpoints();
  ce::DbvmTools::Instance().ResumeAllFrozen(true);  // 顺手放行被冻线程
  AddLogLine("[DBVM断点] 已删除 " + std::to_string(n) + " 个 DBVM 断点");
  StatusText(ToW("已删除 " + std::to_string(n) + " 个 DBVM 断点"));
}

// DBVM 保护（cloak）：隐藏目标内存 → 目标读到原始副本，我们读写真实内容，
// 改动不被目标自检发现（过检测）。对选中行所在页生效。
static void DbvmProtectAddr() {
  ce::Dbvm& dbvm = ce::Dbvm::Instance();
  if (!dbvm.Available()) {
    ::MessageBoxW(g.frame, L"需要 DBVM 才能启用 DBVM 保护。", L"DBVM 保护",
                  MB_OK | MB_ICONINFORMATION);
    return;
  }
  if (!g.dbg.IsAttached() || !g.selAddr) {
    StatusText(L"请先附加进程并在 CPU 窗口选中一行");
    return;
  }
  std::string err;
  const int r = ce::DbvmTools::Instance().CloakProtect(g.dbg.Pid(), g.selAddr, &err);
  if (r == 0)
    StatusText(L"[DBVM保护] 已隐藏该页：目标读到原始副本");
  else if (r == 1)
    StatusText(L"[DBVM保护] 该页已在隐藏态");
  else
    StatusText(ToW("DBVM 保护失败: " + err));
}

static void DbvmUnprotectAddr() {
  if (!g.dbg.IsAttached() || !g.selAddr) { StatusText(L"请先选中一行"); return; }
  ce::DbvmTools::Instance().CloakUnprotect(g.dbg.Pid(), g.selAddr);
  StatusText(L"[DBVM保护] 已取消隐藏该页");
}

static void DbvmHideMemory() {
  if (ce::DbvmTools::Instance().HideDbvmMemory())
    StatusText(L"[DBVM] 已隐藏 DBVM 物理内存");
  else
    StatusText(L"[DBVM] 隐藏 DBVM 内存失败（DBVM 可能不在场）");
}

// ---------------------------------------------------------------------------
//  DBVM 命中改寄存器（ChangeRegOnBp）——命中该页即把 RAX 改成 0
// ---------------------------------------------------------------------------
static bool DbvmSelectedReady() {  // 通用前置：DBVM 在场 + 已附加 + 有选中行
  if (!ce::Dbvm::Instance().Available()) { StatusText(L"DBVM 不在场，请先 加载并启动 DBVM"); return false; }
  if (!g.dbg.IsAttached()) { StatusText(L"请先附加目标进程"); return false; }
  if (!g.selAddr) { StatusText(L"请先在 CPU 窗口选中一行"); return false; }
  return true;
}

static void DbvmChangeRegOnBp() {
  if (!DbvmSelectedReady()) return;
  ce::DbvmChangeRegInfo info{};
  info.flags.changeRax = 1;   // 命中时改 RAX
  info.newRax = 0;            // 新值 = 0
  std::string err;
  const int r = ce::DbvmTools::Instance().ChangeRegOnBpAt(g.dbg.Pid(), g.selAddr, info, &err);
  if (r == 0) {
    StatusText(L"[DBVM] 已设置改寄存器断点：命中该页即 RAX=0");
    AddLogLine("[DBVM] 命中改寄存器断点已设置（命中该物理页时目标寄存器 RAX 改写为 0）");
  } else {
    StatusText(ToW(err.empty() ? std::string("ChangeRegOnBp 失败") : err));
  }
}

static void DbvmRemoveChangeReg() {
  if (!DbvmSelectedReady()) return;
  const int r = ce::DbvmTools::Instance().RemoveChangeRegAt(g.dbg.Pid(), g.selAddr);
  if (r == 0) StatusText(L"[DBVM] 已取消改寄存器断点");
  else StatusText(L"[DBVM] 取消改寄存器断点失败");
}

// ---------------------------------------------------------------------------
//  DBVM 命中跟踪（TraceOnBp）——记录命中该页的执行/访问轨迹
// ---------------------------------------------------------------------------
static void DbvmTraceOnBp() {
  if (!DbvmSelectedReady()) return;
  std::string err;
  const int r = ce::DbvmTools::Instance().TraceOnBpAt(
      g.dbg.Pid(), g.selAddr, 0x4000, 0, &err);
  if (r == 0) StatusText(L"[DBVM] 已开始命中跟踪该页（最多 0x4000 条）");
  else StatusText(ToW(err.empty() ? std::string("TraceOnBp 失败") : err));
}

static void DbvmTraceStop() {
  const int r = ce::DbvmTools::Instance().TraceOnBpStop();
  StatusText(r == 0 ? L"[DBVM] 已停止命中跟踪" : L"[DBVM] 停止命中跟踪失败（可能未在跟踪）");
}

static void DbvmTraceLog() {
  std::vector<ce::DbvmPageEvent> events;
  uint32_t missed = 0;
  const int r = ce::DbvmTools::Instance().TraceOnBpReadLog(&events, &missed);
  if (r != 0) { StatusText(L"[DBVM] 取命中日志失败"); return; }
  char msg[128];
  std::snprintf(msg, sizeof(msg), "[DBVM] 命中跟踪日志：%zu 条，丢包 %u",
                events.size(), missed);
  AddLogLine(msg);
  for (size_t i = 0; i < events.size() && i < 3; ++i) {  // 只打前三条 RIP
    std::string one = "[DBVM]   #" + std::to_string(i) + "  ";
    char rip[32]; std::snprintf(rip, sizeof(rip), "%012llX", (unsigned long long)events[i].rip);
    one += "RIP=" + std::string(rip);
    AddLogLine(one);
  }
  StatusText(ToW("[DBVM] 已取回 " + std::to_string(events.size()) + " 条命中记录"));
}

// ---------------------------------------------------------------------------
//  DBVM 物理内存查看（选中行所在地址，绕过页保护直读物理）
// ---------------------------------------------------------------------------
static void DbvmPhysView() {
  if (!DbvmSelectedReady()) return;
  constexpr int kBytes = 256;
  std::vector<uint8_t> buf(kBytes);
  std::string err;
  const size_t got = ce::DbvmTools::Instance().PhysicalReadAt(
      g.dbg.Pid(), g.selAddr, buf.data(), buf.size(), &err);
  if (got == 0) { StatusText(ToW("DBVM 物理读取失败: " + err)); return; }

  std::string hex;
  for (size_t i = 0; i < got; ++i) {
    char b[8]; std::snprintf(b, sizeof(b), "%02X ", buf[i]);
    hex += b;
    if ((i & 15) == 15) hex += "\n";  // 16 字节一行
  }
  AddLogLine("[DBVM物理内存] 选中行 -> 物理读取 " + std::to_string(got) +
             " 字节：\n" + hex);
  StatusText(ToW("已物理读取 " + std::to_string(got) + " 字节（结果见日志）"));
}

// ---------------------------------------------------------------------------
//  DBVM 内核级保护（该页）：cloak 隐藏 + 隐藏 DBVM 自身内存
//  说明：这是 DBVM 层面对单个页的隐藏式防护（目标读到旧值、改动不被自检发现），
//  完整"进程级 NtOpenProcess 屏蔽/CR3 扫描隐藏"需内核 hook，本移植不包含。
// ---------------------------------------------------------------------------
static void DbvmKernelProt() {
  if (!DbvmSelectedReady()) return;
  std::string err;
  const int r = ce::DbvmTools::Instance().CloakProtect(g.dbg.Pid(), g.selAddr, &err);
  ce::DbvmTools::Instance().HideDbvmMemory();
  if (r == 0 || r == 1) {  // 0=成功 1=已在隐藏态
    StatusText(L"[DBVM内核防护] 该页已隐藏（目标读到旧值）+ DBVM 内存已隐藏");
    AddLogLine("[DBVM内核防护] 已启用：该物理页 cloak 隐藏 + HideDbvmPhysicalMemory");
  } else {
    StatusText(ToW("DBVM 内核保护失败: " + err));
  }
}

static HMENU BuildMenu() {
  // 仿 x64dbg 菜单栏：文件(F) 查看(V) 调试(D) 插件(P) 选项(T) 窗口(W) 帮助(H)
  HMENU bar = ::CreateMenu();

  // ---- 文件(F) ----
  HMENU file = ::CreatePopupMenu();
  ::AppendMenuW(file, MF_STRING, IDM_ATTACH, L"附加进程...\tCtrl+A");
  ::AppendMenuW(file, MF_STRING, IDM_DETACH, L"分离");
  ::AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(file, MF_STRING, IDM_EXIT, L"退出\tAlt+F4");
  ::AppendMenuW(bar, MF_POPUP, (UINT_PTR)file, L"文件(F)");

  // ---- 查看(V) ----
  HMENU view = ::CreatePopupMenu();
  ::AppendMenuW(view, MF_STRING, IDM_VIEW_CPU, L"CPU 窗口");
  ::AppendMenuW(view, MF_STRING, IDM_VIEW_SCAN, L"内存搜索");
  ::AppendMenuW(view, MF_STRING, IDM_VIEW_STRS, L"字符串参考");
  ::AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(view, MF_STRING, IDM_VIEW_MAP, L"内存地图");
  ::AppendMenuW(view, MF_STRING, IDM_VIEW_THREADS, L"线程");
  ::AppendMenuW(view, MF_STRING, IDM_VIEW_BPS, L"断点窗口");
  ::AppendMenuW(view, MF_STRING, IDM_VIEW_LOG, L"日志");
  ::AppendMenuW(view, MF_STRING, IDM_VIEW_LOGDATA, L"日志数据");
  ::AppendMenuW(view, MF_STRING, IDM_VIEW_MCP, L"MCP 输出栏");
  ::AppendMenuW(bar, MF_POPUP, (UINT_PTR)view, L"查看(V)");

  // ---- 调试(D) ----
  HMENU dbg = ::CreatePopupMenu();
  ::AppendMenuW(dbg, MF_STRING, IDM_RUN, L"运行\tF9");
  ::AppendMenuW(dbg, MF_STRING, IDM_PAUSE, L"暂停\tF12");
  ::AppendMenuW(dbg, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(dbg, MF_STRING, IDM_STEPIN, L"单步进入\tF7");
  ::AppendMenuW(dbg, MF_STRING, IDM_STEPOVER, L"单步跳过\tF8");
  ::AppendMenuW(dbg, MF_STRING, IDM_RUNTORET, L"运行到返回\tCtrl+F9");
  ::AppendMenuW(dbg, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(dbg, MF_STRING, IDM_TOGGLEBP, L"切换断点(选中行)\tF2");
  HMENU find = ::CreatePopupMenu();
  ::AppendMenuW(find, MF_STRING, IDM_FINDACCESS, L"谁访问了这个地址");
  ::AppendMenuW(find, MF_STRING, IDM_FINDWRITE, L"谁写入了这个地址");
  ::AppendMenuW(find, MF_STRING, IDM_STOPFIND, L"停止监控");
  ::AppendMenuW(find, MF_SEPARATOR, 0, nullptr);
  // 页守卫（上面三项）对**代码地址**不可用：PAGE_NOACCESS 会让目标一执行到那就崩，
  // 而"恢复 HOOK 时游戏跟着退出"正是要避免的。定位代码地址的访问者要用硬件断点。
  ::AppendMenuW(find, MF_STRING, IDM_VIEW_TLOC, L"线程定位（硬件断点，可定位代码地址）");
  ::AppendMenuW(dbg, MF_POPUP, (UINT_PTR)find, L"监视");
  ::AppendMenuW(bar, MF_POPUP, (UINT_PTR)dbg, L"调试(D)");

  // ---- 插件(P) ----
  HMENU mcp = ::CreatePopupMenu();
  ::AppendMenuW(mcp, MF_STRING, IDM_MCP_CONNECT, L"连接 CE 桥 (命名管道)");
  ::AppendMenuW(mcp, MF_STRING, IDM_MCP_DISCONNECT, L"断开");
  ::AppendMenuW(mcp, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(mcp, MF_STRING, IDM_MCP_PING, L"ping 测试");
  ::AppendMenuW(mcp, MF_STRING, IDM_MCP_PROCINFO, L"进程信息");
  ::AppendMenuW(mcp, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_DETECT, L"DBVM 检测...");
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_LOAD, L"加载并启动 DBVM...");
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_UNLOAD, L"卸载 DBVM 驱动");
  ::AppendMenuW(mcp, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_BP, L"DBVM 断点（当前反汇编选中行）");
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_BP_RESUME, L"续跑所有 DBVM 冻结线程");
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_BP_CLEAR, L"删除所有 DBVM 断点");
  ::AppendMenuW(mcp, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_CLOAK, L"DBVM 保护：隐藏目标内存(cloak)");
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_CLOAK_OFF, L"DBVM 保护：取消隐藏该页");
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_HIDE_MEM, L"隐藏 DBVM 自身物理内存");
  ::AppendMenuW(mcp, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_CR_ON, L"DBVM 断点：命中改寄存器(RAX=0)");
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_CR_OFF, L"DBVM 断点：取消改寄存器");
  ::AppendMenuW(mcp, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_TRACE_ON, L"DBVM 断点：命中跟踪(启动)");
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_TRACE_STOP, L"DBVM 断点：命中跟踪(停止)");
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_TRACE_LOG, L"DBVM 断点：命中跟踪(取日志)");
  ::AppendMenuW(mcp, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_PHYSMEM, L"DBVM 物理内存查看(选中行)");
  ::AppendMenuW(mcp, MF_STRING, IDM_DBVM_KPROT, L"DBVM 内核级保护(该页)");

  // ---- 设置API断点（仿吾爱破解版 OD 工具菜单）----
  HMENU apb = ::CreatePopupMenu();
  for (int i = 0; i < kApbCategoryCount; ++i) {
    ::AppendMenuW(apb, MF_STRING, IDM_APB_FIRST + i,
                  (std::wstring(L"") + kApbCategories[i].label).c_str());
  }
  ::AppendMenuW(apb, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(apb, MF_STRING, IDM_APB_CLEAR, L"清除所有 INT3 断点");
  ::AppendMenuW(mcp, MF_POPUP, (UINT_PTR)apb, L"设置API断点>");

  ::AppendMenuW(bar, MF_POPUP, (UINT_PTR)mcp, L"插件(P)");

  // ---- 选项(T) ----
  HMENU opt = ::CreatePopupMenu();
  HMENU enc = ::CreatePopupMenu();
  ::AppendMenuW(enc, MF_STRING, IDM_STR_ASCII, L"ASCII");
  ::AppendMenuW(enc, MF_STRING, IDM_STR_UNICODE, L"UTF-16");
  ::AppendMenuW(enc, MF_STRING, IDM_STR_SMART, L"智能检测");
  ::AppendMenuW(enc, MF_STRING, IDM_STR_CHS, L"中文 (GBK)");
  ::AppendMenuW(opt, MF_POPUP, (UINT_PTR)enc, L"字符串搜索编码");
  ::AppendMenuW(opt, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(opt, MF_STRING, IDM_SETTINGS, L"界面设置(代码高亮/颜色/字体)...");
  ::AppendMenuW(bar, MF_POPUP, (UINT_PTR)opt, L"选项(T)");

  // ---- 窗口(W) ----
  // 所有 MDI 子窗口的切换集中在此菜单；MDI client 会在末尾自动追加
  // 当前打开的子窗口列表（带勾选标记，点击即切换/激活）
  HMENU wnd = ::CreatePopupMenu();
  ::AppendMenuW(wnd, MF_STRING, IDM_VIEW_CPU, L"CPU\tShift+F2");
  ::AppendMenuW(wnd, MF_STRING, IDM_VIEW_SCAN, L"内存搜索");
  ::AppendMenuW(wnd, MF_STRING, IDM_VIEW_STRS, L"中文搜索引擎");
  ::AppendMenuW(wnd, MF_STRING, IDM_VIEW_MAP, L"内存地图");
  ::AppendMenuW(wnd, MF_STRING, IDM_VIEW_THREADS, L"线程");
  ::AppendMenuW(wnd, MF_STRING, IDM_VIEW_BPS, L"断点");
  ::AppendMenuW(wnd, MF_STRING, IDM_VIEW_LOG, L"日志");
  ::AppendMenuW(wnd, MF_STRING, IDM_VIEW_LOGDATA, L"日志数据");
  ::AppendMenuW(wnd, MF_STRING, IDM_VIEW_MCP, L"MCP 输出栏");
  ::AppendMenuW(wnd, MF_STRING, IDM_VIEW_TLOC, L"线程定位");
  ::AppendMenuW(wnd, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(wnd, MF_STRING, IDM_CASCADE, L"层叠\tShift+F5");
  ::AppendMenuW(wnd, MF_STRING, IDM_TILE, L"平铺\tShift+F4");
  ::AppendMenuW(wnd, MF_SEPARATOR, 0, nullptr);
  ::AppendMenuW(wnd, MF_STRING, IDM_CLOSEALL, L"关闭全部");
  ::AppendMenuW(bar, MF_POPUP, (UINT_PTR)wnd, L"窗口(W)");

  // ---- 帮助(H) ----
  HMENU help = ::CreatePopupMenu();
  ::AppendMenuW(help, MF_STRING, IDM_ABOUT, L"关于");
  ::AppendMenuW(bar, MF_POPUP, (UINT_PTR)help, L"帮助(H)");
  return bar;
}
//=============================================================================
// 工具栏 —— 照「吾爱破解版 OD」参照图逐项复刻
//   ① 第 1 个按钮是文字按钮「暂停」（黄底红字、通栏高），与参照图一致
//   ② 其后全部是图形按钮，顺序 / 分组间隔与参照图一一对应：
//      [暂停] | [打开 重启 关闭] | [运行 暂停] | [步进×4] | [运行到×2]
//             | [l e m t w h c p k b r ... s] | [三 魔杖 ?] | [金:快进 上下 Ab HBP 靶]
//   ③ 用自绘窗口而非 TOOLBARCLASSNAME：原生工具栏做不出黄底文字按钮、
//      单字母按钮、金色按钮组，也没有「按钮通栏高」这种比例。
//=============================================================================
static HWND g_toolbar = nullptr;
static HWND g_tbTip = nullptr;      // 气泡提示：**自绘**顶级 POPUP，一个窗口复用
static int  g_tbTipIdx = -2;        // 当前气泡对应的按钮下标（-1 无，-2 从未显示）
static bool g_tbClassReg = false, g_tbTipClassReg = false;

static const wchar_t kToolbarClass[] = L"CEScanODToolbar";
// 气泡提示窗口类。不用原生 TOOLTIPS_CLASSW：跟踪式 tooltip 在本工程里
// TTM_TRACKACTIVATE 返回成功却始终不出现（owner/子窗口组合下的老问题），
// 自绘一个顶级 POPUP 反而完全可控，顺带能做成 OD 的浅黄底黑框样式。
static const wchar_t kTbTipClass[]  = L"CEScanODToolbarTip";
// 气泡配色（照 OD 参照图）
static const COLORREF kTbTipBg   = RGB(255, 255, 225);
static const COLORREF kTbTipEdge = RGB(0, 0, 0);
static const COLORREF kTbTipInk  = RGB(0, 0, 0);
// 工具栏尺寸（kTbHeight / kTbBtnTop / kTbBtnBot / kTbBtnW / kTbPauseW / kTbSepW /
// kTbGlyph）统一由 ThemeColors.h 的 ThemeSizes（g_sz）提供，这里不再重复定义。

// 工具栏调色板：照参照图取色（经典 3D 灰 + 红箭头 + 金按钮组）。
// 它是「OD 参照图的复刻」，不跟随 g_theme 的暗色主题，故就地定义。
static const COLORREF kTbBtnFace    = RGB(192, 192, 192);  // 工具栏底 / 按钮面
static const COLORREF kTbBtnFaceHot = RGB(214, 214, 214);  // 按钮悬停面
static const COLORREF kTbBtnHi      = RGB(255, 255, 255);  // 3D 高光（上/左）
static const COLORREF kTbBtnInk     = RGB(0, 0, 0);        // 3D 阴影（下/右）与黑色图标
static const COLORREF kTbPauseBg    = RGB(255, 255, 0);    // 「暂停」按钮底（黄）
static const COLORREF kTbPauseBgHot = RGB(238, 238, 40);   // 「暂停」按钮按下
static const COLORREF kTbPauseFg    = RGB(255, 0, 0);      // 「暂停」按钮字（红）
static const COLORREF kTbBtnGold    = RGB(240, 164, 46);   // 末端金色按钮组底
static const COLORREF kTbBtnGoldHot = RGB(250, 192, 92);   // 金色按钮悬停
static const COLORREF kTbIconRed    = RGB(160, 0, 0);      // 运行控制：红
static const COLORREF kTbIconGreen  = RGB(0, 128, 0);      // 辅助：绿
static const COLORREF kTbIconPurple = RGB(128, 0, 160);    // 插件：紫

// 图标索引
enum {
  kGOpen = 0, kGRestart, kGClose,
  kGRun, kGPause,
  kGStepIn, kGStepOver, kGAniIn, kGAniOver,
  kGRunRet, kGRunTo,
  kGList, kGWand, kGHelp,
  kGFast, kGUpDown, kGAb, kGHbp, kGTarget,
};

// 按钮种类
enum { TbK_Sep = 0, TbK_Icon, TbK_Pause, TbK_Letter, TbK_Gold };

struct TbItem {
  int            kind;
  int            id;     // WM_COMMAND id（分隔条为 0）
  int            glyph;  // 图标索引（字母/文字按钮为 -1）
  const wchar_t* tip;    // 气泡提示
  const wchar_t* text;   // 字母按钮的字符 / 文字按钮的字
  int            segW;   // 仅分隔条用：组间隔宽度
};

// ---- 按钮顺序表：逐项照参照图，改顺序/间距前先看参照图 ----
//     segW 是分隔条宽度，按参照图实测换算（参照图按钮 20px → 这里 24px，×1.2）：
//     常规组间隔 12→14，步进子组 6→7，金色组前 28→34
static const TbItem kTbItems[] = {
    {TbK_Pause,  IDM_PAUSE,    -1,        L"暂停 (F12)",                  L"暂停", 0},
    {TbK_Sep,    0,            -1,        nullptr,                        nullptr, 8},
    {TbK_Icon,   IDM_ATTACH,   kGOpen,    L"打开 / 附加目标进程",          nullptr, 0},
    {TbK_Icon,   IDM_ATTACH,   kGRestart, L"重新附加（重启调试）",         nullptr, 0},
    {TbK_Icon,   IDM_DETACH,   kGClose,   L"分离 / 关闭目标进程",          nullptr, 0},
    {TbK_Sep,    0,            -1,        nullptr,                        nullptr, 14},
    {TbK_Icon,   IDM_RUN,      kGRun,     L"运行 (F9)",                   nullptr, 0},
    {TbK_Icon,   IDM_PAUSE,    kGPause,   L"暂停 (F12)",                  nullptr, 0},
    {TbK_Sep,    0,            -1,        nullptr,                        nullptr, 14},
    {TbK_Icon,   IDM_STEPIN,   kGStepIn,  L"单步进入 (F7)",               nullptr, 0},
    {TbK_Icon,   IDM_STEPOVER, kGStepOver,L"单步跳过 (F8)",               nullptr, 0},
    {TbK_Sep,    0,            -1,        nullptr,                        nullptr, 7},
    {TbK_Icon,   IDM_STEPIN,   kGAniIn,   L"动画进入（本工具等同单步进入 F7）", nullptr, 0},
    {TbK_Icon,   IDM_STEPOVER, kGAniOver, L"动画跳过（本工具等同单步跳过 F8）", nullptr, 0},
    {TbK_Sep,    0,            -1,        nullptr,                        nullptr, 7},
    {TbK_Icon,   IDM_RUNTORET, kGRunRet,  L"运行到返回 (Ctrl+F9)",        nullptr, 0},
    {TbK_Sep,    0,            -1,        nullptr,                        nullptr, 14},
    {TbK_Icon,   IDM_RUNTORET, kGRunTo,   L"运行到选中行",                nullptr, 0},
    {TbK_Sep,    0,            -1,        nullptr,                        nullptr, 14},
    {TbK_Letter, IDM_VIEW_LOG,     -1, L"日志窗口  Alt+L",           L"l",   0},
    {TbK_Letter, IDM_VIEW_MAP,     -1, L"内存区域枚举（模块）  Alt+E",    L"e",   0},
    {TbK_Letter, IDM_VIEW_SCAN,    -1, L"内存搜索  Alt+M",           L"m",   0},
    {TbK_Letter, IDM_VIEW_THREADS, -1, L"线程  Alt+T",               L"t",   0},
    {TbK_Letter, IDM_VIEW_MCP,     -1, L"MCP 输出栏  Alt+W",         L"w",   0},
    {TbK_Letter, IDM_VIEW_BPS,     -1, L"断点窗口  Alt+H",           L"h",   0},
    {TbK_Letter, IDM_VIEW_CPU,     -1, L"CPU 窗口  Alt+C",           L"c",   0},
    {TbK_Letter, IDM_VIEW_BPS,     -1, L"断点窗口（补丁）  Alt+P",    L"p",   0},
    {TbK_Letter, IDM_VIEW_CPU,     -1, L"CPU 窗口（调用栈）  Alt+K",  L"k",   0},
    {TbK_Letter, IDM_VIEW_BPS,     -1, L"断点窗口  Alt+B",           L"b",   0},
    {TbK_Letter, IDM_VIEW_STRS,    -1, L"字符串参考  Alt+R",          L"r",   0},
    {TbK_Letter, IDM_CASCADE,      -1, L"更多窗口（层叠）",            L"...", 0},
    {TbK_Letter, IDM_VIEW_STRS,    -1, L"字符串参考（源码）  Alt+S",  L"s",   0},
    {TbK_Sep,    0,            -1,        nullptr,                        nullptr, 14},
    {TbK_Icon,   IDM_TILE,        kGList, L"平铺所有窗口",              nullptr, 0},
    {TbK_Icon,   IDM_MCP_CONNECT, kGWand, L"插件：连接 CE 桥",          nullptr, 0},
    {TbK_Icon,   IDM_ABOUT,       kGHelp, L"关于 / 帮助",               nullptr, 0},
    {TbK_Sep,    0,            -1,        nullptr,                        nullptr, 34},
    {TbK_Gold,   IDM_RUN,      kGFast,   L"全速运行 (F9)",              nullptr, 0},
    {TbK_Gold,   IDM_STEPOVER, kGUpDown, L"单步跳过（上下箭头）(F8)",    nullptr, 0},
    {TbK_Gold,   IDM_STOPFIND, kGAb,     L"中止监视 / 停止搜索",         nullptr, 0},
    {TbK_Gold,   IDM_TOGGLEBP, kGHbp,    L"切换断点 (F2)",              nullptr, 0},
    {TbK_Gold,   IDM_ATTACH,   kGTarget, L"选择目标进程",               nullptr, 0},
};

struct TbHit {
  int            kind;
  int            id;
  int            glyph;
  const wchar_t* tip;
  const wchar_t* text;
  RECT           rc;
};
static std::vector<TbHit> g_tbHits;
static int  g_tbHot = -1, g_tbDown = -1;
static bool g_tbTracking = false;

static HFONT g_fPause = nullptr, g_fLetter = nullptr, g_fBold = nullptr, g_fSmall = nullptr;
static HFONT g_fTip = nullptr;

static void TbEnsureFonts() {
  if (g_fPause) return;
  // 注意：这里用 ANTIALIASED 而不是 CLEARTYPE —— ClearType 的次像素渲染会在
  // 黄底红字 / 灰底彩字上留下彩色边缘，放大看和参照图差别明显。
  g_fPause  = ::CreateFontW(-16, 0, 0, 0, FW_NORMAL, 0, 0, 0, GB2312_CHARSET,
                            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY,
                            DEFAULT_PITCH | FF_DONTCARE, kFontUiName);
  g_fLetter = ::CreateFontW(-15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY,
                            DEFAULT_PITCH | FF_DONTCARE, L"Times New Roman");
  g_fBold   = ::CreateFontW(-13, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
                            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY,
                            DEFAULT_PITCH | FF_DONTCARE, L"Arial");
  g_fSmall  = ::CreateFontW(-9, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
                            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY,
                            DEFAULT_PITCH | FF_DONTCARE, L"Arial");
  g_fTip    = ::CreateFontW(-12, 0, 0, 0, FW_NORMAL, 0, 0, 0, GB2312_CHARSET,
                            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY,
                            DEFAULT_PITCH | FF_DONTCARE, kFontUiName);
}

static void TbFill(HDC dc, const RECT& r, COLORREF c) {
  if (r.right <= r.left || r.bottom <= r.top) return;
  HBRUSH b = ::CreateSolidBrush(c);
  ::FillRect(dc, &r, b);
  ::DeleteObject(b);
}

static void TbText(HDC dc, const wchar_t* s, HFONT f, COLORREF c, const RECT& rc, UINT fmt) {
  HFONT  of = (HFONT)::SelectObject(dc, f);
  int    ob = ::SetBkMode(dc, TRANSPARENT);
  ::SetTextColor(dc, c);
  RECT r = rc;
  ::DrawTextW(dc, s, -1, &r, fmt | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
  ::SetBkMode(dc, ob);
  ::SelectObject(dc, of);
}

// 在 16x16 网格里画第 glyph 个图标，(ox,oy) 为网格左上角
static void TbDrawGlyph(HDC dc, int glyph, int ox, int oy) {
  auto px = [&](int x1, int y1, int x2, int y2, COLORREF c) {
    TbFill(dc, RECT{ox + x1, oy + y1, ox + x2, oy + y2}, c);
  };
  auto tri = [&](int x1, int y1, int x2, int y2, int x3, int y3, COLORREF c) {
    POINT p[3] = {{ox + x1, oy + y1}, {ox + x2, oy + y2}, {ox + x3, oy + y3}};
    HBRUSH  b  = ::CreateSolidBrush(c);
    HPEN    pn = ::CreatePen(PS_SOLID, 1, c);
    HGDIOBJ ob = ::SelectObject(dc, b), op = ::SelectObject(dc, pn);
    ::Polygon(dc, p, 3);
    ::SelectObject(dc, ob);
    ::SelectObject(dc, op);
    ::DeleteObject(b);
    ::DeleteObject(pn);
  };
  auto seg = [&](int x1, int y1, int x2, int y2, COLORREF c, int w) {
    HPEN    pn = ::CreatePen(PS_SOLID, w, c);
    HGDIOBJ op = ::SelectObject(dc, pn);
    ::MoveToEx(dc, ox + x1, oy + y1, nullptr);
    ::LineTo(dc, ox + x2, oy + y2);
    ::SelectObject(dc, op);
    ::DeleteObject(pn);
  };
  auto ring = [&](int cx, int cy, int r, COLORREF c) {
    HBRUSH  b  = (HBRUSH)::GetStockObject(NULL_BRUSH);
    HPEN    pn = ::CreatePen(PS_SOLID, 1, c);
    HGDIOBJ ob = ::SelectObject(dc, b), op = ::SelectObject(dc, pn);
    ::Ellipse(dc, ox + cx - r, oy + cy - r, ox + cx + r, oy + cy + r);
    ::SelectObject(dc, ob);
    ::SelectObject(dc, op);
    ::DeleteObject(pn);
  };
  // 参照图里「步进类」图标右侧恒定有一段红色虚线（追踪缓冲）
  auto dashCol = [&](int x, COLORREF c) {
    px(x, 2, x + 2, 4, c);
    px(x, 6, x + 2, 8, c);
    px(x, 10, x + 2, 12, c);
    px(x, 14, x + 2, 16, c);
  };

  const COLORREF kInk  = kTbBtnInk;
  const COLORREF kRed  = kTbIconRed;

  switch (glyph) {
    case kGOpen: {  // 打开：金色文件夹 + 红箭头（进）+ 绿箭头（出）
      // 文件夹 = 左上角标签块 + 主体块（深/浅两色，16px 下轮廓才看得清）
      px(1, 4, 9, 8, RGB(206, 158, 40));
      px(1, 7, 15, 15, RGB(250, 214, 130));
      seg(1, 15, 15, 15, RGB(150, 110, 20), 1);
      seg(15, 7, 15, 15, RGB(150, 110, 20), 1);
      // 红箭头：从左进
      seg(3, 11, 8, 11, RGB(200, 0, 0), 2);
      tri(8, 9, 12, 11, 8, 13, RGB(200, 0, 0));
      // 绿箭头：从右上出
      seg(10, 6, 13, 3, kTbIconGreen, 1);
      tri(12, 0, 15, 3, 9, 3, kTbIconGreen);
      break;
    }
    case kGRestart: {  // ◀◀ 重启
      tri(13, 3, 13, 13, 7, 8, kInk);
      tri(6, 3, 6, 13, 0, 8, kInk);
      break;
    }
    case kGClose: {  // ✕ 关闭
      seg(3, 3, 12, 12, kInk, 2);
      seg(12, 3, 3, 12, kInk, 2);
      break;
    }
    case kGRun: {  // ▶ 运行
      tri(3, 1, 3, 15, 14, 8, kRed);
      break;
    }
    case kGPause: {  // ‖ 暂停
      px(3, 1, 6, 15, kRed);
      px(10, 1, 13, 15, kRed);
      break;
    }
    case kGStepIn: {  // 单步进入：右折下箭头 + 虚线
      seg(2, 2, 2, 8, kRed, 3);
      seg(2, 8, 5, 8, kRed, 3);
      tri(4, 5, 10, 8, 4, 11, kRed);
      dashCol(13, kRed);
      break;
    }
    case kGStepOver: {  // 单步跳过：细下箭头 + 虚线
      px(5, 1, 8, 8, kRed);
      tri(2, 8, 11, 8, 6, 14, kRed);
      dashCol(13, kRed);
      break;
    }
    case kGAniIn: {  // 动画进入：折线（闪电式）下箭头 + 虚线
      tri(7, 0, 12, 0, 3, 8, kRed);
      tri(3, 7, 12, 7, 7, 15, kRed);
      dashCol(13, kRed);
      break;
    }
    case kGAniOver: {  // 动画跳过：加粗下箭头 + 虚线
      px(4, 1, 8, 8, kRed);
      tri(1, 8, 11, 8, 6, 15, kRed);
      dashCol(13, kRed);
      break;
    }
    case kGRunRet: {  // 运行到返回：右箭头 + J 形回钩
      seg(1, 8, 5, 8, kRed, 2);
      tri(4, 5, 10, 8, 4, 11, kRed);
      seg(11, 2, 11, 12, kRed, 2);
      seg(7, 12, 11, 12, kRed, 2);
      break;
    }
    case kGRunTo: {  // 运行到选中行：黑箭头 + 黑虚线
      seg(0, 8, 4, 8, kInk, 2);
      tri(3, 5, 9, 8, 3, 11, kInk);
      dashCol(13, kInk);
      break;
    }
    case kGList: {  // 三：列表
      for (int y = 1; y <= 12; y += 3) {
        px(1, y, 4, y + 2, kInk);
        px(6, y, 15, y + 2, kInk);
      }
      break;
    }
    case kGWand: {  // 魔杖（插件）
      seg(3, 14, 10, 5, kTbIconPurple, 2);
      seg(11, 0, 11, 4, kTbIconPurple, 1);
      seg(9, 2, 13, 2, kTbIconPurple, 1);
      px(11, 1, 13, 3, kTbIconPurple);
      break;
    }
    case kGHelp: {  // ? 帮助
      TbText(dc, L"?", g_fBold, RGB(200, 0, 0), RECT{ox, oy, ox + 16, oy + 16}, DT_CENTER);
      break;
    }
    case kGFast: {  // 金色：◀◀ / ▶▶ 快进
      tri(7, 1, 7, 7, 2, 4, kInk);
      tri(12, 1, 12, 7, 7, 4, kInk);
      tri(3, 9, 3, 15, 8, 12, kInk);
      tri(9, 9, 9, 15, 14, 12, kInk);
      break;
    }
    case kGUpDown: {  // 金色：上下箭头
      tri(1, 2, 7, 2, 4, 8, kInk);
      tri(9, 8, 15, 8, 12, 2, kInk);
      tri(1, 9, 7, 9, 4, 15, RGB(120, 80, 10));
      tri(9, 15, 15, 15, 12, 9, RGB(120, 80, 10));
      break;
    }
    case kGAb: {  // 金色：Ab（红 A + 绿 b，b 略小偏下 —— 照参照图）
      TbText(dc, L"A", g_fBold, RGB(220, 0, 0), RECT{ox - 1, oy - 1, ox + 9, oy + 15}, DT_LEFT);
      TbText(dc, L"b", g_fSmall, RGB(0, 150, 0), RECT{ox + 8, oy + 3, ox + 18, oy + 16}, DT_LEFT);
      break;
    }
    case kGHbp: {  // 金色：HBP（矩形放宽 2px，否则右侧 P 会被裁掉）
      TbText(dc, L"HBP", g_fSmall, kInk, RECT{ox - 1, oy + 3, ox + 17, oy + 13}, DT_CENTER);
      break;
    }
    case kGTarget: {  // 金色：靶心
      ring(8, 8, 6, RGB(190, 0, 0));
      ring(8, 8, 3, RGB(190, 0, 0));
      seg(8, 1, 8, 4, RGB(190, 0, 0), 1);
      seg(8, 12, 8, 15, RGB(190, 0, 0), 1);
      seg(1, 8, 4, 8, RGB(190, 0, 0), 1);
      seg(12, 8, 15, 8, RGB(190, 0, 0), 1);
      px(7, 7, 10, 10, RGB(90, 40, 0));
      break;
    }
  }
}

// 经典 3D 边线：上/左 1px 高光、下/右 1px 阴影；按下时反转。
// 参照图里按钮边线就只有这 1px（没有内圈），所以这里不再画内圈。
static void TbBevel(HDC dc, const RECT& r, bool down) {
  const COLORREF hi = down ? RGB(128, 128, 128) : kTbBtnHi;
  const COLORREF lo = down ? kTbBtnHi : kTbBtnInk;
  TbFill(dc, RECT{r.left, r.top, r.right - 1, r.top + 1}, hi);        // 上
  TbFill(dc, RECT{r.left, r.top, r.left + 1, r.bottom - 1}, hi);      // 左
  TbFill(dc, RECT{r.left + 1, r.bottom - 1, r.right, r.bottom}, lo);  // 下
  TbFill(dc, RECT{r.right - 1, r.top + 1, r.right, r.bottom}, lo);    // 右
}

// 按给定按钮尺寸算整条工具栏的自然宽度
static int TbTotalWidth(int pauseW, int btnW, int sepScale) {
  int t = 5;   // 左边距
  for (const TbItem& it : kTbItems) {
    if (it.kind == TbK_Sep)
      t += ::MulDiv(it.segW > 0 ? it.segW : kTbSepW, sepScale, 100);
    else
      t += (it.kind == TbK_Pause) ? pauseW : btnW;
  }
  return t;
}

// 布局。availW > 0 时做自适应收缩：整条工具栏必须能在客户区内放下，
// 否则末尾的金色按钮组会被右侧裁掉（主窗口默认只有 920px 宽，而
// 24px 按钮排满需要约 1016px）。收缩顺序：按钮宽 → 组间隔 → 暂停键，
// 按钮最小 19px（还能容下 16px 图标 + 两侧 1px 立体边线）。
static void TbLayout(int availW = 0) {
  g_tbHits.clear();
  int pw = kTbPauseW, bw = kTbBtnW, ss = 100;
  int guard = 0;
  while (availW > 0 && TbTotalWidth(pw, bw, ss) > availW && guard++ < 200) {
    if (bw > 19)       bw -= 1;
    else if (ss > 55)  ss -= 5;
    else if (pw > 78)  pw -= 2;
    else break;                       // 已经缩无可缩，剩下的交给裁切
  }

  int x = 5;   // 左边距：照参照图（参照图第一个按钮左侧留 4px，按 1.2 倍换算取 5）
  for (const TbItem& it : kTbItems) {
    if (it.kind == TbK_Sep) {
      // 组间隔宽度逐项可调（照参照图），并跟随整体缩放
      x += ::MulDiv(it.segW > 0 ? it.segW : kTbSepW, ss, 100);
      continue;
    }
    const int w = (it.kind == TbK_Pause) ? pw : bw;
    TbHit h{};
    h.kind  = it.kind;
    h.id    = it.id;
    h.glyph = it.glyph;
    h.tip   = it.tip;
    h.text  = it.text;
    ::SetRect(&h.rc, x, kTbBtnTop, x + w, kTbHeight - kTbBtnBot);
    g_tbHits.push_back(h);
    x += w;
  }
}

static int TbHitTest(POINT pt) {
  for (int i = 0; i < (int)g_tbHits.size(); ++i)
    if (::PtInRect(&g_tbHits[i].rc, pt)) return i;
  return -1;
}

static void TbPaintButton(HDC dc, int i) {
  const TbHit& h = g_tbHits[i];
  const bool down = (i == g_tbDown);
  const bool hot  = (i == g_tbHot);
  const RECT rc = h.rc;

  if (h.kind == TbK_Pause) {  // 黄底红字，无 3D 边线（照参照图）
    TbFill(dc, rc, down ? kTbPauseBgHot : kTbPauseBg);
    TbText(dc, h.text, g_fPause, kTbPauseFg,
           RECT{rc.left + 9, rc.top, rc.right - 2, rc.bottom}, DT_LEFT);
    return;
  }

  COLORREF face = (h.kind == TbK_Gold) ? kTbBtnGold : kTbBtnFace;
  if (hot && !down) face = (h.kind == TbK_Gold) ? kTbBtnGoldHot : kTbBtnFaceHot;
  TbFill(dc, rc, face);
  TbBevel(dc, rc, down);

  RECT in = rc;
  ::InflateRect(&in, -1, -1);
  if (down) ::OffsetRect(&in, 1, 1);

  if (h.kind == TbK_Letter) {
    TbText(dc, h.text, g_fLetter, kTbBtnInk, in, DT_CENTER);
  } else {
    const int ox = in.left + ((in.right - in.left) - kTbGlyph) / 2;
    const int oy = in.top + ((in.bottom - in.top) - kTbGlyph) / 2;
    TbDrawGlyph(dc, h.glyph, ox, oy);
  }
}

static void TbOnPaint(HWND hwnd) {
  PAINTSTRUCT ps;
  HDC dc = ::BeginPaint(hwnd, &ps);
  RECT cr;
  ::GetClientRect(hwnd, &cr);
  TbFill(dc, cr, kTbBtnFace);
  TbFill(dc, RECT{0, 0, cr.right, 1}, kTbBtnHi);                  // 顶边高光
  TbFill(dc, RECT{0, cr.bottom - 1, cr.right, cr.bottom}, kTbBtnInk);  // 底边阴影
  for (int i = 0; i < (int)g_tbHits.size(); ++i) {
    const RECT& r = g_tbHits[i].rc;
    if (r.right <= 0 || r.left >= cr.right) continue;  // 窗口变窄时裁掉看不见的
    TbPaintButton(dc, i);
  }
  ::EndPaint(hwnd, &ps);
}

// 气泡窗口的根窗口（顶层框架）：气泡只在框架处于前台时才显示，
// 免得 Alt+Tab 切走后留下一个孤儿提示。
static HWND TbRoot() {
  HWND h = ::GetAncestor(g_toolbar, GA_ROOT);
  return h ? h : g_toolbar;
}

static bool TbAppActive() {
  HWND fg = ::GetForegroundWindow();
  if (!fg) return false;
  return fg == TbRoot() || ::GetAncestor(fg, GA_ROOTOWNER) == TbRoot();
}

static void TbHideTip(const char* why = "") {
  if (!g_tbTip) return;
  if (::IsWindowVisible(g_tbTip)) {
    ::ShowWindow(g_tbTip, SW_HIDE);
    UiTrace(std::string("TB tip hide (") + why + ") idx=" + std::to_string(g_tbTipIdx));
  }
  g_tbTipIdx = -1;
}

// 显示第 i 个按钮的气泡（i<0 表示隐藏）。自己做尺寸/避让/显示，不依赖 comctl32。
static void TbShowTip(int i) {
  if (!g_tbTip) return;
  if (i < 0 || i >= (int)g_tbHits.size() || !g_tbHits[i].tip) { TbHideTip("no-tip"); return; }
  if (!TbAppActive()) { TbHideTip("inactive"); return; }

  const wchar_t* s = g_tbHits[i].tip;
  if (g_tbTipIdx != i) {
    ::SetWindowTextW(g_tbTip, s);
    g_tbTipIdx = i;
  }

  // 量文字尺寸（+ 左右 11 / 上下 7 的内边距）
  int tw = 0, th = 0;
  if (HDC dc = ::GetDC(g_tbTip)) {
    HFONT of = (HFONT)::SelectObject(dc, g_fTip ? g_fTip
                                                 : (HFONT)::GetStockObject(DEFAULT_GUI_FONT));
    SIZE sz{};
    if (::GetTextExtentPoint32W(dc, s, (int)::wcslen(s), &sz)) { tw = sz.cx; th = sz.cy; }
    ::SelectObject(dc, of);
    ::ReleaseDC(g_tbTip, dc);
  }
  const int bw = tw + 11, bh = th + 7;

  POINT pt{};
  ::GetCursorPos(&pt);
  int x = pt.x + 14, y = pt.y + 24;              // 默认落在光标右下
  RECT wa{};
  ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
  if (x + bw > wa.right)  x = wa.right - bw;     // 贴右边缘 → 左移
  if (x < wa.left)        x = wa.left;
  if (y + bh > wa.bottom) y = pt.y - bh - 6;     // 下方放不下 → 翻到光标上方

  ::SetWindowPos(g_tbTip, HWND_TOPMOST, x, y, bw, bh,
                 SWP_NOACTIVATE | SWP_SHOWWINDOW);
  ::InvalidateRect(g_tbTip, nullptr, TRUE);
  UiTrace("TB tip i=" + std::to_string(i) + " pos=" + std::to_string(x) + "," + std::to_string(y) +
          " size=" + std::to_string(bw) + "x" + std::to_string(bh) +
          " vis=" + std::to_string((int)::IsWindowVisible(g_tbTip)));
}

// 自绘气泡：浅黄底 + 1px 黑框 + 黑字；对鼠标完全透明，别抢工具栏的 hover。
static LRESULT CALLBACK TbTipProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_ERASEBKGND:
      return 1;
    case WM_NCHITTEST:
      return HTTRANSPARENT;
    case WM_MOUSEACTIVATE:
      return MA_NOACTIVATE;
    case WM_PAINT: {
      PAINTSTRUCT ps;
      HDC dc = ::BeginPaint(hwnd, &ps);
      RECT cr;
      ::GetClientRect(hwnd, &cr);
      TbFill(dc, cr, kTbTipBg);
      TbFill(dc, RECT{0, 0, cr.right, 1}, kTbTipEdge);                      // 上
      TbFill(dc, RECT{0, cr.bottom - 1, cr.right, cr.bottom}, kTbTipEdge);  // 下
      TbFill(dc, RECT{0, 0, 1, cr.bottom}, kTbTipEdge);                     // 左
      TbFill(dc, RECT{cr.right - 1, 0, cr.right, cr.bottom}, kTbTipEdge);   // 右
      wchar_t buf[512] = L"";
      ::GetWindowTextW(hwnd, buf, 512);
      if (buf[0]) {
        RECT tr{cr.left + 6, cr.top + 3, cr.right - 5, cr.bottom - 3};
        TbText(dc, buf, g_fTip ? g_fTip : (HFONT)::GetStockObject(DEFAULT_GUI_FONT),
               kTbTipInk, tr, DT_LEFT);
      }
      ::EndPaint(hwnd, &ps);
      return 0;
    }
  }
  return ::DefWindowProcW(hwnd, msg, wp, lp);
}

static LRESULT CALLBACK ToolbarProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_ERASEBKGND:
      return 1;

    case WM_PAINT:
      TbOnPaint(hwnd);
      return 0;

    case WM_MOUSEMOVE: {
      POINT pt{(short)LOWORD(lp), (short)HIWORD(lp)};
      const int i = TbHitTest(pt);
      if (i != g_tbHot) {
        const int old = g_tbHot;
        g_tbHot = i;
        if (old >= 0) ::InvalidateRect(hwnd, &g_tbHits[old].rc, FALSE);
        if (i >= 0) ::InvalidateRect(hwnd, &g_tbHits[i].rc, FALSE);
        TbShowTip(i);
      }
      if (!g_tbTracking) {
        TRACKMOUSEEVENT tme{sizeof(tme), TME_LEAVE, hwnd, 0};
        ::TrackMouseEvent(&tme);
        g_tbTracking = true;
      }
      if (g_tbDown >= 0 && g_tbDown != i) {  // 按住后拖出按钮 → 取消按下态
        const int old = g_tbDown;
        g_tbDown = -1;
        ::InvalidateRect(hwnd, &g_tbHits[old].rc, FALSE);
      }
      return 0;
    }

    case WM_MOUSELEAVE: {
      // 坑：我们弹出 TOPMOST 气泡后，Windows 会**误发**一次 WM_MOUSELEAVE，
      // 而光标其实还稳稳停在工具栏上 —— 结果气泡刚出来 ~130ms 就被收掉。
      // 不信消息，信光标的实际位置：还在按钮区就重新挂 TME_LEAVE 并忽略这次。
      POINT cp{};
      ::GetCursorPos(&cp);
      RECT wr{};
      ::GetWindowRect(hwnd, &wr);
      if (::PtInRect(&wr, cp)) {
        TRACKMOUSEEVENT tme{sizeof(tme), TME_LEAVE, hwnd, 0};
        ::TrackMouseEvent(&tme);
        g_tbTracking = true;
        UiTrace("TB mouseleave 误报（光标仍在 " + std::to_string(cp.x) + "," +
                std::to_string(cp.y) + "），忽略");
        return 0;
      }
      g_tbTracking = false;
      const int old = g_tbHot;
      g_tbHot = -1;
      if (old >= 0) ::InvalidateRect(hwnd, &g_tbHits[old].rc, FALSE);
      TbHideTip("mouseleave");
      return 0;
    }

    case WM_LBUTTONDOWN: {
      POINT pt{(short)LOWORD(lp), (short)HIWORD(lp)};
      const int i = TbHitTest(pt);
      UiTrace("TB down x=" + std::to_string(pt.x) + " y=" + std::to_string(pt.y) +
              " idx=" + std::to_string(i));
      if (i >= 0) {
        g_tbDown = i;
        TbHideTip("btn-down");  // 按下就把气泡收起来，别挡视线
        ::SetCapture(hwnd);
        ::InvalidateRect(hwnd, &g_tbHits[i].rc, FALSE);
      }
      return 0;
    }

    case WM_LBUTTONUP: {
      POINT pt{(short)LOWORD(lp), (short)HIWORD(lp)};
      const int i = TbHitTest(pt);
      const int d = g_tbDown;
      // 先清按下态再 ReleaseCapture：ReleaseCapture 会**同步**发回
      // WM_CAPTURECHANGED，如果那时 g_tbDown 还没清，命令就永远发不出去。
      g_tbDown = -1;
      if (::GetCapture() == hwnd) ::ReleaseCapture();
      if (d >= 0) ::InvalidateRect(hwnd, &g_tbHits[d].rc, FALSE);
      UiTrace("TB up   x=" + std::to_string(pt.x) + " y=" + std::to_string(pt.y) +
              " down=" + std::to_string(d) + " hit=" + std::to_string(i) +
              " id=" + std::to_string(d >= 0 ? g_tbHits[d].id : 0));
      // 和原生工具栏一样：发给父窗口 WM_COMMAND，框架的现有分发逻辑直接复用
      if (d >= 0 && d == i && g_tbHits[i].id)
        ::SendMessageW(::GetParent(hwnd), WM_COMMAND,
                       MAKEWPARAM((WORD)g_tbHits[i].id, 0), (LPARAM)hwnd);
      return 0;
    }

    case WM_CAPTURECHANGED: {
      if (g_tbDown >= 0) {
        const int d = g_tbDown;
        g_tbDown = -1;
        ::InvalidateRect(hwnd, &g_tbHits[d].rc, FALSE);
      }
      return 0;
    }

    case WM_DESTROY:
      TbHideTip();
      return 0;
  }
  return ::DefWindowProcW(hwnd, msg, wp, lp);
}

static void CreateFrameToolbar(HWND parent) {
  TbEnsureFonts();
  TbLayout();

  if (!g_tbClassReg) {
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = ToolbarProc;
    wc.hInstance     = g.inst;
    wc.hCursor       = ::LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;  // 全部自绘
    wc.lpszClassName = kToolbarClass;
    ::RegisterClassExW(&wc);
    g_tbClassReg = true;
  }

  g_toolbar = ::CreateWindowExW(0, kToolbarClass, nullptr,
                                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                0, 0, 0, kTbHeight, parent, (HMENU)(INT_PTR)IDC_TOOLBAR,
                                g.inst, nullptr);
  g.toolbar = g_toolbar;  // 同步到 App，供 FrameProc 的 WM_SIZE 布局使用

  // 气泡提示：自绘顶级 POPUP（owner 取框架窗口，避免出现在任务栏/Alt+Tab）。
  // 用 WS_EX_NOACTIVATE 保证点它不会抢焦点；WM_NCHITTEST 返回 HTTRANSPARENT
  // 让鼠标穿透，免得挡住工具栏的 hover。
  if (!g_tbTipClassReg) {
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = TbTipProc;
    wc.hInstance     = g.inst;
    wc.hCursor       = ::LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;  // 自绘
    wc.lpszClassName = kTbTipClass;
    ::RegisterClassExW(&wc);
    g_tbTipClassReg = true;
  }
  g_tbTip = ::CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                              kTbTipClass, L"", WS_POPUP,
                              0, 0, 10, 10, parent, nullptr, g.inst, nullptr);
  g_tbTipIdx = -2;
  UiTrace("TB create hwnd=" + std::to_string((unsigned long long)(uintptr_t)g_toolbar) +
          " tip=" + std::to_string((unsigned long long)(uintptr_t)g_tbTip) +
          " err=" + std::to_string((unsigned)::GetLastError()));
}

//=============================================================================
// CE 风格「以下操作码访问了 XXXXXXXX」窗口
//   对应 CE FoundCodeUnit.pas 的 TFoundCodeDialog：
//     · 命中按"指令地址"聚合 —— 计数 | 指令（CE 的 Count | Instruction）
//     · 按钮 停止(对应 btnOK) / 显示反汇编器 / 替换为NOP / 添加到断点列表
//     · 被监视地址写进窗口标题，与 CE 的 rsTheFollowingOpcodesAccessed 一致
//   引擎侧：CE 默认用调试寄存器(bpmDebugRegister)，我们用页面守卫(bpmException)，
//           两者都需要"命中后重新武装"，这部分在 Debugger.cpp 里完成。
//=============================================================================
static const wchar_t kWatchClass[] = L"CEScanWatchWnd";
static bool g_watchClassReg = false;

struct WatchRow {
  ptruint      rip = 0;
  int          count = 0;
  bool         write = false;
  DWORD        tid = 0;
  std::wstring ins, mod, bytes;
  std::wstring restore;   // HOOK/VM 还原字节（分析完成后回填）
  // ---- 访问性质自动判定（新列）----
  std::wstring      verdict;      // 列显示的短标签
  std::string       vReason;      // 判定依据（更多信息框）
  ce::AccessKind    vKind = ce::AccessKind::Unknown;
  ULONGLONG         firstTick = 0, lastTick = 0;   // 用于轮询规律统计
  std::vector<double> gaps;       // 命中间隔(ms)，最多保留 32 个
};
struct WatchWinState {
  HWND wnd = nullptr, list = nullptr, info = nullptr;
  HWND btnStop = nullptr, btnDis = nullptr, btnNop = nullptr, btnBp = nullptr;
  HWND btnRestore = nullptr;                  // 手动触发「查找还原字节」
  HWND btnBypass = nullptr;                   // 过检测/过CRC（打掉比对分支）
  HWND btnAuto = nullptr;                     // VM 自动还原 开/关
  bool autoRestore = true;                    // 分析出 HOOK 后自动写回原始字节
  HBRUSH bg = nullptr;
  bool    write = false;      // 监视类型：false=访问 true=写入
  ptruint addr = 0;           // 被监视地址
  bool    watching = false;   // 仍在监视（对应 CE 的 Stop/Close 按钮文字切换）
  std::vector<WatchRow> rows;
  std::map<ptruint, int> index;   // 指令地址 -> rows 下标
};
static WatchWinState g_watch;

static void WatchSyncTitle() {
  if (g_watch.btnStop)
    ::SetWindowTextW(g_watch.btnStop, g_watch.watching ? L"停止" : L"关闭");
  if (g_watch.wnd) {
    wchar_t title[128];
    std::swprintf(title, 128,
                  g_watch.write ? L"以下操作码写入了 %012llX"
                                : L"以下操作码访问了 %012llX",
                  (unsigned long long)g_watch.addr);
    ::SetWindowTextW(g_watch.wnd, title);
  }
}

static void WatchShowInfo(int row) {
  if (!g_watch.info) return;
  if (row < 0 || row >= (int)g_watch.rows.size()) {
    ::SetWindowTextW(g_watch.info, L"");
    return;
  }
  const WatchRow& r = g_watch.rows[row];
  // 用动态拼接，不用固定大小缓冲 + swprintf：指令文本/模块名长度不可控，
  // 一旦超长就是栈缓冲区溢出（进程会以 0xC0000409 直接挂掉）。
  wchar_t addr[64];
  std::swprintf(addr, 64, L"%012llX", (unsigned long long)r.rip);
  std::wstring s;
  s.reserve(512);
  s += L"指令地址: "; s += addr;                                   s += L"\r\n";
  s += L"指令:     "; s += r.ins;                                  s += L"\r\n";
  s += L"字节:     "; s += r.bytes;                                s += L"\r\n";
  s += L"访问类型: "; s += r.write ? L"写入" : L"读取";            s += L"\r\n";
  s += L"线程:     "; s += std::to_wstring(r.tid);                 s += L"\r\n";
  s += L"命中次数: "; s += std::to_wstring(r.count);               s += L"\r\n";
  s += L"模块基址: "; s += r.mod.empty() ? L"(未识别)" : r.mod;    s += L"\r\n";
  s += L"访问性质: "; s += (r.verdict.empty() ? L"(待判定)" : r.verdict); s += L"\r\n";
  if (!r.vReason.empty()) {
    s += L"判定依据: "; s += ToW(r.vReason);                       s += L"\r\n";
  }
  if (!r.restore.empty()) { s += L"还原字节: "; s += r.restore; s += L"\r\n"; }
  RTrace("WSI built len=%zu", s.size());
  ::SetWindowTextW(g_watch.info, s.c_str());
  RTrace("WSI done");
}

// ---------------------------------------------------------------------------
//  HOOK / VM 还原：后台分析，结果经 WM_APP_RESTORE 回 UI 线程
//  （监视窗口每出现一条新指令就自动触发一次；也可手动按按钮/右键触发）
// ---------------------------------------------------------------------------
static std::set<ptruint> g_restoreAsked;            // 已请求过分析的地址
static ce::RestoreJournal g_restoreJournal;          // 本地记录文件（还原记录_时间.txt）

static void StartRestoreAnalyze(ptruint addr) {
  if (!addr || !g.proc.IsOpen()) return;
  if (!g_restoreAsked.insert(addr).second) return;  // 同一地址只分析一次
  char ab[32];
  std::snprintf(ab, sizeof(ab), "%llX", (unsigned long long)addr);
  AddLogLine(std::string("[还原] 分析 0x") + ab + " ...");
  std::thread([addr]() {
    // 后台线程里一旦有未捕获异常，std::terminate 会直接 abort 整个 GUI
    // （进程退出码 0xC0000409），所以这里必须全部兜住。
    try {
      // 关键：后台线程**绝不能**用 g.proc。
      // ProcessMemory::CachedModules() 是懒加载且无锁的，UI 线程同时在用
      // g.proc，两边并发填充 moduleCache_ 会直接把堆搞坏
      // （表现为 GUI 突然以 0xC0000409 崩掉）。这里开一份自己用的实例。
      ce::ProcessMemory own;
      ce::ProcessMemory* use = &own;
      std::string e;
      RTrace("begin   %llX  (own=%d)", (unsigned long long)addr,
             own.Open(g.dbg.Pid(), &e) ? 1 : 0);
      if (!own.IsOpen()) use = &g.proc;             // 打不开才退回共享实例
      ce::RestoreResult r = ce::AnalyzeHook(*use, addr);
      RTrace("analyzed %llX readable=%d hook=%d found=%d",
             (unsigned long long)addr, (int)r.readable, (int)r.isHook, (int)r.found);
      if (!r.readable) return;                      // 附加已断开：丢弃即可
      ce::RestoreResult* copy = new ce::RestoreResult(std::move(r));
      const BOOL okPost =
          ::PostMessageW(g.frame, WM_APP_RESTORE, 0, (LPARAM)copy);
      RTrace("posted  %llX ok=%d err=%lu", (unsigned long long)addr, (int)okPost,
             okPost ? 0 : (unsigned long)::GetLastError());
      if (!okPost) delete copy;
    } catch (const std::exception& e) {
      RTrace("EXCEPTION %llX: %s", (unsigned long long)addr, e.what());
      std::fprintf(stderr, "[还原] 分析 0x%llX 异常: %s\n",
                   (unsigned long long)addr, e.what());
    } catch (...) {
      RTrace("EXCEPTION %llX: unknown", (unsigned long long)addr);
      std::fprintf(stderr, "[还原] 分析 0x%llX 未知异常\n", (unsigned long long)addr);
    }
  }).detach();
}

// ---------------------------------------------------------------------------
//  访问性质判定辅助（配合 HookRestore.h 的 ClassifyAccessStatic/Refine）
// ---------------------------------------------------------------------------

// 命中间隔统计：平均间隔与抖动系数（平均绝对偏差/平均值，越小越规律）
static void GapStats(const std::vector<double>& gaps, double* avg, double* jitter) {
  *avg = 0.0;
  *jitter = 1.0;
  if (gaps.empty()) return;
  double sum = 0.0;
  for (double g : gaps) sum += g;
  const double a = sum / (double)gaps.size();
  if (a <= 0.0) return;
  double dev = 0.0;
  for (double g : gaps) dev += (g > a ? g - a : a - g);
  *avg = a;
  *jitter = dev / (double)gaps.size() / a;
}

// 把判定结果写进「访问性质」列（UI 线程）；标签变化时记日志
static void WatchSetVerdict(int row, const ce::AccessVerdict& v) {
  if (row < 0 || row >= (int)g_watch.rows.size()) return;
  WatchRow& r = g_watch.rows[row];
  if (!r.verdict.empty() && r.verdict == ToW(v.label)) {
    r.vReason = v.reason;                    // 依据可能更新（追加轮询统计）
    return;
  }
  r.verdict = ToW(v.label);
  r.vKind = v.kind;
  r.vReason = v.reason;
  if (g_watch.list && ::IsWindow(g_watch.list)) {
    LVITEMW s{};
    s.mask = LVIF_TEXT;
    s.iItem = row;
    s.iSubItem = 3;                          // 访问性质列
    s.pszText = const_cast<LPWSTR>(r.verdict.c_str());
    ::SendMessageW(g_watch.list, LVM_SETITEMW, row, (LPARAM)&s);
    ::InvalidateRect(g_watch.list, nullptr, FALSE);   // 按性质着色重画
  }
}

// 把该地址对应的行标记为「已还原✓」（UI 线程调用）
static void WatchMarkRestored(ptruint addr) {
  auto it = g_watch.index.find(addr);
  if (it == g_watch.index.end()) return;
  const int row = it->second;
  if (row < 0 || row >= (int)g_watch.rows.size()) return;
  g_watch.rows[row].restore = L"已还原✓";
  if (g_watch.list && ::IsWindow(g_watch.list)) {
    LVITEMW s{};
    s.mask = LVIF_TEXT;
    s.iItem = row;
    s.iSubItem = 4;                          // 还原字节列
    s.pszText = const_cast<LPWSTR>(g_watch.rows[row].restore.c_str());
    ::SendMessageW(g_watch.list, LVM_SETITEMW, row, (LPARAM)&s);
  }
}

// VM 自动还原：把《VM还原档案》里手工做的最后一步自动化 ——
// 分析出 HOOK 且找到还原字节后，直接把原始字节写回目标进程，解除 HOOK。
// （UI 线程调用；写目标内存用 g.proc，不碰后台线程的实例）
static void DoAutoRestore(const ce::RestoreResult& r) {
  if (!g.proc.IsOpen()) return;
  // 组写回缓冲：还原字节不足 hookLen 时用 0x90 补齐，覆盖整个 HOOK 区域
  std::vector<ubyte> w = r.origBytes;
  if (r.hookLen > 0 && (int)w.size() < r.hookLen)
    w.resize((size_t)r.hookLen, 0x90);
  if (w.empty()) return;

  char ab[32];
  std::snprintf(ab, sizeof(ab), "%012llX", (unsigned long long)r.addr);

  // 读当前字节：一是幂等判断（已还原过就不再写），二是日志里留改动前快照
  std::vector<ubyte> cur(w.size(), 0);
  const size_t got = g.proc.ReadPartial(r.addr, cur.data(), cur.size());
  std::string curHex;
  {
    char t[8];
    for (size_t i = 0; i < got; ++i) {
      std::snprintf(t, sizeof(t), "%02X ", cur[i]);
      curHex += t;
    }
  }
  if (got == w.size() && cur == w) {
    AddLogLine(std::string("[自动还原] ") + ab + " 已是原始字节，无需写回");
    WatchMarkRestored(r.addr);
    return;
  }

  size_t written = 0;
  if (!g.proc.Write(r.addr, w.data(), w.size(), &written) || written != w.size()) {
    AddLogLine(std::string("[自动还原] ") + ab + " 写回失败（页保护/权限不足）");
    return;
  }
  // 回读校验：确保真的写进去了
  std::vector<ubyte> chk(w.size(), 0);
  const size_t got2 = g.proc.ReadPartial(r.addr, chk.data(), chk.size());
  if (got2 == chk.size() && chk == w) {
    AddLogLine(std::string("[自动还原] OK ") + ab + " 已写回 " + r.origHex +
               "（原为 " + curHex + "）HOOK 已解除");
    WatchMarkRestored(r.addr);
    if (g.cpu && ::IsWindow(g.cpu)) { g.lastDisasmBase = 0; UpdateCpuWindow(); }
  } else {
    AddLogLine(std::string("[自动还原] ") + ab +
               " 写回后回读不一致，目标可能自行改写了该页");
  }
}

static void WatchClear() {
  g_watch.rows.clear();
  g_watch.index.clear();
  g_restoreAsked.clear();                    // 新一轮监视重新自动分析
  if (g_watch.list) ::SendMessageW(g_watch.list, LVM_DELETEALLITEMS, 0, 0);
  if (g_watch.info) ::SetWindowTextW(g_watch.info, L"");
}

// 命中 -> 聚合到列表（在 UI 线程调用）
static void WatchAddHit(const HitReport& hit) {
  if (!g_watch.wnd || !::IsWindow(g_watch.wnd) || !g_watch.list) return;
  auto it = g_watch.index.find(hit.rip);
  const int selRow = (int)::SendMessageW(g_watch.list, LVM_GETNEXTITEM, (WPARAM)-1,
                                        MAKELPARAM(LVNI_SELECTED, 0));
  if (it == g_watch.index.end()) {
    WatchRow r;
    r.rip = hit.rip;
    r.count = 1;
    r.tid = hit.tid;
    r.write = (hit.kind == BpKind::Write || hit.kind == BpKind::HardwareWrite);
    r.ins = ToW(hit.disasm);
    r.mod = ToW(hit.module);
    {
      wchar_t t[8];
      for (size_t i = 0; i < hit.bytes.size() && i < 12; ++i) {
        std::swprintf(t, 8, L"%02X ", hit.bytes[i]);
        r.bytes += t;
      }
    }
    // ---- 访问性质自动判定：首条命中先做静态分类（指令特征 + RIP 区域）----
    r.firstTick = r.lastTick = ::GetTickCount64();
    const ce::AccessVerdict v0 =
        ce::ClassifyAccessStatic(hit.disasm, r.write, hit.module.empty());
    r.verdict = ToW(v0.label);
    r.vKind = v0.kind;
    r.vReason = v0.reason;
    const int row = (int)g_watch.rows.size();
    g_watch.rows.push_back(r);
    g_watch.index[hit.rip] = row;

    wchar_t c0[24], c1[32], c2[512], c3[64];
    std::swprintf(c0, 24, L"%d", r.count);
    std::swprintf(c1, 32, L"%012llX", (unsigned long long)r.rip);
    std::swprintf(c2, 512, L"%s", r.ins.c_str());
    std::swprintf(c3, 64, L"%s", r.verdict.c_str());
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = row;
    item.pszText = c0;
    const int idx = (int)::SendMessageW(g_watch.list, LVM_INSERTITEMW, 0, (LPARAM)&item);
    // 第 3 列 = 访问性质（插入时就有静态判定结果），第 5 列(还原字节)插入时给
    // 占位文本"…"，分析完再由 WM_APP_RESTORE 回填。
    // 给占位而不是留空，是为了让"待分析"状态在界面上可见（列表里空白列容易被
    // 误认为是 BUG）。
    // 注：早期这里记过一条"子项文本为空时选中该行会 AV 崩"的结论，后来用
    // tools/lvcrash_test.cpp 与 tools/repro_sel_crash.py 复查是误判——
    // 真实鼠标点击并不会崩（见 .workbuddy/memory/MEMORY.md）。
    wchar_t c4[8] = L"\x2026";     // "…" = 待分析
    wchar_t* cols[4] = {c1, c2, c3, c4};
    for (int c = 0; c < 4; ++c) {
      LVITEMW s{};
      s.mask = LVIF_TEXT;              // 同上：缺 mask 会导致子列写不进去
      s.iItem = idx;                   // 关键：LVM_SETITEM 的行号取自 iItem
      s.iSubItem = c + 1;
      s.pszText = cols[c];
      ::SendMessageW(g_watch.list, LVM_SETITEMW, idx, (LPARAM)&s);
    }
    // 判定结果记日志（一条命中一行，便于翻历史）
    AddLogLine(std::string("[性质] 0x") + [&] {
      char b[32];
      std::snprintf(b, sizeof(b), "%llX", (unsigned long long)r.rip);
      return std::string(b);
    }() + "  " + hit.disasm + "  →  " + v0.label + "（" + v0.reason + "）");
    // 《VM还原档案》：自动找出还原字节
    // （CE_NO_RESTORE=1 可临时关掉，仅用于排查）
    if (!::getenv("CE_NO_RESTORE")) StartRestoreAnalyze(hit.rip);
  } else {
    const int row = it->second;
    WatchRow& r = g_watch.rows[row];
    if (r.count < 99999999) ++r.count;
    // ---- 命中间隔统计（轮询规律性）----
    const ULONGLONG now = ::GetTickCount64();
    if (r.lastTick) {
      r.gaps.push_back((double)(now - r.lastTick));
      if (r.gaps.size() > 32) r.gaps.erase(r.gaps.begin());
    }
    r.lastTick = now;
    // 命中 3/10/30 次时用轮询规律修正判定：规律高频读取 → 疑似检测/CRC 轮询
    if (r.count == 3 || r.count == 10 || r.count == 30) {
      double avg = 0.0, jit = 1.0;
      GapStats(r.gaps, &avg, &jit);
      const ce::AccessVerdict v = ce::RefineAccessVerdict(
          ce::ClassifyAccessStatic(hit.disasm, r.write, r.mod.empty()),
          r.count, avg, jit);
      WatchSetVerdict(row, v);
    }
    wchar_t c0[24];
    std::swprintf(c0, 24, L"%d", r.count);
    LVITEMW s{};
    s.mask = LVIF_TEXT;                // 刷新计数同样需要 mask
    s.iItem = row;                     // 关键：LVM_SETITEM 的行号取自 iItem
    s.iSubItem = 0;
    s.pszText = c0;
    ::SendMessageW(g_watch.list, LVM_SETITEMW, row, (LPARAM)&s);
    if (row == selRow) WatchShowInfo(row);   // 选中行实时刷新"更多信息"
  }
}

// 取当前"选中"的地址：内存搜索结果优先，其次反汇编锚点（对应 CE 右键取选区地址）
static ptruint PickWatchAddress() {
  if (g.scanWnd && ::IsWindow(g.scanWnd)) {
    HWND list = Ctrl(g.scanWnd, IDC_RESULTS);
    int sel = (int)::SendMessageW(list, LVM_GETNEXTITEM, (WPARAM)-1,
                                 MAKELPARAM(LVNI_SELECTED, 0));
    if (sel >= 0) {
      ptruint a = g.scan.AddressAt((size_t)sel);
      if (a) return a;
    }
  }
  if (g.selAddr) return g.selAddr;
  if (g.disasmSel >= 0 && g.disasmSel < (int)g.disasmAddr.size())
    return g.disasmAddr[g.disasmSel];
  return 0;
}

static void WatchStopFind(const wchar_t* why) {
  g.dbg.StopFind();
  ++g_watchGen;                             // 让已排队/在途的命中失效，避免停止后还往里加行
  DropPendingHits();                        // 顺带清掉积压，别让它拖慢后面的操作
  if (g_watch.watching) {
    g_watch.watching = false;
    ::InterlockedExchange(&g_guardWatchOn, 0);
    WatchSyncTitle();
  }
  AddLogLine("[监视] 已停止");
  StatusText(why ? why : L"已停止监控");
}

// --- 定位「选中崩溃」用的一次性开关（读环境变量，定位完即可删）---
//   CE_W_NOTHEME=1  不给监视列表套 DarkMode_Explorer 主题
//   CE_W_NODBL=1    不加 LVS_EX_DOUBLEBUFFER
//   CE_W_NOFULL=1   不加 LVS_EX_FULLROWSELECT
//   CE_W_NOCD=1     监视列表不参与父窗的 NM_CUSTOMDRAW
//   CE_W_NOINFO=1   选中时不调 WatchShowInfo（不给"更多信息"框写文本）
static bool EnvOn(const char* n) {
  const char* v = ::getenv(n);
  return v && v[0] == '1';
}
static bool g_wNoTheme = false, g_wNoDbl = false, g_wNoFull = false;

static LRESULT CALLBACK WatchProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE: {
      g_watch.wnd = hwnd;
      g_watch.bg = GetCachedBrush(kWatchBg);
      auto mkBtn = [&](int id, const wchar_t* text) {
        HWND b = ::CreateWindowExW(0, L"BUTTON", text,
                                   WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                   0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)id, g.inst, nullptr);
        MakeDarkButton(b, BS_PUSHBUTTON);
        ::SendMessageW(b, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
        return b;
      };
      g_watch.btnNop  = mkBtn(IDC_W_NOP,    L"替换为 NOP");
      g_watch.btnDis  = mkBtn(IDC_W_DISASM, L"显示反汇编器");
      g_watch.btnBp   = mkBtn(IDC_W_BP,     L"添加到断点列表");
      g_watch.btnRestore = mkBtn(IDC_W_RESTORE, L"查找还原字节");
      g_watch.btnBypass  = mkBtn(IDC_W_BYPASS,  L"过检测/过CRC");
      g_watch.btnStop = mkBtn(IDC_W_STOP,   L"停止");

      HWND list = ::CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                                    WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT |
                                        LVS_SHOWSELALWAYS | WS_VSCROLL,
                                    0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)IDC_W_LIST,
                                    g.inst, nullptr);
      {
        DWORD ex = 0;
        if (!g_wNoFull) ex |= LVS_EX_FULLROWSELECT;
        if (!g_wNoDbl)  ex |= LVS_EX_DOUBLEBUFFER;
        ListView_SetExtendedListViewStyle(list, ex);
      }
      ::SendMessageW(list, LVM_SETBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(list, LVM_SETTEXTBKCOLOR, 0, (LPARAM)kListBg);
      ::SendMessageW(list, LVM_SETTEXTCOLOR, 0, (LPARAM)kListText);
      // 滚动条保持系统默认配色（g_wNoTheme 环境变量已无意义，保留仅为兼容）
      AddListColumn(list, L"计数", 70);
      AddListColumn(list, L"指令地址", 140);
      AddListColumn(list, L"指令", 340);
      AddListColumn(list, L"访问性质", 110);
      AddListColumn(list, L"还原字节", 150);
      ::SendMessageW(list, WM_SETFONT, (WPARAM)g.monoFont, TRUE);
      g_watch.list = list;

      HWND info = ::CreateWindowExW(0, L"EDIT", nullptr,
                                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE |
                                        ES_READONLY | WS_VSCROLL,
                                    0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)IDC_W_INFO,
                                    g.inst, nullptr);
      ::SendMessageW(info, WM_SETFONT, (WPARAM)g.monoFont, TRUE);
      g_watch.info = info;
      return 0;
    }

    case WM_SIZE: {
      RECT rc;
      ::GetClientRect(hwnd, &rc);
      const int pad = 6, bw = 132;
      int leftW = rc.right - bw - pad * 3;
      if (leftW < 140) leftW = 140;
      int listH = (int)((rc.bottom - pad * 3) * 0.60);
      ::MoveWindow(g_watch.list, pad, pad, leftW, listH, TRUE);
      ::MoveWindow(g_watch.info, pad, pad + listH + pad, leftW,
                   rc.bottom - listH - pad * 3, TRUE);
      int bx = pad + leftW + pad, by = pad;
      ::MoveWindow(g_watch.btnNop, bx, by, bw, 30, TRUE); by += 36;
      ::MoveWindow(g_watch.btnDis, bx, by, bw, 30, TRUE); by += 36;
      ::MoveWindow(g_watch.btnBp,  bx, by, bw, 30, TRUE); by += 36;
      ::MoveWindow(g_watch.btnRestore, bx, by, bw, 30, TRUE); by += 36;
      ::MoveWindow(g_watch.btnBypass, bx, by, bw, 30, TRUE); by += 36;
      ::MoveWindow(g_watch.btnAuto, bx, by, bw, 30, TRUE);
      ::MoveWindow(g_watch.btnStop, bx, rc.bottom - pad - 34, bw, 34, TRUE);
      return 0;
    }

    case WM_ERASEBKGND: {
      RECT rc;
      ::GetClientRect(hwnd, &rc);
      ::FillRect((HDC)wp, &rc, g_watch.bg ? g_watch.bg
                                          : (HBRUSH)(COLOR_BTNFACE + 1));
      return 1;
    }

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: {
      HDC dc = (HDC)wp;
      ::SetTextColor(dc, kListText);
      ::SetBkColor(dc, kListBg);
      if (g_watch.bg) return (LRESULT)g_watch.bg;
      break;
    }

    case WM_DRAWITEM: {
      DRAWITEMSTRUCT* ds = (DRAWITEMSTRUCT*)lp;
      if (ds->CtlType == 4 /*ODT_BUTTON*/) {
        DrawDarkButton(ds);
        return TRUE;
      }
      break;
    }

    case WM_NOTIFY: {
      NMHDR* nm = (NMHDR*)lp;
      if (nm->idFrom == IDC_W_LIST && g_watch.list) {
        if (nm->code == LVN_ITEMCHANGED) {
          if (!g_wNoInfo) {
            int row = (int)::SendMessageW(g_watch.list, LVM_GETNEXTITEM, (WPARAM)-1,
                                          MAKELPARAM(LVNI_SELECTED, 0));
            WatchShowInfo(row);
          }
        } else if (nm->code == NM_DBLCLK) {
          ::SendMessageW(hwnd, WM_COMMAND, IDC_W_DISASM, 0);
        }
      }
      break;
    }

    case WM_COMMAND: {
      const int selRow = g_watch.list
                             ? (int)::SendMessageW(g_watch.list, LVM_GETNEXTITEM,
                                                   (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0))
                             : -1;
      switch (LOWORD(wp)) {
        case IDC_W_STOP:
          if (g_watch.watching) WatchStopFind(L"已停止监控");
          else ::ShowWindow(hwnd, SW_HIDE);
          return 0;
        case IDC_W_DISASM:
          if (selRow >= 0 && selRow < (int)g_watch.rows.size()) {
            const ptruint a = g_watch.rows[selRow].rip;
            g.followRip = false;
            g.disasmBase = a;
            g.selAddr = a;
            if (!g.cpu || !::IsWindow(g.cpu))
              NewChild(kChildCpu, L"CPU — 反汇编 / 寄存器 / 数据 / 堆栈", kDefCpuW, kDefCpuH);
            UpdateCpuWindow();
            StatusText(ToW("已定位到 " + [&] {
              char b[32];
              std::snprintf(b, sizeof(b), "%012llX", (unsigned long long)a);
              return std::string(b);
            }()));
          }
          return 0;
        case IDC_W_NOP: {
          if (selRow < 0 || selRow >= (int)g_watch.rows.size()) return 0;
          const ptruint a = g_watch.rows[selRow].rip;
          int len = 0;
          for (size_t i = 0; i < g.disasmAddr.size(); ++i)
            if (g.disasmAddr[i] == a) { len = g.disasmLines[i].length; break; }
          if (len <= 0) {
            unsigned char code[16];
            SIZE_T got = g.proc.ReadPartial(a, code, sizeof(code));
            if (got) {
              DisasmResult dr;
              Disassemble(code, got, a, &dr);
              len = dr.length;
            }
          }
          if (len <= 0 || len > 64) {
            StatusText(L"无法确定指令长度，未替换");
            return 0;
          }
          std::vector<ubyte> nops((size_t)len, 0x90);
          size_t wr = 0;
          if (g.proc.Write(a, nops.data(), (size_t)len, &wr) && wr == (size_t)len) {
            StatusText(L"已替换为 NOP");
            {
              char b[32];
              std::snprintf(b, sizeof(b), "%012llX", (unsigned long long)a);
              AddLogLine(std::string("[监视] 替换为 NOP @ ") + b);
            }
            if (g.cpu && ::IsWindow(g.cpu)) { g.lastDisasmBase = 0; UpdateCpuWindow(); }
          } else {
            StatusText(L"替换失败");
          }
          return 0;
        }
        case IDC_W_BP: {
          if (selRow < 0 || selRow >= (int)g_watch.rows.size()) return 0;
          std::string err;
          g.dbg.SetInt3(g_watch.rows[selRow].rip, &err);
          StatusText(err.empty() ? L"已添加到断点列表" : ToW("失败: " + err));
          if (!err.empty()) ::MessageBoxW(hwnd, ToW(err).c_str(), L"提示", MB_OK);
          RefreshBpList();
          if (!g.bps || !::IsWindow(g.bps)) NewChild(kChildBps, L"断点 / 谁访问谁写入", kDefBpsW, kDefBpsH);
          return 0;
        }
        case IDC_W_BYPASS: {
          // 过检测/过CRC：从选中指令向后找第一条条件跳转（比对报警分支），
          // 按规则打掉（jne→NOP / je→jmp），并把完整写法（# 行）发输出
          // 窗口 + 剪贴板，方便照着手工复现/异地操作。
          if (selRow < 0 || selRow >= (int)g_watch.rows.size()) {
            StatusText(L"请先在列表里选中一条指令");
            return 0;
          }
          if (!g.proc.IsOpen()) return 0;
          const ptruint base = g_watch.rows[selRow].rip;
          unsigned char code[96];
          const SIZE_T got = g.proc.ReadPartial(base, code, sizeof(code));
          if (!got) { StatusText(L"指令地址不可读"); return 0; }

          char bBase[32], bJcc[32];
          std::snprintf(bBase, sizeof(bBase), "%012llX", (unsigned long long)base);

          std::string firstText;                 // 选中指令（通常是 cmp/test/累加）
          ptruint jccAddr = 0;
          int jccLen = 0;
          std::vector<ubyte> jccBytes, patch;
          std::string jccText, jccNote;

          for (size_t p = 0, idx = 0; p < got;) {
            DisasmResult dr;
            const int len = Disassemble(code + p, got - p, base + p, &dr);
            if (len <= 0) break;
            if (idx == 0) firstText = dr.text;
            const ubyte b0 = code[p];
            const bool j8  = (b0 >= 0x70 && b0 <= 0x7F);
            const bool j32 = (b0 == 0x0F && p + 1 < got &&
                              code[p + 1] >= 0x80 && code[p + 1] <= 0x8F);
            if (j8 || j32) {
              jccAddr = base + p;
              jccLen  = len;
              jccBytes.assign(code + p, code + p + (size_t)len);
              jccText = dr.text;
              if (b0 == 0x75) {                    // jne rel8：不相等才报警
                patch = {0x90, 0x90};
                jccNote = "jne → NOP（不相等才报警 → 永不报警）";
              } else if (b0 == 0x74) {             // je rel8：相等才走通过分支
                patch = jccBytes;
                patch[0] = 0xEB;
                jccNote = "je → jmp（永走通过分支）";
              } else if (j32 && code[p + 1] == 0x85) {
                patch.assign(6, 0x90);
                jccNote = "jne near → NOP×6（永不报警）";
              } else if (j32 && code[p + 1] == 0x84) {
                patch = jccBytes;                  // 0F 84 rel32 → E9 rel32
                patch.erase(patch.begin() + 1);
                patch[0] = 0xE9;
                int32_t rel;
                std::memcpy(&rel, &jccBytes[2], 4);
                ++rel;                             // 指令短 1 字节，位移 +1
                std::memcpy(&patch[1], &rel, 4);
                jccNote = "je near → jmp near（永走通过分支）";
              } else {                             // 其余 jcc：通用 NOP
                patch.assign((size_t)len, 0x90);
                jccNote = "jcc → NOP（注意：若该分支是「通过」分支，请改用反向补丁）";
              }
              break;
            }
            if (dr.isRet || dr.isInt3) break;
            ++idx;
            p += (size_t)len;
          }

          if (!jccAddr) {
            AddLogLine(std::string("# [过检测] ") + bBase +
                       " 起 96 字节内未找到条件跳转（比对分支），未动手");
            StatusText(L"未找到比对分支（jcc）");
            return 0;
          }
          std::snprintf(bJcc, sizeof(bJcc), "%012llX", (unsigned long long)jccAddr);
          auto hexOf = [](const std::vector<ubyte>& v) {
            std::string s;
            char t[8];
            for (ubyte x : v) { std::snprintf(t, sizeof(t), "%02X ", x); s += t; }
            return s;
          };
          PostRecipe({
            "==== 过检测/过CRC 写法 ====",
            std::string("比对指令: ") + bBase + "  " + firstText,
            std::string("报警分支: ") + bJcc + "  " + jccText +
                "  (" + hexOf(jccBytes) + ")",
            std::string("写入字节: ") + hexOf(patch) + " —— " + jccNote,
            std::string("手工操作: 把 ") + bJcc + " 起 " +
                std::to_string(jccLen) + " 字节改为 " + hexOf(patch),
          });
          // 动手：写回 + 回读校验（写法已同时进了输出窗口和剪贴板）
          size_t wr = 0;
          if (g.proc.Write(jccAddr, patch.data(), patch.size(), &wr) &&
              wr == patch.size()) {
            std::vector<ubyte> chk(patch.size(), 0);
            const size_t got2 = g.proc.ReadPartial(jccAddr, chk.data(), chk.size());
            if (got2 == chk.size() && chk == patch) {
              AddLogLine(std::string("[过检测] 已应用: ") + bJcc + "  " +
                         hexOf(jccBytes) + " → " + hexOf(patch));
              StatusText(L"过检测/过CRC 补丁已应用");
              if (g.cpu && ::IsWindow(g.cpu)) { g.lastDisasmBase = 0; UpdateCpuWindow(); }
            } else {
              AddLogLine(std::string("[过检测] ") + bJcc + " 写回后回读不一致");
            }
          } else {
            AddLogLine(std::string("[过检测] ") + bJcc + " 写回失败（页保护/权限）");
          }
          return 0;
        }
        case IDC_W_AUTORESTORE: {
          g_watch.autoRestore = !g_watch.autoRestore;
          ::SetWindowTextW(g_watch.btnAuto,
                           g_watch.autoRestore ? L"自动还原:开" : L"自动还原:关");
          StatusText(g_watch.autoRestore ? L"VM 自动还原：开（分析出 HOOK 后自动写回原始字节）"
                                         : L"VM 自动还原：关");
          return 0;
        }
        case IDC_W_RESTORE: {
          // 手动触发：对选中行强制重新分析还原字节（清掉“已分析”标记）
          if (selRow < 0 || selRow >= (int)g_watch.rows.size()) {
            StatusText(L"请先在列表里选中一条指令");
            return 0;
          }
          const ptruint a = g_watch.rows[selRow].rip;
          g_restoreAsked.erase(a);
          StartRestoreAnalyze(a);
          return 0;
        }
        default: break;
      }
      break;
    }

    case WM_CLOSE:
      if (g_watch.watching) WatchStopFind(L"已停止监控");
      // 与 CE 一致：隐藏而不销毁，随时可以再打开
      ::ShowWindow(hwnd, SW_HIDE);
      return 0;

    default: break;
  }
  return ::DefWindowProcW(hwnd, msg, wp, lp);
}

// 开始监视：write=监视写入，addr=0 时自动取当前选中地址
static bool StartWatch(bool write, ptruint addr) {
  if (!g.dbg.IsAttached()) {
    ::MessageBoxW(g.frame, L"请先通过 文件-附加进程 选择目标", L"提示",
                  MB_OK | MB_ICONINFORMATION);
    return false;
  }
  if (addr == 0) addr = PickWatchAddress();
  if (addr == 0) {
    ::MessageBoxW(g.frame,
                  L"请先在「内存搜索」结果列表或反汇编窗口里选中一个地址，"
                  L"然后在它上面点右键选择「查找写入/访问此地址的内容」",
                  L"提示", MB_OK | MB_ICONINFORMATION);
    return false;
  }

  if (g_watch.watching) g.dbg.StopFind();   // 同一时刻只保留一个监视（窗口共用）
  ++g_watchGen;                             // 开启新一轮：丢弃队列里上一轮的残留命中
  DropPendingHits();                        // 把上一轮积压的消息清空，新一轮结果立刻可见
  std::string err;
  // 过滤开关要**先于挂守卫**打开：守卫一挂上，调试线程立刻就会产生
  // 「守卫命中 AV + TF 单步」两类事件，晚一步打开就会有一批漏进日志。
  g_guardWatchAddr = addr;
  ::InterlockedExchange(&g_guardWatchOn, 1);
  const bool ok = write ? g.dbg.FindWhatWrites(addr, &err)
                        : g.dbg.FindWhatAccesses(addr, &err);
  if (!ok) {
    ::InterlockedExchange(&g_guardWatchOn, 0);
    ::MessageBoxW(g.frame, ToW(err.empty() ? "ä¸çè§å¤±è´¥" : err).c_str(), L"提示",
                  MB_OK | MB_ICONWARNING);
    return false;
  }

  if (!g_watchClassReg) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WatchProc;
    wc.hInstance = g.inst;
    wc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;   // 背景由 WM_ERASEBKGND 画
    wc.lpszClassName = kWatchClass;
    ::RegisterClassExW(&wc);
    g_watchClassReg = true;
  }
  if (!g_watch.wnd || !::IsWindow(g_watch.wnd)) {
    g_watch.wnd = ::CreateWindowExW(0, kWatchClass, L"以下操作码…",
                                    WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                    640, 430, g.frame, nullptr, g.inst, nullptr);
    if (!g_watch.wnd) {
      ::MessageBoxW(g.frame, L"创建监视窗口失败", L"提示", MB_OK | MB_ICONWARNING);
      return false;
    }
  }
  WatchClear();
  g_watch.write = write;
  g_watch.addr = addr;
  g_watch.watching = true;
  WatchSyncTitle();
  ::ShowWindow(g_watch.wnd, SW_SHOW);
  ::SetForegroundWindow(g_watch.wnd);

  char b[32];
  std::snprintf(b, sizeof(b), "%012llX", (unsigned long long)addr);
  AddLogLine(std::string(write ? "[监视] 谁写入 " : "[监视] 谁访问 ") + b +
             "（窗口：以下操作码" + (write ? "写入" : "访问") + "了 " + b + "）");
  StatusText(write ? L"正在监视写入..." : L"正在监视访问...");
  return true;
}

//=============================================================================
// 监视菜单命令（谁访问 / 谁写入 / 停止）
//=============================================================================
static void FindFromMenu(bool write) {
  // 优先用"当前选中地址"（扫描结果 / 反汇编锚点）——CE 就是右键地址即可监视，
  // 不再要求用户跑到断点窗口手打十六进制地址
  ptruint addr = PickWatchAddress();
  if (addr == 0 && g.bps && ::IsWindow(g.bps)) {
    std::string t = Trim(GetText(::GetDlgItem(g.bps, IDC_BADDR)));
    if (!t.empty()) addr = std::strtoull(t.c_str(), nullptr, 16);
  }
  if (addr == 0) {
    ::MessageBoxW(g.frame,
                  L"请先在「内存搜索」结果列表或反汇编窗口里选中要监视的地址，"
                  L"也可以直接在地址上点右键",
                  L"提示", MB_OK | MB_ICONINFORMATION);
    return;
  }
  StartWatch(write, addr);
}

//=============================================================================
// 框架窗口过程
//=============================================================================
static void ShowSettingsDlg(HWND parent);   // 界面设置窗口（定义在文件尾部）

//=============================================================================
// 启动窗口标题：每次启动随机 10 个字母
//   固定标题是个稳定特征 —— 窗口枚举、任务栏、日志里一眼可辨，也容易被按名字
//   针对性处理。改成每次启动随机 10 个字母，看起来就是个普通程序。
//   （随机数用自带 xorshift，种子混 时间+PID+性能计数器，避免同一时刻重启撞车；
//     可执行文件名仍是 CEScanGUI.exe，要改名是另一件事。）
//=============================================================================
static wchar_t g_titleTag[16] = L"CEScan";     // 10 字母 + 结束符（留余量）
static void MakeRandomTitleTag() {
  static const wchar_t kLetters[] =
      L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  LARGE_INTEGER pc{};
  ::QueryPerformanceCounter(&pc);
  unsigned long long s = (unsigned long long)::GetTickCount64() ^
                         ((unsigned long long)::GetCurrentProcessId() << 21) ^
                         (unsigned long long)pc.QuadPart;
  auto next = [&s]() {                        // xorshift64*
    s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
    return (unsigned)((s * 0x2545F4914F6CDD1DULL) >> 33);
  };
  for (int i = 0; i < 10; ++i) g_titleTag[i] = kLetters[next() % 52];
  g_titleTag[0] = kLetters[26 + next() % 26];      // 首字母大写：像个正常程序名
  g_titleTag[10] = 0;
}

// 组合并设置主窗口标题：
//   <随机10字母> —— [进程 - [PID x, 状态]]   （已附加时）
//   + " - 驱动已加载支持驱动调试" / " - 驱动未加载"   （JfDebug 设备在线状态）
//   + " - R0附加进程"                  （本次附加走了驱动内核态路径）
//   未附加时标题就是那 10 个随机字母本身（不暴露工具身份）
static void RefreshFrameTitle(HWND hwnd) {
  wchar_t ttl[560];
  if (g.dbg.IsAttached()) {
    wchar_t base[384];
    std::swprintf(base, 384, L"%s —— [%s - [PID %u, %s]] | By:Jin", g_titleTag,
                  g.proc.Name().c_str(), g.dbg.Pid(),
                  g.uiRunning ? L"运行中" : L"已暂停");
    std::swprintf(ttl, 560, L"%s - %s%s", base,
                  g.driverLoaded ? L"驱动已加载支持驱动调试" : L"驱动未加载",
                  g.dbg.DriverAttachUsed() ? L" - R0附加进程" : L"");
  } else {
    std::swprintf(ttl, 560, L"%s", g_titleTag);
  }
  ::SetWindowTextW(hwnd, ttl);
}

static LRESULT CALLBACK FrameProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE: {
      g.frame = hwnd;
      // 「线程定位」工具窗口：注入宿主环境（窗口句柄 / 调试引擎 / 主题 / 回调）。
      // 该模块自成一体（src/ThreadLocator.cpp），不碰主程序的静态全局，
      // 所以这里只要把句柄和颜色交过去，之后靠 TlOnHit 转发命中即可。
      {
        ce::TlHost tl;
        tl.frame = hwnd;
        tl.inst  = g.inst;
        tl.dbg   = &g.dbg;
        tl.bg     = kUiBg;        tl.fg     = kUiText;
        tl.panel  = kPanelBg;
        tl.editBg = kEditBg;      tl.editFg = kEditText;
        tl.listBg = kListBg;      tl.listFg = kListText;
        tl.edge   = kSplitBorder; tl.dim    = kUiTextDim;
        tl.hot    = RGB(255, 96, 96);
        tl.warn   = kWatchOrange;
        ::lstrcpynW(tl.uiFont, kFontUiName, 32);
        ::lstrcpynW(tl.monoFont, kFontMonoName, 32);
        tl.uiFontH   = kFontUiHeight;
        tl.monoFontH = kFontMonoHeight;
        tl.status = [](const wchar_t* s) { StatusText(s); };
        tl.log    = [](const std::string& s) { AddLogLine(s); };
        ce::TlInit(tl);
      }
      CreateFrameToolbar(hwnd);  // 仿 x64dbg 工具栏（在 MDI client 之前创建）
      CLIENTCREATESTRUCT ccs{};
      // 窗口菜单 = 菜单栏第 6 项（文件0/查看1/调试2/插件3/选项4/窗口5）
      ccs.hWindowMenu = ::GetSubMenu(::GetMenu(hwnd), 5);  // 窗口菜单
      ccs.idFirstChild = 0x1000;
      g.client = ::CreateWindowExW(0, L"MDICLIENT", nullptr,
                                   WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN |
                                       WS_VSCROLL | WS_HSCROLL,
                                   0, 0, 0, 0, hwnd, (HMENU)1, g.inst, &ccs);

      // 打开默认窗口 —— 必须等主窗口完成布局后再创建（此时 MDI client 还是 0x0，
      // 立即创建会被钳制成 136x39 的最小尺寸且无法恢复）
      ::PostMessageW(hwnd, WM_APP_INIT, 0, 0);

      ::SetTimer(hwnd, 1, 500, nullptr);
      ::SetTimer(hwnd, 2, 3000, nullptr);   // 驱动在线轮询（\\.\JfDebug）
      g.driverLoaded = ce::JfDriverLoaded();
      RefreshFrameTitle(hwnd);              // 启动即显示一次驱动状态
      StatusText(L"就绪 —— 请通过 文件-附加进程 开始");
      return 0;
    }

    case WM_APP_INIT: {
      if (g.cpu || g.scanWnd) return 0;  // 防止重复
      NewChild(kChildCpu, L"CPU — 反汇编 / 寄存器 / 数据 / 堆栈", kDefCpuW, kDefCpuH);
      NewChild(kChildScan, L"内存搜索", kDefScanW, kDefScanH);
      NewChild(kChildBps, L"断点 / 谁访问谁写入", kDefBpsW, kDefBpsH);
      NewChild(kChildLog, L"日志", kDefLogW, kDefLogH);
      NewChild(kChildMcp, L"MCP 输出栏", kDefMcpW, kDefMcpH);
      NewChild(kChildStrs, L"字符串搜索引擎", kDefStrsW, kDefStrsH);
      NewChild(kChildMap, L"内存区域枚举", kDefMapW, kDefMapH);
      NewChild(kChildThreads, L"线程", kDefThrW, kDefThrH);
      ::SendMessageW(g.client, WM_MDICASCADE, 0, 0);
      return 0;
    }

    case WM_TIMER:
      if (wp == 2) {                       // 3s 一次：驱动在线检测 + 标题刷新
        g.driverLoaded = ce::JfDriverLoaded();
        RefreshFrameTitle(hwnd);
        break;
      }
      if (wp == 1 && g.dbg.IsAttached()) {
        UpdateCpuWindow();
        wchar_t buf[256];
        std::swprintf(buf, 256, L"目标: PID %u    [%s]", g.dbg.Pid(),
                      g.uiRunning ? L"运行中" : L"已暂停");
        StatusText(buf);
        RefreshFrameTitle(hwnd);           // 仿 x64dbg 标题栏 + 驱动/R0 附加状态
      }
      break;

    case WM_COMMAND: {
      UiTrace("FrameProc WM_COMMAND id=" + std::to_string((unsigned)LOWORD(wp)));
      switch (LOWORD(wp)) {
        case IDM_ATTACH: UiTrace("IDM_ATTACH -> AttachProcess"); AttachProcess(hwnd); break;
        case IDM_DETACH: DetachProcess(); break;
        case IDM_EXIT: ::DestroyWindow(hwnd); break;
        case IDM_RUN: g.dbg.Run(); g.uiRunning = true; break;
        case IDM_PAUSE:
          // 暂停不强制跟随 RIP：视口保持原地（RIP 行仍高亮），OD 式"停住不走"
          g.dbg.Pause(); g.uiRunning = false;
          UpdateCpuWindow();
          break;
        case IDM_STEPIN:
          g.followRip = true;
          g.dbg.StepInto(); g.uiRunning = false;
          ::Sleep(120);
          UpdateCpuWindow();
          break;
        case IDM_STEPOVER:
          g.followRip = true;
          g.dbg.StepOver(); g.uiRunning = false;
          ::Sleep(120);
          UpdateCpuWindow();
          break;
        case IDM_RUNTORET:
          g.dbg.ExecuteUntilReturn(); g.uiRunning = false;
          ::Sleep(150);
          UpdateCpuWindow();
          break;
        case IDM_TOGGLEBP: ToggleBpOnSelectedLine(); break;
        case IDM_FINDACCESS: FindFromMenu(false); break;
        case IDM_FINDWRITE: FindFromMenu(true); break;
        case IDM_STOPFIND: WatchStopFind(L"已停止监控"); break;
        // 「窗口」菜单切换：不存在则创建，已存在则激活到前台
        case IDM_VIEW_CPU:
          if (!g.cpu) NewChild(kChildCpu, L"CPU", kDefCpuW, kDefCpuH);
          else ::SendMessageW(g.client, WM_MDIACTIVATE, (WPARAM)g.cpu, 0);
          break;
        case IDM_VIEW_SCAN:
          if (!g.scanWnd) NewChild(kChildScan, L"内存搜索", kDefScanW, kDefScanH);
          else ::SendMessageW(g.client, WM_MDIACTIVATE, (WPARAM)g.scanWnd, 0);
          break;
        case IDM_VIEW_MAP:
          if (!g.map) NewChild(kChildMap, L"内存区域枚举", kDefMapW, kDefMapH);
          else ::SendMessageW(g.client, WM_MDIACTIVATE, (WPARAM)g.map, 0);
          break;
        case IDM_VIEW_THREADS:
          if (!g.thr) NewChild(kChildThreads, L"线程", kDefThrW, kDefThrH);
          else ::SendMessageW(g.client, WM_MDIACTIVATE, (WPARAM)g.thr, 0);
          break;
        case IDM_VIEW_BPS:
          if (!g.bps) NewChild(kChildBps, L"断点", kDefBpsW, kDefBpsH);
          else ::SendMessageW(g.client, WM_MDIACTIVATE, (WPARAM)g.bps, 0);
          break;
        case IDM_VIEW_LOG:
          if (!g.log) NewChild(kChildLog, L"日志", kDefLogW, kDefLogH);
          else ::SendMessageW(g.client, WM_MDIACTIVATE, (WPARAM)g.log, 0);
          break;
        case IDM_VIEW_LOGDATA:
          if (!g.logData) NewChild(kChildLogData, L"日志数据", kDefLogDW, kDefLogDH);
          else ::SendMessageW(g.client, WM_MDIACTIVATE, (WPARAM)g.logData, 0);
          FlushPendingLogData();
          break;
        case IDM_VIEW_MCP:
          if (!g.mcp) NewChild(kChildMcp, L"MCP 输出栏", kDefMcpW, kDefMcpH);
          else ::SendMessageW(g.client, WM_MDIACTIVATE, (WPARAM)g.mcp, 0);
          break;
        case IDM_VIEW_TLOC: ce::TlOpen(); break;
        case IDM_MCP_CONNECT: McpConnect(); break;
        case IDM_MCP_DISCONNECT: McpDisconnect(); break;
        case IDM_MCP_PING: McpSendCmd("ping"); break;
        case IDM_MCP_PROCINFO: McpSendCmd("get_process_info"); break;
        case IDM_DBVM_DETECT: DbvmDetectDialog(); break;
        case IDM_DBVM_LOAD: LoadDbvmDialog(); break;
        case IDM_DBVM_UNLOAD: UnloadDbvmDialog(); break;
        case IDM_DBVM_BP: DbvmBreak(); break;
        case IDM_DBVM_BP_RESUME: DbvmResumeAll(); break;
        case IDM_DBVM_BP_CLEAR: DbvmClearBp(); break;
        case IDM_DBVM_CLOAK: DbvmProtectAddr(); break;
        case IDM_DBVM_CLOAK_OFF: DbvmUnprotectAddr(); break;
        case IDM_DBVM_HIDE_MEM: DbvmHideMemory(); break;
        case IDM_DBVM_CR_ON: DbvmChangeRegOnBp(); break;
        case IDM_DBVM_CR_OFF: DbvmRemoveChangeReg(); break;
        case IDM_DBVM_TRACE_ON: DbvmTraceOnBp(); break;
        case IDM_DBVM_TRACE_STOP: DbvmTraceStop(); break;
        case IDM_DBVM_TRACE_LOG: DbvmTraceLog(); break;
        case IDM_DBVM_PHYSMEM: DbvmPhysView(); break;
        case IDM_DBVM_KPROT: DbvmKernelProt(); break;
        case IDM_APB_STRING: ApbApply(0); break;
        case IDM_APB_MSGBOX: ApbApply(1); break;
        case IDM_APB_DIALOG: ApbApply(2); break;
        case IDM_APB_FILE: ApbApply(3); break;
        case IDM_APB_LIB: ApbApply(4); break;
        case IDM_APB_MEM: ApbApply(5); break;
        case IDM_APB_REG: ApbApply(6); break;
        case IDM_APB_DIR: ApbApply(7); break;
        case IDM_APB_DRIVE: ApbApply(8); break;
        case IDM_APB_TIME: ApbApply(9); break;
        case IDM_APB_MISC: ApbApply(10); break;
        case IDM_APB_VB: ApbApply(11); break;
        case IDM_APB_CUSTOM: ApbApply(12); break;
        case IDM_APB_CLEAR: ApbClearAll(); break;
        case IDM_VIEW_STRS:
          if (!g.strs) NewChild(kChildStrs, L"字符串搜索引擎", kDefStrsW, kDefStrsH);
          else ::SendMessageW(g.client, WM_MDIACTIVATE, (WPARAM)g.strs, 0);
          break;
        case IDM_STR_ASCII: StrSearchRun(0); break;
        case IDM_STR_UNICODE: StrSearchRun(1); break;
        case IDM_STR_SMART: StrSearchRun(2); break;
        case IDM_STR_CHS:
          // 强制中文：临时把 requireChinese 打开（通过 mode=3 标记）
          if (g.proc.IsOpen()) {
            g.strSearchRunning = false;
            g.strMode = 3;
            g.strHits.clear();
            StrStatusText(L"字符串搜索引擎: 扫描中(仅含中文)...");
            std::thread([]() {
              ce::StrSearchOptions opt;
              opt.mode = 2;
              opt.requireChinese = true;
              std::vector<ce::StrHit> hits;
              std::string err;
              ce::StrSearch::Run(g.proc.Handle(), opt, hits,
                                 [](int) { return true; }, &err);
              ::PostMessageW(g.frame, WM_APP_STR_DONE, 1,
                             (LPARAM)new std::vector<ce::StrHit>(std::move(hits)));
            }).detach();
            g.strSearchRunning = true;
          }
          break;
        case IDM_CASCADE: ::SendMessageW(g.client, WM_MDICASCADE, 0, 0); break;
        case IDM_TILE: ::SendMessageW(g.client, WM_MDITILE, MDITILE_HORIZONTAL, 0); break;
        case IDM_CLOSEALL: {
          // EnumMDIChild 关闭
          HWND c = (HWND)::SendMessageW(g.client, WM_MDIGETACTIVE, 0, 0);
          (void)c;
          for (int i = 0; i < 20; ++i) {
            HWND active = (HWND)::SendMessageW(g.client, WM_MDIGETACTIVE, 0, 0);
            if (active == nullptr) break;
            ::SendMessageW(g.client, WM_MDIDESTROY, (WPARAM)active, 0);
          }
          break;
        }
        case IDM_SETTINGS: ShowSettingsDlg(hwnd); break;
        case IDM_ABOUT:
          ::MessageBoxW(hwnd,
                        L"仿CE/OD的小工具",
                        L"关于", MB_OK | MB_ICONINFORMATION);
          break;
      }
      break;
    }

    case WM_NOTIFY: {
      // 工具栏气泡提示已改为工具栏自绘窗口内部手工 TRACK（见 ToolbarProc），
      // 这里不再需要 TTN_GETDISPINFO 分支。
      break;
    }

    case WM_APP_HIT: {
      if (g_hitInFlight.load() > 0) --g_hitInFlight;
      HitReport* hit = (HitReport*)lp;
      if (hit) {
        // 页面守卫（谁访问/谁写入）命中来自异步排队的消息：如果轮次号对不上，
        // 说明它是上一轮看完/停止后残留在队列里的，直接丢弃，别污染新列表。
        const bool guardHit = (hit->kind == ce::BpKind::Access ||
                               hit->kind == ce::BpKind::Write);
        if (guardHit && (unsigned)wp != g_watchGen.load()) { delete hit; return 0; }
        // 「线程定位」窗口优先消化本次硬件断点命中：它自己按 (线程ID, 指令地址)
        // 聚合，并且只对新出现的行做一次反汇编。热点函数上的硬件访问断点每秒能命中
        // 上千次，如果照样走下面的"逐条反汇编 + 插行"路径，UI 会被灌死。
        if (ce::TlOnHit(*hit)) { delete hit; return 0; }
        FillHitDisasm(*hit);
        AppendHitRow(*hit);
        WatchAddHit(*hit);          // CE 风格聚合窗口（计数 | 指令地址 | 指令）
        delete hit;
        g.uiRunning = false;
        UpdateCpuWindow();
      }
      return 0;
    }

    case WM_APP_LOG: {
      std::string* line = (std::string*)lp;
      if (line) {
        // 日志窗口还没打开时先攒着（g.log 建好后由 FlushPendingLog 补写），
        // 否则这些行会被静默丢弃 —— 还原分析结果就全丢了，用户根本看不到。
        if ((!g.log || !IsWindow(g.log)) && g_pendingLog.size() < 4000) {
          g_pendingLog.push_back(*line);
          delete line;
          return 0;
        }
        if (g.log && IsWindow(g.log)) {
          HWND list = Ctrl(g.log, IDC_LOGLIST);
          int idx = (int)::SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)ToW(*line).c_str());
          ::SendMessageW(list, LB_SETTOPINDEX, idx, 0);
          const int n = (int)::SendMessageW(list, LB_GETCOUNT, 0, 0);
          if (n > 3000) ::SendMessageW(list, LB_DELETESTRING, 0, 0);
          FlushPendingLog();          // 窗口终于有了，把之前攒下的行补进去
        }
        delete line;
      }
      return 0;
    }

    case WM_APP_LOGDATA: {
      // 日志数据窗口（OD Log data）行：地址|消息 已拼好，直接入列表
      std::wstring* line = (std::wstring*)lp;
      if (line) {
        if ((!g.logData || !IsWindow(g.logData)) && g_pendingLogData.size() < 4000) {
          g_pendingLogData.push_back(*line);
          delete line;
          return 0;
        }
        if (g.logData && IsWindow(g.logData)) {
          HWND list = Ctrl(g.logData, IDC_LDLIST);
          int idx = (int)::SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)line->c_str());
          ::SendMessageW(list, LB_SETTOPINDEX, idx, 0);
          const int n = (int)::SendMessageW(list, LB_GETCOUNT, 0, 0);
          if (n > 5000) ::SendMessageW(list, LB_DELETESTRING, 0, 0);
          FlushPendingLogData();
        }
        delete line;
      }
      return 0;
    }

    case WM_APP_RESTORE: {
      // HOOK/VM 还原分析结果（后台线程回传）
      ce::RestoreResult* r = (ce::RestoreResult*)lp;
      RTrace("MSG     %llX", r ? (unsigned long long)r->addr : 0);
      if (r) {
        // 1) 监视窗口「还原字节」列回填
        auto it = g_watch.index.find(r->addr);
        if (it != g_watch.index.end() && it->second < (int)g_watch.rows.size() &&
            g_watch.list && ::IsWindow(g_watch.list)) {
          std::wstring txt;
          if (r->found)       txt = ToW(r->origHex);
          else if (r->isHook) txt = L"(未找到)";
          else                 txt = L"—";
          g_watch.rows[it->second].restore = txt;
          LVITEMW s{};
          s.mask = LVIF_TEXT;
          s.iItem = it->second;
          s.iSubItem = 3;
          s.pszText = const_cast<LPWSTR>(txt.c_str());
          ::SendMessageW(g_watch.list, LVM_SETITEMW, s.iItem, (LPARAM)&s);
        }
        // 2) 输出窗口：单行摘要 + 多行详情（一行一条，别把列表框撑爆）
        AddLogLine(ce::FormatRestoreLine(*r));
        {
          std::string detail = ce::FormatRestoreDetail(*r);
          if (!detail.empty()) {
            size_t pos = 0, prev = 0;
            while (prev < detail.size()) {
              pos = detail.find("\r\n", prev);
              if (pos == std::string::npos) pos = detail.size();
              std::string one = detail.substr(prev, pos - prev);
              if (!one.empty()) AddLogLine(one);
              prev = pos + 2;
            }
          }
        }
        RTrace("col+log ok %llX", (unsigned long long)r->addr);
        // 3) 本地记录文件（还原记录_YYYYMMDD_HHMMSS.txt，每行带时间戳）
        if (g_restoreJournal.Open()) {
          g_restoreJournal.Write(ce::FormatRestoreLine(*r));
          g_restoreJournal.WriteRaw(ce::FormatRestoreDetail(*r));
        }
        // 2b) 「VM还原 写法」块：判定为 HOOK 且找到还原字节时，
        //     把手工复现步骤（# 行）发输出窗口 + 剪贴板 + 还原记录文件
        if (r->isHook && r->found) {
          const std::string rr = ce::FormatRestoreRecipe(*r);
          std::vector<std::string> recipe;
          size_t pos2 = 0, prev2 = 0;
          while (prev2 < rr.size()) {
            pos2 = rr.find("\r\n", prev2);
            if (pos2 == std::string::npos) pos2 = rr.size();
            const std::string one = rr.substr(prev2, pos2 - prev2);
            if (!one.empty()) recipe.push_back(one);
            prev2 = pos2 + 2;
          }
          if (!recipe.empty()) PostRecipe(recipe);
          if (g_restoreJournal.IsOpen())
            g_restoreJournal.WriteRaw(ce::FormatRestoreRecipe(*r));
        }
        RTrace("journal ok %llX", (unsigned long long)r->addr);
        // 4) VM 自动还原：判定为 HOOK 且拿到还原字节 → 自动写回目标进程
        //    （开关在监视窗口「自动还原:开/关」，默认开；判定 HOOK 但没找到
        //      还原字节时不动手，等用户手动处理）
        if (r->isHook && r->found && !r->origBytes.empty() && g_watch.autoRestore)
          DoAutoRestore(*r);
        delete r;
      }
      return 0;
    }

    case WM_APP_MCP_LOG: {
      std::string* line = (std::string*)lp;
      if (line) {
        if (g.mcp && IsWindow(g.mcp)) {
          HWND list = Ctrl(g.mcp, IDC_MCP_LOG);
          int idx = (int)::SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)ToW(*line).c_str());
          ::SendMessageW(list, LB_SETTOPINDEX, idx, 0);
          const int n = (int)::SendMessageW(list, LB_GETCOUNT, 0, 0);
          if (n > 3000) ::SendMessageW(list, LB_DELETESTRING, 0, 0);
        }
        delete line;
      }
      return 0;
    }

    case WM_APP_STR_DONE: {
      auto* hits = (std::vector<ce::StrHit>*)lp;
      if (hits) {
        if (wp == 1) {
          g.strHits = std::move(*hits);
          RefreshStrList();
          AddLogLine("[搜索引擎] 完成，共 " + std::to_string(g.strHits.size()) + " 条");
        } else {
          StrStatusText(L"中文搜索引擎: 扫描失败");
        }
        delete hits;
      }
      g.strSearchRunning = false;
      return 0;
    }

    case WM_APP_MCP_STATUS:
      McpUpdateStatusPart();
      if (wp == 0) AddLogLine("[MCP] 连接已断开");
      return 0;

    case WM_APP_SCAN_PRG: {
      std::unique_ptr<ScanPctMsg> pm(static_cast<ScanPctMsg*>(reinterpret_cast<void*>(lp)));
      if (!pm) return 0;
      // 进度条范围 0..1000，按字节比例换算，避免超大 total 溢出
      if (g.scanWnd && IsWindow(g.scanWnd)) {
        HWND prog = Ctrl(g.scanWnd, IDC_PROG);
        if (pm->total == 0) {  // 起始哨兵：区域清单尚未建好，只给“正在扫描”反馈
          ::SetWindowTextW(Ctrl(g.scanWnd, IDC_COUNT), L"正在扫描… 建立区域清单");
          ::SendMessageW(prog, PBM_SETPOS, 0, 0);
        } else {
          const qword total = pm->total > 0 ? pm->total : 1;
          int pos = static_cast<int>((pm->scanned * 1000ULL) / total);
          if (pos > 1000) pos = 1000;
          ::SendMessageW(prog, PBM_SETPOS, static_cast<WPARAM>(pos), 0);
          if (pm->scanned > 0 && pm->scanned < pm->total) {
            wchar_t s[128];
            std::swprintf(s, 128, L"正在扫描… 已处理 %I64u / %I64u 字节",
                          (unsigned long long)pm->scanned, (unsigned long long)pm->total);
            ::SetWindowTextW(Ctrl(g.scanWnd, IDC_COUNT), s);
          }
        }
      }
      return 0;
    }

    case WM_APP_SCAN_DONE:
      if (g.scanWnd && IsWindow(g.scanWnd)) RefreshResultList(g.scanWnd);
      if (wp == 0) StatusText(L"扫描失败");
      else StatusText(L"扫描完成");
      return 0;

    case WM_APP_SCAN_ERR: {
      std::string* err = (std::string*)lp;
      if (err) {
        // err 是 UTF-8 字符串，MessageBoxA 按 ANSI(GBK) 解读会乱码，先转宽字符
      ::MessageBoxW(hwnd, ce::util::Utf8ToWide(err->c_str()).c_str(), L"扫描错误", MB_OK | MB_ICONWARNING);
        delete err;
      }
      return 0;
    }

    case WM_SIZE: {
      // 布局：工具栏(顶) + MDI 客户区(中) + 状态栏(底)
      int tbH = 0;
      const int cw = LOWORD(lp), ch = HIWORD(lp);
      if (g.toolbar && ::IsWindow(g.toolbar)) {
        // 自绘工具栏：高度固定，宽度跟随窗口；先按新宽度重排（必要则收缩按钮），
        // 保证末尾的金色按钮组不会被裁掉。
        tbH = kTbHeight;
        TbLayout(cw);
        ::MoveWindow(g.toolbar, 0, 0, cw, tbH, TRUE);
        ::InvalidateRect(g.toolbar, nullptr, FALSE);
      }
      int stH = 0;
      if (g.status && ::IsWindow(g.status)) {
        ::SendMessageW(g.status, WM_SIZE, 0, 0);
        RECT sr;
        ::GetWindowRect(g.status, &sr);
        stH = sr.bottom - sr.top;
      }
      const int clientH = ch - tbH - stH;
      if (g.client && ::IsWindow(g.client))
        ::MoveWindow(g.client, 0, tbH, cw, clientH > 0 ? clientH : 1, TRUE);
      // 状态栏两段：主状态 | MCP 状态
      if (g.status && ::IsWindow(g.status)) {
        int parts[3] = { cw - 660, cw - 280, -1 };
        ::SendMessageW(g.status, SB_SETPARTS, 3, (LPARAM)parts);
      }
      return 0;
    }

    case WM_DESTROY:
      ::KillTimer(hwnd, 1);
      ce::TlShutdown();     // 先摘硬件断点、关窗口，再断调试会话
      g.mcpClient.Disconnect();
      g.dbg.Detach();
      ::PostQuitMessage(0);
      return 0;
  }
  return ::DefFrameProcW(hwnd, g.client, msg, wp, lp);
}

//=============================================================================
// ---------------------------------------------------------------------------
//  崩溃日志：GUI 是窗口程序，崩了什么也看不到。
//  这里把异常地址与调用栈（相对模块基址的偏移）写进 CEScanVC/crash.txt，
//  配合链接时生成的 obj_gui/*.map 就能定位到具体函数。
// ---------------------------------------------------------------------------
static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep) {
  static LONG s_busy = 0;
  if (::InterlockedExchange(&s_busy, 1)) return EXCEPTION_EXECUTE_HANDLER;
  FILE* f = ::fopen("crash.txt", "ab");
  if (f) {
    const DWORD code = ep->ExceptionRecord
                           ? ep->ExceptionRecord->ExceptionCode
                           : 0;
    const ptruint base = (ptruint)::GetModuleHandleW(nullptr);
    const ptruint rip =
        ep->ContextRecord ? (ptruint)ep->ContextRecord->Rip : 0;
    const ptruint fault = (ep->ExceptionRecord &&
                           ep->ExceptionRecord->NumberParameters >= 2)
                              ? (ptruint)ep->ExceptionRecord->ExceptionInformation[1]
                              : 0;
    // 读/写？ 0=读 1=写 8=DEP
    const ptruint rw = (ep->ExceptionRecord &&
                        ep->ExceptionRecord->NumberParameters >= 1)
                           ? (ptruint)ep->ExceptionRecord->ExceptionInformation[0]
                           : 99;
    wchar_t modPath[MAX_PATH] = L"?";
    ptruint modBase = 0;
    HMODULE hMod = nullptr;
    if (rip && ::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                    (LPCWSTR)rip, &hMod)) {
      ::GetModuleFileNameW(hMod, modPath, MAX_PATH);
      modBase = (ptruint)hMod;
    }
    std::fprintf(f, "==== crash code=0x%08X  %s 地址 0x%llX\n",
                 (unsigned)code, rw == 1 ? "写" : (rw == 0 ? "读" : "执行"),
                 (unsigned long long)fault);
    std::fprintf(f, "  RIP=0x%llX  模块=%ls  (mod+0x%llX)\n",
                 (unsigned long long)rip, modPath,
                 (unsigned long long)(rip && modBase ? rip - modBase : 0));
    std::fprintf(f, "  本模块 base=0x%llX\n", (unsigned long long)base);
    void* frames[24];
    const USHORT n = ::RtlCaptureStackBackTrace(0, 24, frames, nullptr);
    for (USHORT i = 0; i < n; ++i) {
      const ptruint a = (ptruint)frames[i];
      std::fprintf(f, "  #%-2u 0x%llX  (base+0x%llX)\n", (unsigned)i,
                   (unsigned long long)a,
                   (unsigned long long)(a > base ? a - base : a));
    }
    std::fclose(f);
  }
  return EXCEPTION_EXECUTE_HANDLER;
}


//=============================================================================
// 界面设置窗口（选项(T)-界面设置）：代码高亮颜色可配置 + INI 持久化 + 启动复原
// 左侧为全部主题颜色项列表（反汇编/堆栈/寄存器/控件），选中后改色即时生效；
// 确定/应用写入 CEScanGUI.ini，下次启动自动复原。
//=============================================================================
static const wchar_t* kSetDlgClass = L"CEScanSettingsDlg";
static int g_setCur = 0;
static HWND g_setList = nullptr, g_setSwatch = nullptr;
static HWND g_setChkOperands = nullptr;

static bool PickColor(HWND parent, COLORREF* c) {
  static COLORREF custom[16] = {};
  CHOOSECOLORW cc{};
  cc.lStructSize = sizeof(cc);
  cc.hwndOwner = parent;
  cc.lpCustColors = custom;
  cc.rgbResult = *c;
  cc.Flags = CC_FULLOPEN | CC_RGBINIT;
  if (!::ChooseColorW(&cc)) return false;
  *c = cc.rgbResult;
  return true;
}

static BOOL CALLBACK ThemeEnumInval(HWND h, LPARAM) {
  ::InvalidateRect(h, nullptr, TRUE);
  return TRUE;
}

// 主题变更后让所有窗口立即重绘
static void ApplyThemeLive() {
  if (g.frame && IsWindow(g.frame)) {
    ::EnumChildWindows(g.frame, ThemeEnumInval, 0);
    ::InvalidateRect(g.frame, nullptr, TRUE);
  }
}

// 当前选中项的颜色（供色块绘制）
static COLORREF SetCurColor() {
  if (g_setCur < 0 || g_setCur >= kThemeFieldCount) return RGB(0, 0, 0);
  return g_theme.*(kThemeFields[g_setCur].p);
}

static LRESULT CALLBACK SettingsProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE: {
      auto mk = [&](int id, const wchar_t* cls, const wchar_t* text, DWORD style,
                    int x, int y, int w, int h) {
        return ::CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style,
                                 x, y, w, h, hwnd, (HMENU)(INT_PTR)id, g.inst, nullptr);
      };
      // 左侧：主题颜色项列表
      g_setList = mk(101, L"LISTBOX", nullptr,
                     WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
                     10, 10, 300, 380);
      for (int i = 0; i < kThemeFieldCount; ++i)
        ::SendMessageW(g_setList, LB_ADDSTRING, 0, (LPARAM)kThemeFields[i].label);
      ::SendMessageW(g_setList, LB_SETCURSEL, 0, 0);
      // 右侧：色块 + 改色按钮
      mk(0, L"STATIC", L"当前颜色：", SS_LEFT, 330, 14, 90, 20);
      g_setSwatch = mk(104, L"STATIC", nullptr, WS_BORDER | SS_NOTIFY, 330, 36, 140, 28);
      mk(102, L"BUTTON", L"修改颜色...", BS_PUSHBUTTON, 330, 76, 140, 28);
      mk(106, L"BUTTON", L"恢复此项默认", BS_PUSHBUTTON, 330, 116, 140, 28);
      mk(107, L"BUTTON", L"恢复全部默认", BS_PUSHBUTTON, 330, 152, 140, 28);
      g_setChkOperands = mk(108, L"BUTTON", L"高亮操作数", BS_AUTOCHECKBOX,
                            330, 192, 140, 20);
      ::SendMessageW(g_setChkOperands, BM_SETCHECK,
                     g_theme.highlightOperands ? BST_CHECKED : BST_UNCHECKED, 0);
      mk(0, L"STATIC", L"确定=保存到 CEScanGUI.ini 并关闭；\n应用=保存不关闭；\n下次启动自动复原设置。",
         SS_LEFT, 330, 224, 160, 80);
      mk(IDOK, L"BUTTON", L"确定", BS_DEFPUSHBUTTON, 220, 398, 90, 28);
      mk(IDABORT, L"BUTTON", L"应用", BS_PUSHBUTTON, 320, 398, 90, 28);
      mk(IDCANCEL, L"BUTTON", L"取消", BS_PUSHBUTTON, 420, 398, 90, 28);
      ::SendMessageW(g_setList, WM_SETFONT, (WPARAM)g.uiFont, TRUE);
      return 0;
    }

    case WM_COMMAND: {
      const int id = LOWORD(wp);
      if (id == 101 && HIWORD(wp) == LBN_SELCHANGE) {
        g_setCur = (int)::SendMessageW(g_setList, LB_GETCURSEL, 0, 0);
        ::InvalidateRect(g_setSwatch, nullptr, TRUE);
        return 0;
      }
      if ((id == 102 || id == 104) && g_setCur >= 0) {   // 改色（按钮或点色块）
        COLORREF c = SetCurColor();
        if (PickColor(hwnd, &c)) {
          g_theme.*(kThemeFields[g_setCur].p) = c;
          ::InvalidateRect(g_setSwatch, nullptr, TRUE);
          ApplyThemeLive();
        }
        return 0;
      }
      if (id == 106) {                                   // 恢复此项默认
        ThemeColors d = DefaultTheme();
        if (g_setCur >= 0 && g_setCur < kThemeFieldCount)
          g_theme.*(kThemeFields[g_setCur].p) = d.*(kThemeFields[g_setCur].p);
        ::InvalidateRect(g_setSwatch, nullptr, TRUE);
        ApplyThemeLive();
        return 0;
      }
      if (id == 107) {                                   // 恢复全部默认
        g_theme = DefaultTheme();
        ::SendMessageW(g_setChkOperands, BM_SETCHECK,
                       g_theme.highlightOperands ? BST_CHECKED : BST_UNCHECKED, 0);
        ::InvalidateRect(g_setSwatch, nullptr, TRUE);
        ApplyThemeLive();
        return 0;
      }
      if (id == 108 && HIWORD(wp) == BN_CLICKED) {       // 高亮操作数开关
        g_theme.highlightOperands =
            ::SendMessageW((HWND)lp, BM_GETCHECK, 0, 0) == BST_CHECKED;
        ApplyThemeLive();
        return 0;
      }
      if (id == IDOK) {                                  // 确定：保存+关闭
        ThemeSaveIni();
        ::DestroyWindow(hwnd);
        return 0;
      }
      if (id == IDABORT) {                               // 应用：保存不关闭
        ThemeSaveIni();
        StatusText(L"界面设置已保存到 CEScanGUI.ini");
        return 0;
      }
      if (id == IDCANCEL) { ::DestroyWindow(hwnd); return 0; }
      break;
    }
    case WM_CTLCOLORSTATIC: {
      HDC dc = (HDC)wp;
      if ((HWND)lp == g_setSwatch) {                     // 色块=当前项颜色
        COLORREF c = SetCurColor();
        ::SetBkColor(dc, c);
        ::SetTextColor(dc, c);
        return (LRESULT)GetCachedBrush(c);
      }
      ::SetBkColor(dc, kPanelBg);
      ::SetTextColor(dc, kEditText);
      return (LRESULT)GetCachedBrush(kPanelBg);
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
      HDC dc = (HDC)wp;
      ::SetBkColor(dc, kEditBg);
      ::SetTextColor(dc, kEditText);
      return (LRESULT)GetCachedBrush(kEditBg);
    }
    case WM_DRAWITEM: {
      DRAWITEMSTRUCT* dsb = (DRAWITEMSTRUCT*)lp;
      if (dsb->CtlType == 4) { DrawDarkButton(dsb); return TRUE; }
      break;
    }
    case WM_ERASEBKGND: {
      RECT rc; ::GetClientRect(hwnd, &rc);
      ::FillRect((HDC)wp, &rc, GetCachedBrush(kPanelBg));
      return 1;
    }
    case WM_CLOSE:
      ::DestroyWindow(hwnd);
      return 0;
  }
  return ::DefWindowProcW(hwnd, msg, wp, lp);
}

// 打开设置窗口（局部模态，与附加进程对话框同一模式）
static void ShowSettingsDlg(HWND parent) {
  static bool reg = false;
  if (!reg) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = SettingsProc;
    wc.hInstance = g.inst;
    wc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = ::CreateSolidBrush(kPanelBg);
    wc.lpszClassName = kSetDlgClass;
    ::RegisterClassW(&wc);
    reg = true;
  }
  g_setCur = 0;
  RECT work{};
  ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
  const int dw = 520, dh = 450;
  const int x = work.left + ((work.right - work.left) - dw) / 2;
  const int y = work.top + ((work.bottom - work.top) - dh) / 2;
  ::EnableWindow(parent, FALSE);
  HWND dlg = ::CreateWindowExW(WS_EX_DLGMODALFRAME, kSetDlgClass,
                               L"界面设置 —— 代码高亮/颜色/字体",
                               WS_POPUP | WS_CAPTION | WS_SYSMENU,
                               x, y, dw, dh, parent, nullptr, g.inst, nullptr);
  ::ShowWindow(dlg, SW_SHOW);
  ::UpdateWindow(dlg);
  MSG m;
  while (::GetMessageW(&m, nullptr, 0, 0) > 0) {
    if (!::IsDialogMessageW(dlg, &m)) {
      ::TranslateMessage(&m);
      ::DispatchMessageW(&m);
    }
  }
  ::EnableWindow(parent, TRUE);
  ::SetForegroundWindow(parent);
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
  g.inst = hInstance;
  ::HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);
  ::SetUnhandledExceptionFilter(CrashFilter);

  INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS |
                                        ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES};
  ::InitCommonControlsEx(&icc);
  g_wNoTheme = EnvOn("CE_W_NOTHEME");
  g_wNoDbl   = EnvOn("CE_W_NODBL");
  g_wNoFull  = EnvOn("CE_W_NOFULL");
  g_wNoCd    = EnvOn("CE_W_NOCD");
  g_wNoInfo  = EnvOn("CE_W_NOINFO");

  ThemeLoadIni();   // 启动复原：读取 exe 同目录 CEScanGUI.ini
  g.uiFont = ::CreateFontW(kFontUiHeight, 0, 0, 0, FW_NORMAL, 0, 0, 0, GB2312_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH | FF_DONTCARE, kFontUiName);
  g.monoFont = ::CreateFontW(kFontMonoHeight, 0, 0, 0, FW_NORMAL, 0, 0, 0, GB2312_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FIXED_PITCH | FF_MODERN, kFontMonoName);

  // 回调
  g.dbg.SetEventCallback(OnDebugEvent);
  g.dbg.SetHitCallback(OnDebugHit);
  ce::DbvmTools::Instance().SetHitCallback(DbvmOnHit);  // DBVM 断点命中回调

  WNDCLASSW wc{};
  wc.lpfnWndProc = FrameProc;
  wc.hInstance = hInstance;
  wc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = ::CreateSolidBrush(kPanelBg);
  wc.lpszClassName = kFrameClass;
  wc.hIcon = ::LoadIcon(nullptr, IDI_APPLICATION);
  ::RegisterClassW(&wc);

  // 启动标题：这次启动随机 10 个字母（越早生成越好，建窗口时直接用）
  MakeRandomTitleTag();

  WNDCLASSW cc{};
  cc.lpfnWndProc = ChildProc;
  cc.hInstance = hInstance;
  cc.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
  cc.hbrBackground = ::CreateSolidBrush(kPanelBg);
  cc.lpszClassName = kChildClass;
  cc.hIcon = ::LoadIcon(nullptr, IDI_APPLICATION);
  ::RegisterClassW(&cc);

  // 菜单：文件0 调试1 监视2 窗口3 帮助4
  HMENU menu = BuildMenu();

  RECT work{};
  ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
  const int winW = kMainWndW, winH = kMainWndH;   // 尺寸见 ThemeColors.h（DefaultSizes）
  int x = work.left + ((work.right - work.left) - winW) / 2;
  int y = work.top + ((work.bottom - work.top) - winH) / 2;

  HWND hwnd = ::CreateWindowExW(0, kFrameClass,
                                g_titleTag,      // 启动标题：每次随机 10 个字母
                                WS_OVERLAPPEDWINDOW, x, y, winW, winH, nullptr, menu,
                                hInstance, nullptr);

  // 状态栏
  g.status = ::CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
                               WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, hwnd,
                               (HMENU)(INT_PTR)IDC_STATUS, hInstance, nullptr);

  // 状态栏分两段：主状态 + MCP 状态
  {
    RECT fr0;
    ::GetClientRect(hwnd, &fr0);
    int parts[3] = { fr0.right - 660, fr0.right - 280, -1 };
    ::SendMessageW(g.status, SB_SETPARTS, 3, (LPARAM)parts);
    StatusOwnerSet(1, L"MCP: 未连接");
    StatusOwnerSet(2, L"起始: -  结束: -  当前值: -");
  }

  // 状态栏创建于 WM_SIZE 之后，补发一次让三段布局（工具栏/MDI/状态栏）生效
  {
    RECT fr;
    ::GetWindowRect(hwnd, &fr);
    ::SendMessageW(hwnd, WM_SIZE, SIZE_RESTORED,
                   MAKELPARAM(fr.right - fr.left, fr.bottom - fr.top));
  }

  // 规范化显示方式（某些终端启动器会传入最小化/隐藏）
  if (nCmdShow == SW_HIDE || nCmdShow == SW_SHOWMINIMIZED || nCmdShow == SW_SHOWMINNOACTIVE ||
      nCmdShow == 0) {
    nCmdShow = SW_SHOWNORMAL;
  }
  ::ShowWindow(hwnd, nCmdShow);
  ::UpdateWindow(hwnd);

  // 快捷键
  ACCEL accels[] = {
      {FVIRTKEY, VK_F9, IDM_RUN},
      {FVIRTKEY, VK_F12, IDM_PAUSE},
      {FVIRTKEY, VK_F7, IDM_STEPIN},
      {FVIRTKEY, VK_F8, IDM_STEPOVER},
      {FVIRTKEY | FCONTROL, VK_F9, IDM_RUNTORET},
      {FVIRTKEY, VK_F2, IDM_TOGGLEBP},
      // CE：F5=查找访问此地址的内容，F6=查找写入此地址的内容
      {FVIRTKEY, VK_F5, IDM_FINDACCESS},
      {FVIRTKEY, VK_F6, IDM_FINDWRITE},
  };
  HACCEL hAccel = ::CreateAcceleratorTableW(accels, 8);

  MSG msg;
  while (::GetMessageW(&msg, nullptr, 0, 0)) {
    if (!::TranslateMDISysAccel(g.client, &msg) && !::TranslateAcceleratorW(hwnd, hAccel, &msg)) {
      ::TranslateMessage(&msg);
      ::DispatchMessageW(&msg);
    }
  }
  return (int)msg.wParam;
}
