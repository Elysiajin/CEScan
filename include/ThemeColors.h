//=============================================================================
//  ThemeColors.h
//  CEScanGUI 配色/字体集中定义（运行时可配置，设置窗口修改，INI 持久化）
//
//  所有 k 前缀名字是宏，展开为 g_theme 的字段；调整默认颜色改 DefaultTheme()，
//  界面上的临时修改由设置窗口（选项-界面设置）完成并写入 CEScanGUI.ini。
//=============================================================================
#ifndef CE_THEMECOLORS_H
#define CE_THEMECOLORS_H

#include <windows.h>

struct ThemeColors {
  // 反汇编
  COLORREF disBg, disRipBg, disSelBg, disRetBg, disJumpBg;
  COLORREF disJumpFg, disRetFg, disJumpHexFg, disPlainMn, disDataMn;
  COLORREF disSegFg, disRegFg, disHexFg, disApiFg, disDbFg, disPunctFg;
  COLORREF disAddrFg, disBytesFg, disCommentFg, disBpDot;
  // 反汇编列分隔线（每条一色：地址栏右缘=红 机器码右缘=绿 备注起点=橙；
  // 原"指令列右缘"蓝线已删——与备注起点重复，用户确认多余）
  COLORREF disColLine1, disColLine2, disColLine4;
  // 日志数据窗口（OD Log data）
  COLORREF logDataLine, logDataMsgFg, logDataAddrFg, logDataHdrBg;
  COLORREF disFlowJmp, disFlowCall;
  // 通用 UI / 堆栈
  COLORREF uiBg, uiText, uiTextDim;
  COLORREF uiStackBg, uiStackSelBg, uiStackFg, uiStackRetFg, uiStackSehFg, uiStackPtrFg;
  // 寄存器面板
  COLORREF regNameFg, regValueFg, regNoteFg, regEipFg, regEflFg, regFlagFg, regSegFg, regBg;
  // 滚动条 / 虚拟滚动条
  COLORREF sbTrackBg, sbBorder, vScrollThumb, vScrollThumbHi, vScrollSplit;
  // 分割条
  COLORREF splitFace, splitHot, splitBorder, splitHotBorder;
  // 转储/堆栈列分隔线（地址|机器码=红，机器码|备注=绿）
  COLORREF colAddrLine, colDataLine;
  // 按钮
  COLORREF btnFace, btnPressed, btnDisabledBg, btnBorder, btnBorderHi;
  COLORREF btnCheckBg, btnCheckTick, btnCheckBorder, btnText, btnTextDisabled, btnTextSub;
  // 编辑框 / 面板 / 列表
  COLORREF editBg, editText, editTextSub, panelBg;
  COLORREF listBg, listText;
  // 监视窗口
  COLORREF watchBg;
  COLORREF watchRed, watchDarkRed, watchGreen, watchBlue, watchOrange, watchPurple, watchGray, watchSteel;
  // 字体（名称用定长数组，便于设置窗口写入与 INI 持久化）
  wchar_t fontUiName[32];
  wchar_t fontMonoName[32];
  int fontUiHeight, fontMonoHeight, fontTbHeight;
  // 高亮开关
  bool highlightOperands;   // 高亮操作数（关闭则指令整体一色）
};

// 默认主题（也是设置窗口"恢复默认"的来源）
inline ThemeColors DefaultTheme() {
  ThemeColors t{};
  t.disBg=RGB(0,0,0);       t.disRipBg=RGB(90,20,90);   t.disSelBg=RGB(90,40,130);
  t.disRetBg=RGB(25,45,90); t.disJumpBg=RGB(255,255,90);
  t.disJumpFg=RGB(200,0,0); t.disRetFg=RGB(0,0,0);      t.disJumpHexFg=RGB(0,0,160);
  t.disPlainMn=RGB(240,240,240); t.disDataMn=RGB(255,255,0);
  t.disSegFg=RGB(255,60,255); t.disRegFg=RGB(60,220,60); t.disHexFg=RGB(200,160,70);
  t.disApiFg=RGB(255,220,80); t.disDbFg=RGB(140,140,140); t.disPunctFg=RGB(150,150,165);
  t.disAddrFg=RGB(255,255,255); t.disBytesFg=RGB(255,255,255);
  t.disCommentFg=RGB(150,210,170); t.disBpDot=RGB(220,40,40);
  t.disColLine1=RGB(200,40,40);   // 红：地址栏右缘（可拖动）
  t.disColLine2=RGB(40,170,70);   // 绿：机器码右缘
  t.disColLine4=RGB(220,150,40);  // 橙：备注列起点
  t.logDataLine=RGB(40,170,70);   // 日志数据 地址|消息 分隔线（绿）
  t.logDataMsgFg=RGB(64,190,96);  // 消息文字（OD 绿）
  t.logDataAddrFg=RGB(210,210,214); // 地址文字
  t.logDataHdrBg=RGB(26,26,30);   // 表头条底色
  t.disFlowJmp=RGB(120,200,255); t.disFlowCall=RGB(200,140,255);
  t.uiBg=RGB(0,0,0); t.uiText=RGB(220,220,230); t.uiTextDim=RGB(150,150,165);
  t.uiStackBg=RGB(0,0,0); t.uiStackSelBg=RGB(90,40,130); t.uiStackFg=RGB(228,228,238);
  t.uiStackRetFg=RGB(255,64,64); t.uiStackSehFg=RGB(255,190,90); t.uiStackPtrFg=RGB(150,210,170);
  t.regNameFg=RGB(255,220,100); t.regValueFg=RGB(240,240,240); t.regNoteFg=RGB(150,150,165);
  t.regEipFg=RGB(255,80,160); t.regEflFg=RGB(255,220,100); t.regFlagFg=RGB(120,200,255);
  t.regSegFg=RGB(200,200,200); t.regBg=RGB(0,0,0);
  t.sbTrackBg=RGB(45,45,45); t.sbBorder=RGB(85,85,85);
  t.vScrollThumb=RGB(110,110,110); t.vScrollThumbHi=RGB(165,165,165); t.vScrollSplit=RGB(90,90,90);
  t.splitFace=RGB(58,58,62); t.splitHot=RGB(95,95,102);
  t.splitBorder=RGB(106,106,114); t.splitHotBorder=RGB(150,190,255);
  t.colAddrLine=RGB(200,40,40); t.colDataLine=RGB(40,170,70);
  t.btnFace=RGB(62,62,62); t.btnPressed=RGB(32,32,32); t.btnDisabledBg=RGB(45,45,45);
  t.btnBorder=RGB(95,95,95); t.btnBorderHi=RGB(115,115,115);
  t.btnCheckBg=RGB(28,28,28); t.btnCheckTick=RGB(190,190,190); t.btnCheckBorder=RGB(20,20,20);
  t.btnText=RGB(235,235,240); t.btnTextDisabled=RGB(115,115,115); t.btnTextSub=RGB(205,205,215);
  t.editBg=RGB(0,0,0); t.editText=RGB(220,220,230); t.editTextSub=RGB(200,200,210);
  t.panelBg=RGB(40,40,40);
  t.listBg=RGB(0,0,0); t.listText=RGB(220,220,230);
  t.watchBg=RGB(40,40,40);
  t.watchRed=RGB(180,40,40); t.watchDarkRed=RGB(150,30,30); t.watchGreen=RGB(40,130,60);
  t.watchBlue=RGB(40,90,190); t.watchOrange=RGB(200,120,30); t.watchPurple=RGB(130,60,170);
  t.watchGray=RGB(100,100,100); t.watchSteel=RGB(105,130,180);
  t.fontUiName[31]=L'\0'; ::lstrcpyW(t.fontUiName, L"Microsoft YaHei UI");
  t.fontMonoName[31]=L'\0'; ::lstrcpyW(t.fontMonoName, L"Consolas");
  t.fontUiHeight=-14; t.fontMonoHeight=-14; t.fontTbHeight=-11;
  t.highlightOperands=true;
  return t;
}

extern ThemeColors g_theme;

//=============================================================================
//  控件尺寸集中调节区
//  所有界面尺寸都定义在 DefaultSizes()，运行期直接改 g_sz 字段同样生效。
//  想调整某个控件大小：改这里 → 重编译（或运行期改 g_sz）。
//=============================================================================
struct ThemeSizes {
  // 工具栏（OD 风格）
  int tbHeight, tbBtnTop, tbBtnBot, tbBtnW, tbLetterW, tbPauseW, tbSepW, tbGlyph;
  // 通用布局
  int margin;            // 子窗口内容边距
  int rowScanH;          // 内存搜索 行高
  int rowBpsH;           // 断点窗口 行高
  int rowMcpH;           // MCP 输出栏 / 中文搜索引擎 行高
  int splitBar;          // 分割条厚度（竖/横同值）
  int vsWidth;           // 反汇编虚拟滚动条宽
  int cpuTopGap;         // CPU 面板顶部留白（原顶部跳转框高度）
  int cpuMinW, cpuMinH;  // CPU 四面板拖动最小宽/高
  int gotoW, gotoH;      // 地址跳转小窗尺寸
  // 反汇编列（列线可拖动，以下为默认位置；指令列宽度由备注起点线决定，无独立线）
  int disAddrEnd, disBytesEnd, disCmtX;
  // 转储/堆栈列（红/绿线默认位置 + 钳制保护值）
  int dumpCol1, dumpCol2, stkCol1, stkCol2;
  int colMinW;           // 列线最小 x
  int dumpHexGap, stkHexGap;       // 红/绿两线最小间距
  int dumpRightKeep, stkRightKeep; // 绿线右侧需保留的宽度
  // 新建子窗口默认尺寸（宽, 高）
  int defCpuW, defCpuH, defScanW, defScanH, defBpsW, defBpsH;
  int defLogW, defLogH, defMcpW, defMcpH, defStrsW, defStrsH;
  int defMapW, defMapH, defThrW, defThrH;
  // 附加进程对话框 / logo 宫格（bin\logo\*.gif，IPicture 首帧绘制）
  int mainWndW, mainWndH;    // 主窗口初始尺寸
  int defLogDW, defLogDH;    // 日志数据窗口默认尺寸
  int logDataAddrW, logDataHdrH;  // 地址列宽 / 表头条高
  int procDlgW, procDlgH;    // 对话框总尺寸（底部预留宫格区）
  int logoCols;              // 宫格列数
  int logoW, logoH;          // 单元格尺寸（用户指定 90x30）
  int logoGapX, logoGapY;    // 横/纵间距
};

// 默认尺寸（集中调节入口）
inline ThemeSizes DefaultSizes() {
  ThemeSizes s{};
  // 工具栏
  s.tbHeight=25; s.tbBtnTop=1; s.tbBtnBot=2; s.tbBtnW=24; s.tbLetterW=22;
  s.tbPauseW=112; s.tbSepW=14; s.tbGlyph=16;
  // 通用布局
  s.margin=8; s.rowScanH=26; s.rowBpsH=28; s.rowMcpH=30;
  s.splitBar=6; s.vsWidth=14;
  s.cpuTopGap=8; s.cpuMinW=80; s.cpuMinH=60;
  s.gotoW=366; s.gotoH=92;
  // 反汇编列（红线=地址栏右缘，可拖动调地址栏宽）
  s.disAddrEnd=142; s.disBytesEnd=250; s.disCmtX=600;
  // 转储/堆栈列
  s.dumpCol1=120; s.dumpCol2=520; s.stkCol1=120; s.stkCol2=300;
  s.colMinW=60; s.dumpHexGap=80; s.stkHexGap=60;
  s.dumpRightKeep=220; s.stkRightKeep=160;
  // 新建子窗口默认尺寸
  s.defCpuW=780;  s.defCpuH=560;  s.defScanW=640; s.defScanH=460;
  s.defBpsW=640;  s.defBpsH=420;  s.defLogW=520;  s.defLogH=300;
  s.defMcpW=620;  s.defMcpH=460;  s.defStrsW=720; s.defStrsH=480;
  s.defMapW=560;  s.defMapH=420;  s.defThrW=480;  s.defThrH=300;
  s.mainWndW=920; s.mainWndH=650;
  s.defLogDW=640; s.defLogDH=430;
  s.logDataAddrW=104; s.logDataHdrH=20;
  // 附加对话框 / logo 宫格
  s.procDlgW=480; s.procDlgH=580;
  s.logoCols=5; s.logoW=90; s.logoH=30; s.logoGapX=0; s.logoGapY=0;
  return s;
}

extern ThemeSizes g_sz;

// ---- 尺寸兼容宏：旧代码里的 k 名字直接映射到 g_sz 字段 ----
#define kTbHeight   (g_sz.tbHeight)
#define kTbBtnTop   (g_sz.tbBtnTop)
#define kTbBtnBot   (g_sz.tbBtnBot)
#define kTbBtnW     (g_sz.tbBtnW)
#define kTbLetterW  (g_sz.tbLetterW)
#define kTbPauseW   (g_sz.tbPauseW)
#define kTbSepW     (g_sz.tbSepW)
#define kTbGlyph    (g_sz.tbGlyph)
#define kMargin     (g_sz.margin)
#define kRowScanH   (g_sz.rowScanH)
#define kRowBpsH    (g_sz.rowBpsH)
#define kRowMcpH    (g_sz.rowMcpH)
#define kSplitBar   (g_sz.splitBar)
#define kVsW        (g_sz.vsWidth)
#define kCpuTopGap  (g_sz.cpuTopGap)
#define kCpuMinW    (g_sz.cpuMinW)
#define kCpuMinH    (g_sz.cpuMinH)
#define kGotoW      (g_sz.gotoW)
#define kGotoH      (g_sz.gotoH)
#define kDisAddrEnd (g_sz.disAddrEnd)
#define kDisBytesEnd (g_sz.disBytesEnd)
#define kDisCmtX    (g_sz.disCmtX)
#define kDumpCol1   (g_sz.dumpCol1)
#define kDumpCol2   (g_sz.dumpCol2)
#define kStkCol1    (g_sz.stkCol1)
#define kStkCol2    (g_sz.stkCol2)
#define kColMinW    (g_sz.colMinW)
#define kDumpHexGap (g_sz.dumpHexGap)
#define kStkHexGap  (g_sz.stkHexGap)
#define kDumpRightKeep (g_sz.dumpRightKeep)
#define kStkRightKeep  (g_sz.stkRightKeep)
#define kDefCpuW    (g_sz.defCpuW)
#define kDefCpuH    (g_sz.defCpuH)
#define kDefScanW   (g_sz.defScanW)
#define kDefScanH   (g_sz.defScanH)
#define kDefBpsW    (g_sz.defBpsW)
#define kDefBpsH    (g_sz.defBpsH)
#define kDefLogW    (g_sz.defLogW)
#define kDefLogH    (g_sz.defLogH)
#define kDefMcpW    (g_sz.defMcpW)
#define kDefMcpH    (g_sz.defMcpH)
#define kDefStrsW   (g_sz.defStrsW)
#define kDefStrsH   (g_sz.defStrsH)
#define kDefMapW    (g_sz.defMapW)
#define kDefMapH    (g_sz.defMapH)
#define kDefThrW    (g_sz.defThrW)
#define kDefThrH    (g_sz.defThrH)
#define kMainWndW   (g_sz.mainWndW)
#define kMainWndH   (g_sz.mainWndH)
#define kDefLogDW   (g_sz.defLogDW)
#define kDefLogDH   (g_sz.defLogDH)
#define kLogDataAddrW (g_sz.logDataAddrW)
#define kLogDataHdrH  (g_sz.logDataHdrH)
#define kProcDlgW   (g_sz.procDlgW)
#define kProcDlgH   (g_sz.procDlgH)
#define kLogoCols   (g_sz.logoCols)
#define kLogoW      (g_sz.logoW)
#define kLogoH      (g_sz.logoH)
#define kLogoGapX   (g_sz.logoGapX)
#define kLogoGapY   (g_sz.logoGapY)

// ---- 兼容宏：旧代码里的 k 名字直接映射到 g_theme 字段 ----
#define kDisBg          (g_theme.disBg)
#define kDisRipBg       (g_theme.disRipBg)
#define kDisSelBg       (g_theme.disSelBg)
#define kDisRetBg       (g_theme.disRetBg)
#define kDisJumpBg      (g_theme.disJumpBg)
#define kDisJumpFg      (g_theme.disJumpFg)
#define kDisRetFg       (g_theme.disRetFg)
#define kDisJumpHexFg   (g_theme.disJumpHexFg)
#define kDisPlainMn     (g_theme.disPlainMn)
#define kDisDataMn      (g_theme.disDataMn)
#define kDisSegFg       (g_theme.disSegFg)
#define kDisRegFg       (g_theme.disRegFg)
#define kDisHexFg       (g_theme.disHexFg)
#define kDisApiFg       (g_theme.disApiFg)
#define kDisDbFg        (g_theme.disDbFg)
#define kDisPunctFg     (g_theme.disPunctFg)
#define kDisAddrFg      (g_theme.disAddrFg)
#define kDisBytesFg     (g_theme.disBytesFg)
#define kDisCommentFg   (g_theme.disCommentFg)
#define kDisColLine1    (g_theme.disColLine1)
#define kDisColLine2    (g_theme.disColLine2)
#define kDisColLine4    (g_theme.disColLine4)
#define kLogDataLine    (g_theme.logDataLine)
#define kLogDataMsgFg   (g_theme.logDataMsgFg)
#define kLogDataAddrFg  (g_theme.logDataAddrFg)
#define kLogDataHdrBg   (g_theme.logDataHdrBg)
#define kDisBpDot       (g_theme.disBpDot)
#define kDisFlowJmp     (g_theme.disFlowJmp)
#define kDisFlowCall    (g_theme.disFlowCall)
#define kUiBg           (g_theme.uiBg)
#define kUiText         (g_theme.uiText)
#define kUiTextDim      (g_theme.uiTextDim)
#define kUiStackBg      (g_theme.uiStackBg)
#define kUiStackSelBg   (g_theme.uiStackSelBg)
#define kUiStackFg      (g_theme.uiStackFg)
#define kUiStackRetFg   (g_theme.uiStackRetFg)
#define kUiStackSehFg   (g_theme.uiStackSehFg)
#define kUiStackPtrFg   (g_theme.uiStackPtrFg)
#define kRegNameFg      (g_theme.regNameFg)
#define kRegValueFg     (g_theme.regValueFg)
#define kRegNoteFg      (g_theme.regNoteFg)
#define kRegEipFg       (g_theme.regEipFg)
#define kRegEflFg       (g_theme.regEflFg)
#define kRegFlagFg      (g_theme.regFlagFg)
#define kRegSegFg       (g_theme.regSegFg)
#define kRegBg          (g_theme.regBg)
#define kSbTrackBg      (g_theme.sbTrackBg)
#define kSbBorder       (g_theme.sbBorder)
#define kVScrollThumb   (g_theme.vScrollThumb)
#define kVScrollThumbHi (g_theme.vScrollThumbHi)
#define kVScrollSplit   (g_theme.vScrollSplit)
#define kSplitFace      (g_theme.splitFace)
#define kSplitHot       (g_theme.splitHot)
#define kSplitBorder    (g_theme.splitBorder)
#define kSplitHotBorder (g_theme.splitHotBorder)
#define kColAddrLine    (g_theme.colAddrLine)
#define kColDataLine    (g_theme.colDataLine)
#define kBtnFace        (g_theme.btnFace)
#define kBtnPressed     (g_theme.btnPressed)
#define kBtnDisabledBg  (g_theme.btnDisabledBg)
#define kBtnBorder      (g_theme.btnBorder)
#define kBtnBorderHi    (g_theme.btnBorderHi)
#define kBtnCheckBg     (g_theme.btnCheckBg)
#define kBtnCheckTick   (g_theme.btnCheckTick)
#define kBtnCheckBorder (g_theme.btnCheckBorder)
#define kBtnText        (g_theme.btnText)
#define kBtnTextDisabled (g_theme.btnTextDisabled)
#define kBtnTextSub     (g_theme.btnTextSub)
#define kEditBg         (g_theme.editBg)
#define kEditText       (g_theme.editText)
#define kEditTextSub    (g_theme.editTextSub)
#define kPanelBg        (g_theme.panelBg)
#define kListBg         (g_theme.listBg)
#define kListText       (g_theme.listText)
#define kWatchBg        (g_theme.watchBg)
#define kWatchRed       (g_theme.watchRed)
#define kWatchDarkRed   (g_theme.watchDarkRed)
#define kWatchGreen     (g_theme.watchGreen)
#define kWatchBlue      (g_theme.watchBlue)
#define kWatchOrange    (g_theme.watchOrange)
#define kWatchPurple    (g_theme.watchPurple)
#define kWatchGray      (g_theme.watchGray)
#define kWatchSteel     (g_theme.watchSteel)
#define kFontUiName     (g_theme.fontUiName)
#define kFontMonoName   (g_theme.fontMonoName)
#define kFontUiHeight   (g_theme.fontUiHeight)
#define kFontMonoHeight (g_theme.fontMonoHeight)
#define kFontTbHeight   (g_theme.fontTbHeight)
#define kHighlightOperands (g_theme.highlightOperands)
#define kIconMask       RGB(255, 0, 255)

// 命令栏字体（9 号宋体；集中于此便于调整）
#define kFontCmdName    L"宋体"
#define kFontCmdHeight  (-12)   // 9pt ≈ -12 像素高

#endif  // CE_THEMECOLORS_H
