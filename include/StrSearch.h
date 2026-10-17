#pragma once
// ============================================================================
//  StrSearch.h —— OD 中文搜索引擎（复刻）
//  遍历目标进程可读内存，提取可读字符串：
//    · ASCII 模式：连续可打印字节（含 GBK 双字节中文）
//    · UNICODE 模式：连续 UTF-16LE 可打印字符（含中文）
//    · 智能模式：两种都搜
// ============================================================================
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include "CETypes.h"

namespace ce {

struct StrHit {
  ptruint address = 0;
  std::wstring text;      // 显示文本（ASCII 的按 GBK 解码，UNICODE 原样）
  int length = 0;         // 字节长度
  int kind = 0;           // 0=ASCII 1=UNICODE
};

struct StrSearchOptions {
  int mode = 2;           // 0=ASCII 1=UNICODE 2=智能
  int minLength = 4;      // 最短字符数
  bool requireChinese = false; // 只显示含中文的
  qword maxRegionSize = 0;     // 0=不限
};

class StrSearch {
public:
  // 在目标进程上扫描；hProc 需 PROCESS_VM_READ 权限；进度回调 (0-100)，返回 false 中止
  static bool Run(HANDLE hProc, const StrSearchOptions& opt,
                  std::vector<StrHit>& out,
                  std::function<bool(int)> progress = nullptr,
                  std::string* error = nullptr);

  // 判定：GBK 双字节中文/扩展字符
  static bool IsGbkLead(ubyte b) { return b >= 0x81 && b <= 0xFE; }
  static bool IsGbkTrail(ubyte b) { return (b >= 0x40 && b <= 0x7E) || (b >= 0x80 && b <= 0xFE); }
  static bool IsPrintableAscii(ubyte b) { return b >= 0x20 && b <= 0x7E; }
};

} // namespace ce
