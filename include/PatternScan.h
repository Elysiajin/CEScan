#pragma once
//=============================================================================
//  PatternScan.h
//  特征码（Array of Bytes）匹配 —— 移植 memscan.pas 的：
//      TScanner.ArrayOfByteExact                       (2582)  全等匹配（-1 通配）
//      TScanner.ArrayOfByteExact_NibbleWildcardSupport (2554)  半字节通配 (?A / A? / 0?）
//      TScanner.ArrayOfBytesExact                     (2627)  多特征码版本
//
//  模式数组约定（与 CE 的 abs_arraytofind 一致）：
//      >= 0   必须精确相等的字节
//      -1     全通配（? 或 ??）
//      < -1   半字节通配：低 8 位为期望值，bit8..15 为掩码
//             例如 A? -> 0x0A | (0xF0 << 8)
//=============================================================================
#include <string>
#include <vector>

#include "CETypes.h"

namespace ce {

struct AobPattern {
  std::vector<std::int32_t> bytes;  // 见文件头约定
  bool usesWildcard = false;        // 含 -1
  bool usesNibble = false;          // 含半字节通配
  bool valid = false;
  std::string error;

  int Length() const { return static_cast<int>(bytes.size()); }
};

// 解析特征码文本，接受：
//     "48 8B 05 ?? ?? ?? ??"
//     "488B05????????"
//     "48 8B 05 A? ?B"      (半字节通配)
//     "48 8b 05" (hex 模式) / "72 101 108 108 111" (十进制模式, hexadecimal=false)
AobPattern ParseAobPattern(const std::string& text, bool hexadecimal);

// 单个位置匹配（newvalue 指向候选起始地址，至少 pattern.Length() 字节可读）
bool MatchAob(const ubyte* newValue, const AobPattern& pattern);

// 带半字节通配的匹配（较慢，仅当 usesNibble 时使用）
bool MatchAobNibble(const ubyte* newValue, const AobPattern& pattern);

// 依据模式自动选择匹配器
inline bool MatchAobAuto(const ubyte* newValue, const AobPattern& pattern) {
  return pattern.usesNibble ? MatchAobNibble(newValue, pattern) : MatchAob(newValue, pattern);
}

}  // namespace ce
