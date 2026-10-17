//=============================================================================
//  PatternScan.cpp
//======================================================================
#include "PatternScan.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

#include "CEUtil.h"

namespace ce {
namespace {

constexpr std::int32_t kFullWildcard = -1;
// 半字节通配的编码前缀（与 CE parsers.pas:ConvertStringToBytes 完全一致）
constexpr std::uint32_t kNibbleFlag = 0x80000000u;  // 最高位为 1 表示“带掩码”
constexpr std::uint32_t kNibbleLowMask = 0x0000F000u;  // 低 4 位需比较
constexpr std::uint32_t kNibbleHighMask = 0x00000F00u; // 高 4 位需比较

bool IsHexDigit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int HexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool IsSeparator(char c) {
  return c == ' ' || c == '\t' || c == ',' || c == '-' || c == '_' || c == '\r' || c == '\n' ||
         c == '|';
}

}  // namespace

//-----------------------------------------------------------------------------
// 解析特征码文本
//-----------------------------------------------------------------------------
AobPattern ParseAobPattern(const std::string& text, bool hexadecimal) {
  AobPattern result;
  const std::string trimmed = util::Trim(text);
  if (trimmed.empty()) {
    result.error = "特征码为空";
    return result;
  }

  if (!hexadecimal) {
    // ---- 十进制模式：按分隔符切分，每个 token 是一个 0..255 的十进制数或 '?' ----
    std::string token;
    auto flush = [&]() -> bool {
      if (token.empty()) return true;
      if (token == "?" || token == "*" || token == "??") {
        result.bytes.push_back(kFullWildcard);
        result.usesWildcard = true;
      } else {
        char* end = nullptr;
        const long v = std::strtol(token.c_str(), &end, 10);
        if (end == token.c_str() || *end != '\0' || v < 0 || v > 255) {
          result.error = "无法识别的十进制字节: " + token;
          return false;
        }
        result.bytes.push_back(static_cast<std::int32_t>(v));
      }
      token.clear();
      return true;
    };

    for (char c : trimmed) {
      if (IsSeparator(c)) {
        if (!flush()) return result;
      } else {
        token.push_back(c);
      }
    }
    if (!flush()) return result;
  } else {
    // ---- 十六进制模式：去掉分隔符后两两成对解析 ----
    std::string compact;
    for (char c : trimmed) {
      if (IsSeparator(c)) continue;
      compact.push_back(c);
    }
    if (compact.empty()) {
      result.error = "特征码为空";
      return result;
    }

    size_t i = 0;
    while (i < compact.size()) {
      const char c0 = compact[i];
      const char c1 = (i + 1 < compact.size()) ? compact[i + 1] : '\0';

      const int h0 = HexValue(c0);
      const int h1 = HexValue(c1);

      if (h0 >= 0 && h1 >= 0) {
        result.bytes.push_back(h0 * 16 + h1);
        i += 2;
        continue;
      }

      const bool w0 = (c0 == '?' || c0 == '*');
      const bool w1 = (c1 == '?' || c1 == '*');

      if (w0 && w1) {
        result.bytes.push_back(kFullWildcard);
        result.usesWildcard = true;
        i += 2;
        continue;
      }
      if (h0 >= 0 && w1) {
        // "A?" -> 高 4 位必须是 A
        const std::uint32_t v = kNibbleFlag | kNibbleLowMask | (static_cast<std::uint32_t>(h0) << 4);
        result.bytes.push_back(static_cast<std::int32_t>(v));
        result.usesNibble = true;
        i += 2;
        continue;
      }
      if (w0 && h1 >= 0) {
        // "?A" -> 低 4 位必须是 A
        const std::uint32_t v = kNibbleFlag | kNibbleHighMask | static_cast<std::uint32_t>(h1);
        result.bytes.push_back(static_cast<std::int32_t>(v));
        result.usesNibble = true;
        i += 2;
        continue;
      }
      if (h0 >= 0) {
        // 末尾单个十六进制字符（如 "8B0" 的最后一位）
        result.bytes.push_back(h0);
        i += 1;
        continue;
      }

      result.error = std::string("无法识别的特征码字符: '") + c0 + "'";
      return result;
    }
  }

  if (result.bytes.empty()) {
    result.error = "特征码为空";
    return result;
  }

  result.valid = true;
  return result;
}

//-----------------------------------------------------------------------------
// 匹配（移植 TScanner.ArrayOfByteExact，memscan.pas:2582）
//-----------------------------------------------------------------------------
bool MatchAob(const ubyte* newValue, const AobPattern& pattern) {
  const int n = pattern.Length();
  for (int i = 0; i < n; ++i) {
    const std::int32_t expected = pattern.bytes[static_cast<size_t>(i)];
    if (expected != kFullWildcard && newValue[i] != static_cast<ubyte>(expected)) return false;
  }
  return true;
}

//-----------------------------------------------------------------------------
// 匹配（移植 TScanner.ArrayOfByteExact_NibbleWildcardSupport，memscan.pas:2554）
//-----------------------------------------------------------------------------
bool MatchAobNibble(const ubyte* newValue, const AobPattern& pattern) {
  const int n = pattern.Length();
  for (int i = 0; i < n; ++i) {
    const std::int32_t raw = pattern.bytes[static_cast<size_t>(i)];
    if (raw == kFullWildcard) continue;  // 全通配

    if (raw < 0) {
      // 半字节通配：Pascal 的 shr 是逻辑移位，这里同样按无符号右移处理
      const std::uint32_t v = static_cast<std::uint32_t>(raw);
      const std::uint32_t mask = (v >> 8) & 0xFFu;
      const std::uint32_t expect = v & 0xFFu;
      if ((static_cast<std::uint32_t>(newValue[i]) & mask) != expect) return false;
    } else if (newValue[i] != static_cast<ubyte>(raw)) {
      return false;
    }
  }
  return true;
}

}  // namespace ce
