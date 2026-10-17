//=============================================================================
//  CEUtil.cpp
//=============================================================================
#include "CEUtil.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>

namespace ce {
namespace util {

//-----------------------------------------------------------------------------
// 编码
//-----------------------------------------------------------------------------
std::string WideToUtf8(const std::wstring& s) {
  if (s.empty()) return std::string();
  const int need = ::WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                         nullptr, 0, nullptr, nullptr);
  if (need <= 0) return std::string();
  std::string out(static_cast<size_t>(need), '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &out[0], need, nullptr,
                        nullptr);
  return out;
}

std::wstring Utf8ToWide(const std::string& s) {
  if (s.empty()) return std::wstring();
  const int need = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                         nullptr, 0);
  if (need <= 0) return std::wstring();
  std::wstring out(static_cast<size_t>(need), L'\0');
  ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &out[0], need);
  return out;
}

std::string Trim(const std::string& s) {
  size_t b = 0;
  size_t e = s.size();
  while (b < e && static_cast<unsigned char>(s[b]) <= ' ') ++b;
  while (e > b && static_cast<unsigned char>(s[e - 1]) <= ' ') --e;
  return s.substr(b, e - b);
}

std::wstring ToLower(const std::wstring& s) {
  std::wstring r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](wchar_t c) { return static_cast<wchar_t>(::towlower(c)); });
  return r;
}

bool IEquals(const std::wstring& a, const std::wstring& b) {
  if (a.size() != b.size()) return false;
  return ToLower(a) == ToLower(b);
}

std::vector<std::string> Split(const std::string& s, char sep) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == sep) {
      out.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  out.push_back(cur);
  return out;
}

//-----------------------------------------------------------------------------
// 数值解析
//-----------------------------------------------------------------------------
bool ParseInteger(const std::string& text, bool hexadecimal, qword* out, bool* negative) {
  if (negative) *negative = false;
  if (out) *out = 0;

  std::string s = Trim(text);
  if (s.empty()) return false;

  size_t i = 0;
  bool neg = false;
  if (s[0] == '+' || s[0] == '-') {
    neg = (s[0] == '-');
    i = 1;
  }

  // 十六进制模式下不允许负号（与 CE 的 StrToQWord('$'+值) 行为一致）
  if (neg && hexadecimal) return false;

  int base = hexadecimal ? 16 : 10;
  if (s.compare(i, 2, "0x") == 0 || s.compare(i, 2, "0X") == 0) {
    base = 16;
    i += 2;
  } else if (i < s.size() && s[i] == '$') {
    base = 16;
    i += 1;
  } else if (i < s.size() && s[i] == '#') {
    base = 16;
    i += 1;
  } else if (i < s.size() && s[i] == '%') {
    base = 2;
    i += 1;
  }
  if (i >= s.size()) return false;

  std::string digits;
  for (; i < s.size(); ++i) {
    const char c = s[i];
    if (c == '_' || c == ',' || c == ' ' || c == '\t') continue;  // 容错：千分位/下划线
    digits.push_back(c);
  }
  if (digits.empty()) return false;

  errno = 0;
  char* end = nullptr;
  const unsigned long long magnitude = std::strtoull(digits.c_str(), &end, base);

  if (end == digits.c_str() || *end != '\0' || errno == ERANGE) {
    // 回退：按浮点解析再截断（对应 CE 的 except 分支 trunc(StrToFloatEx(s))）
    double d = 0.0;
    if (!ParseFloat(s, &d)) return false;
    const double t = std::trunc(d);
    if (out) *out = static_cast<qword>(static_cast<long long>(t));
    if (negative) *negative = (t < 0.0);
    return true;
  }

  if (negative) *negative = neg;
  if (out) {
    // 负数按 2 的补码回绕，等价于 Pascal 把 Int64 赋给 qword
    *out = neg ? static_cast<qword>(0ULL - static_cast<qword>(magnitude))
               : static_cast<qword>(magnitude);
  }
  return true;
}

bool ParseFloat(const std::string& text, double* out) {
  std::string s = Trim(text);
  if (s.empty()) return false;

  // 去掉常见千分位分隔符
  std::string cleaned;
  cleaned.reserve(s.size());
  for (char c : s) {
    if (c == '_' || c == ' ' || c == '\'') continue;
    cleaned.push_back(c);
  }

  std::string attempts[2] = {cleaned, cleaned};

  // 第一次按 '.' 当小数点；失败则把 ',' 换成 '.' 重试
  bool first = true;
  for (std::string candidate : attempts) {
    if (!first) {
      std::replace(candidate.begin(), candidate.end(), ',', '.');
    }
    first = false;

    errno = 0;
    char* end = nullptr;
    const double v = std::strtod(candidate.c_str(), &end);
    if (end != candidate.c_str() && end != nullptr && *end == '\0' && errno != ERANGE) {
      if (out) *out = v;
      return true;
    }
  }
  return false;
}

bool ParsePercentage(const std::string& text, double* out) {
  std::string s = Trim(text);
  if (!s.empty() && s.back() == '%') s.pop_back();
  return ParseFloat(s, out);
}

//-----------------------------------------------------------------------------
// Delphi RoundTo / Round
//-----------------------------------------------------------------------------
namespace {

// Delphi 的 Round 使用“银行家舍入”（四舍六入五取偶）
double BankerRound(double v) {
  if (!std::isfinite(v)) return v;
  const double f = std::floor(v);
  const double diff = v - f;
  if (diff > 0.5) return f + 1.0;
  if (diff < 0.5) return f;
  return (std::fmod(f, 2.0) == 0.0) ? f : f + 1.0;
}

}  // namespace

double RoundTo(double value, int digits) {
  if (!std::isfinite(value)) return value;
  if (digits == 0) return BankerRound(value);
  if (digits > 37) digits = 37;
  if (digits < -37) digits = -37;

  const double factor = std::pow(10.0, static_cast<double>(digits));
  if (factor == 0.0 || !std::isfinite(factor)) return value;
  return BankerRound(value / factor) * factor;
}

int ComputeFloatAccuracy(const std::string& text, char decimalSeparator) {
  const size_t pos = text.find(decimalSeparator);
  if (pos == std::string::npos) return 0;
  // 含指数形式时 CE 直接置 0
  for (char c : text) {
    if (c == 'e' || c == 'E') return 0;
  }
  return static_cast<int>(text.size() - pos - 1);
}

//-----------------------------------------------------------------------------
// 格式化
//-----------------------------------------------------------------------------
std::string FormatHex(ptruint v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
  return std::string(buf);
}

std::string FormatThousands(qword v) {
  std::string s = std::to_string(v);
  std::string out;
  int count = 0;
  for (auto it = s.rbegin(); it != s.rend(); ++it) {
    if (count != 0 && count % 3 == 0) out.push_back(',');
    out.push_back(*it);
    ++count;
  }
  std::reverse(out.begin(), out.end());
  return out;
}

std::string FormatSize(qword bytes) {
  static const char* units[] = {"B", "KB", "MB", "GB", "TB"};
  double v = static_cast<double>(bytes);
  int u = 0;
  while (v >= 1024.0 && u < 4) {
    v /= 1024.0;
    ++u;
  }
  char buf[64];
  if (u == 0)
    std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
  else
    std::snprintf(buf, sizeof(buf), "%.2f %s", v, units[u]);
  return std::string(buf);
}

std::string FormatTypedValue(const ubyte* data, int size, VariableType type) {
  if (data == nullptr || size <= 0) return "<none>";

  char buf[128];
  switch (type) {
    case VariableType::vtByte:
    case VariableType::vtWord:
    case VariableType::vtDword:
    case VariableType::vtQword: {
      unsigned long long v = 0;
      std::memcpy(&v, data, static_cast<size_t>(size > 8 ? 8 : size));
      const long long sv = static_cast<long long>(v);
      std::snprintf(buf, sizeof(buf), "%lld (0x%llX)", sv, v);
      return std::string(buf);
    }
    case VariableType::vtSingle: {
      float f = 0.0f;
      std::memcpy(&f, data, sizeof(float));
      std::snprintf(buf, sizeof(buf), "%g", static_cast<double>(f));
      return std::string(buf);
    }
    case VariableType::vtDouble: {
      double d = 0.0;
      std::memcpy(&d, data, sizeof(double));
      std::snprintf(buf, sizeof(buf), "%.17g", d);
      return std::string(buf);
    }
    case VariableType::vtString: {
      std::string s(reinterpret_cast<const char*>(data), static_cast<size_t>(size));
      while (!s.empty() && s.back() == '\0') s.pop_back();
      return "\"" + s + "\"";
    }
    case VariableType::vtUnicodeString: {
      const size_t n = static_cast<size_t>(size) / 2;
      std::wstring w(reinterpret_cast<const wchar_t*>(data), n);
      while (!w.empty() && w.back() == L'\0') w.pop_back();
      return "\"" + WideToUtf8(w) + "\"";
    }
    default: {
      std::string out = "0x";
      for (int i = size - 1; i >= 0; --i) {
        std::snprintf(buf, sizeof(buf), "%02X", data[i]);
        out += buf;
      }
      return out;
    }
  }
}

}  // namespace util
}  // namespace ce
