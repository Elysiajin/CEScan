#pragma once
//=============================================================================
//  CEUtil.h
//  Cheat Engine 移植所需的通用工具：
//    字符串/编码转换、数值解析(strtoqwordex/StrToFloat 等价物)、
//    Delphi RoundTo 等价实现、格式化输出、计时器。
//=============================================================================
#include <chrono>
#include <string>
#include <vector>

#include "CETypes.h"

namespace ce {
namespace util {

//-----------------------------------------------------------------------------
// 编码
//-----------------------------------------------------------------------------
std::string WideToUtf8(const std::wstring& s);
std::wstring Utf8ToWide(const std::string& s);

std::string Trim(const std::string& s);
std::wstring ToLower(const std::wstring& s);
bool IEquals(const std::wstring& a, const std::wstring& b);

std::vector<std::string> Split(const std::string& s, char sep);

//-----------------------------------------------------------------------------
// 数值解析
//  ParseInteger 等价于 Pascal 的 StrToQWord / StrToQWordEx：
//    支持 "0x1F" / "$1F" / "1F"(hex 模式) / "123" / "-5"
//  negative 返回是否带有负号（对应 memscan.pas:4583 的 signed 判定）
//-----------------------------------------------------------------------------
bool ParseInteger(const std::string& text, bool hexadecimal, qword* out, bool* negative = nullptr);

// 解析浮点；失败时剔除常见千分位/空白重试（对应 CE 的 DecimalSeparator 重试逻辑）
bool ParseFloat(const std::string& text, double* out);

// "10%" / "10" 均可，percentage 为真时按百分号处理（memscan.pas:4824）
bool ParsePercentage(const std::string& text, double* out);

//-----------------------------------------------------------------------------
// Delphi 的 RoundTo(Value, -Digits)
// Delphi 默认使用“银行家舍入”(round half to even)，此处保持一致。
//-----------------------------------------------------------------------------
double RoundTo(double value, int digits);

// CE 里依据字符串小数位数推算 floataccuracy (memscan.pas:4845)
int ComputeFloatAccuracy(const std::string& text, char decimalSeparator = '.');

//-----------------------------------------------------------------------------
// 格式化
//-----------------------------------------------------------------------------
std::string FormatHex(ptruint v);
std::string FormatSize(qword bytes);  // 1.25 MB 之类
std::string FormatThousands(qword v);

// 按变量类型把原始字节渲染为可读文本（结果列表 / 写出值）
std::string FormatTypedValue(const ubyte* data, int size, VariableType type);

//-----------------------------------------------------------------------------
// 计时
//-----------------------------------------------------------------------------
class Stopwatch {
 public:
  Stopwatch() : start_(std::chrono::steady_clock::now()) {}
  void Reset() { start_ = std::chrono::steady_clock::now(); }
  double Elapsed() const {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - start_).count();
  }

 private:
  std::chrono::steady_clock::time_point start_;
};

}  // namespace util
}  // namespace ce
