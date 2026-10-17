#pragma once
//=============================================================================
//  CETypes.h
//  Cheat Engine 「内存搜索 / 区域排除」模块 —— 基础类型移植
//
//  移植来源（保持与原始 Pascal 一致的命名，便于对照源码）:
//      Cheat Engine/commontypedefs.pas   TVariableType / TScanOption / TMemoryRegion ...
//      Cheat Engine/memscan.pas          Tscanregionpreference / TFastScanMethod ...
//
//  本头文件不依赖 Windows SDK，可被任何平台上的纯逻辑代码包含。
//=============================================================================
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ce {

//-----------------------------------------------------------------------------
// Delphi 基础类型 -> C++
//-----------------------------------------------------------------------------
using ptruint = std::uintptr_t;  // Pascal: ptruint   指针宽度无符号整数
using qword = std::uint64_t;     // Pascal: qword
using dword = std::uint32_t;     // Pascal: dword
using uword = std::uint16_t;     // Pascal: word
using ubyte = std::uint8_t;      // Pascal: byte

using PByteArray = ubyte*;

//-----------------------------------------------------------------------------
// TMemoryRegion  (commontypedefs.pas:37)
//-----------------------------------------------------------------------------
struct MemoryRegion {
  ptruint BaseAddress = 0;   // 区域基址
  qword MemorySize = 0;      // 区域长度
  bool IsChild = false;      // 前面还有一个连续区域
  ptruint startaddress = 0;  // 在整块“旧内存镜像”中的偏移（未知值扫描使用）
};

// 地址区间 —— 用于排除/包含列表
struct AddressRange {
  ptruint start = 0;
  ptruint stop = 0;  // 半开区间 [start, stop)

  qword Size() const { return stop > start ? static_cast<qword>(stop - start) : 0; }
  bool Contains(ptruint a) const { return a >= start && a < stop; }
};

//-----------------------------------------------------------------------------
// TVariableType  (commontypedefs.pas:15)
//-----------------------------------------------------------------------------
enum class VariableType : int {
  vtByte = 0,
  vtWord = 1,
  vtDword = 2,
  vtQword = 3,
  vtSingle = 4,
  vtDouble = 5,
  vtString = 6,
  vtUnicodeString = 7,
  vtByteArray = 8,
  vtBinary = 9,
  vtAll = 10,
  vtAutoAssembler = 11,
  vtPointer = 12,
  vtCustom = 13,
  vtGrouped = 14,
  vtByteArrays = 15,
  vtCodePageString = 16,
};

// vtAll 时逐个尝试的“标量类型”数量 (vtByte..vtDouble)
constexpr int kScalarTypeCount = 6;

//-----------------------------------------------------------------------------
// TScanOption  (commontypedefs.pas:12)
//-----------------------------------------------------------------------------
enum class ScanOption : int {
  soUnknownValue = 0,
  soExactValue = 1,
  soValueBetween = 2,
  soBiggerThan = 3,
  soSmallerThan = 4,
  soIncreasedValue = 5,
  soIncreasedValueBy = 6,
  soDecreasedValue = 7,
  soDecreasedValueBy = 8,
  soChanged = 9,
  soUnchanged = 10,
  soForgot = 11,  // == soUnchanged 的别名用法，CE 内部当作 Unknown
  soCustom = 12,
};

//-----------------------------------------------------------------------------
// Tscanregionpreference  (memscan.pas:46)
// 三态语义 —— 这就是「排除」能力的核心：
//     scanDontCare : 不关心，不参与过滤
//     scanExclude  : 排除（例如 "-W" = 排除可写内存）
//     scanInclude  : 包含（例如 "+W" = 只扫描可写内存）
//-----------------------------------------------------------------------------
enum class ScanRegionPreference : int {
  scanDontCare = 0,
  scanExclude = 1,
  scanInclude = 2,
};

//-----------------------------------------------------------------------------
// TFastScanMethod  (commontypedefs.pas:20)
//-----------------------------------------------------------------------------
enum class FastScanMethod : int {
  fsmNotAligned = 0,  // 逐字节扫描
  fsmAligned = 1,     // 按 fastScanAlignSize 对齐
  fsmLastDigits = 2,  // 末位数字固定（步进 16^fastScanDigitCount）
};

//-----------------------------------------------------------------------------
// TRoundingType  (commontypedefs.pas:14)
//-----------------------------------------------------------------------------
enum class RoundingType : int {
  rtRounded = 0,
  rtExtremerounded = 1,
  rtTruncated = 2,
};

//-----------------------------------------------------------------------------
// 名称 <-> 枚举 转换（命令行/界面使用）
//-----------------------------------------------------------------------------
VariableType VariableTypeFromName(const std::string& s, bool* ok = nullptr);
const char* VariableTypeName(VariableType t);
int VariableTypeSize(VariableType t);  // 固定长度类型返回字节数，变长返回 0

ScanOption ScanOptionFromName(const std::string& s, bool* ok = nullptr);
const char* ScanOptionName(ScanOption o);
bool ScanOptionNeedsValue(ScanOption o);          // 是否需要用户输入数值
bool ScanOptionNeedsSecondValue(ScanOption o);    // 是否需要第二个数值
bool ScanOptionUsesPreviousValue(ScanOption o);   // 是否依赖上一次的快照

FastScanMethod FastScanMethodFromName(const std::string& s, bool* ok = nullptr);

const char* ScanRegionPreferenceName(ScanRegionPreference p);

// 拼装所有可选值的帮助文本（用于 CLI 报错提示）
std::string AllVariableTypeNames();
std::string AllScanOptionNames();
std::string AllFastScanMethodNames();

}  // namespace ce
