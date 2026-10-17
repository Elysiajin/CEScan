//=============================================================================
//  CETypes.cpp
//=============================================================================
#include "CETypes.h"

#include <algorithm>
#include <cctype>

#include "CEUtil.h"

namespace ce {
namespace {

std::string Lower(const std::string& s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return r;
}

// 去掉名字里的 '-' '_' ' '，便于 "byte-array" / "bytearray" 都能识别
std::string Canonical(const std::string& s) {
  std::string r;
  for (char c : Lower(s)) {
    if (c != '-' && c != '_' && c != ' ' && c != '\t') r.push_back(c);
  }
  return r;
}

}  // namespace

//-----------------------------------------------------------------------------
// 变量类型
//-----------------------------------------------------------------------------
VariableType VariableTypeFromName(const std::string& s, bool* ok) {
  const std::string k = Canonical(s);
  bool found = true;
  VariableType t = VariableType::vtDword;

  if (k == "byte" || k == "b" || k == "1" || k == "int8" || k == "uint8")
    t = VariableType::vtByte;
  else if (k == "word" || k == "w" || k == "2" || k == "short" || k == "int16" ||
           k == "uint16" || k == "2bytes")
    t = VariableType::vtWord;
  else if (k == "dword" || k == "d" || k == "4" || k == "int32" || k == "uint32" ||
           k == "4bytes" || k == "int" || k == "integer")
    t = VariableType::vtDword;
  else if (k == "qword" || k == "q" || k == "8" || k == "int64" || k == "uint64" ||
           k == "8bytes" || k == "long")
    t = VariableType::vtQword;
  else if (k == "float" || k == "single" || k == "f" || k == "4float")
    t = VariableType::vtSingle;
  else if (k == "double" || k == "dd" || k == "8float")
    t = VariableType::vtDouble;
  else if (k == "string" || k == "str" || k == "text" || k == "ascii")
    t = VariableType::vtString;
  else if (k == "wstring" || k == "unicodestring" || k == "unicode" || k == "wtext" ||
           k == "utf16")
    t = VariableType::vtUnicodeString;
  else if (k == "aob" || k == "bytearray" || k == "arrayofbytes" || k == "pattern" ||
           k == "sig" || k == "signature")
    t = VariableType::vtByteArray;
  else if (k == "binary" || k == "bin" || k == "bit")
    t = VariableType::vtBinary;
  else if (k == "all" || k == "any")
    t = VariableType::vtAll;
  else if (k == "aobs")
    t = VariableType::vtByteArrays;
  else
    found = false;

  if (ok) *ok = found;
  return t;
}

const char* VariableTypeName(VariableType t) {
  switch (t) {
    case VariableType::vtByte: return "byte";
    case VariableType::vtWord: return "word";
    case VariableType::vtDword: return "dword";
    case VariableType::vtQword: return "qword";
    case VariableType::vtSingle: return "float";
    case VariableType::vtDouble: return "double";
    case VariableType::vtString: return "string";
    case VariableType::vtUnicodeString: return "wstring";
    case VariableType::vtByteArray: return "aob";
    case VariableType::vtBinary: return "binary";
    case VariableType::vtAll: return "all";
    case VariableType::vtAutoAssembler: return "autoassembler";
    case VariableType::vtPointer: return "pointer";
    case VariableType::vtCustom: return "custom";
    case VariableType::vtGrouped: return "grouped";
    case VariableType::vtByteArrays: return "aobs";
    case VariableType::vtCodePageString: return "codepagestring";
  }
  return "unknown";
}

int VariableTypeSize(VariableType t) {
  switch (t) {
    case VariableType::vtByte: return 1;
    case VariableType::vtWord: return 2;
    case VariableType::vtDword: return 4;
    case VariableType::vtQword: return 8;
    case VariableType::vtSingle: return 4;
    case VariableType::vtDouble: return 8;
    case VariableType::vtBinary: return 8;
    case VariableType::vtAll: return 8;  // 取最大标量宽度
    default: return 0;                   // 变长（字符串 / 特征码）
  }
}

//-----------------------------------------------------------------------------
// 扫描方式
//-----------------------------------------------------------------------------
ScanOption ScanOptionFromName(const std::string& s, bool* ok) {
  const std::string k = Canonical(s);
  bool found = true;
  ScanOption o = ScanOption::soExactValue;

  if (k == "unknown" || k == "unknownvalue" || k == "unknowninitialvalue" || k == "u")
    o = ScanOption::soUnknownValue;
  else if (k == "exact" || k == "exactvalue" || k == "e" || k == "=" || k == "equal")
    o = ScanOption::soExactValue;
  else if (k == "between" || k == "valuebetween" || k == "range" || k == "btw")
    o = ScanOption::soValueBetween;
  else if (k == "bigger" || k == "biggerthan" || k == ">" || k == "greater")
    o = ScanOption::soBiggerThan;
  else if (k == "smaller" || k == "smallerthan" || k == "<" || k == "less")
    o = ScanOption::soSmallerThan;
  else if (k == "increased" || k == "increasedvalue" || k == "inc")
    o = ScanOption::soIncreasedValue;
  else if (k == "increasedby" || k == "increasedvalueby" || k == "incby")
    o = ScanOption::soIncreasedValueBy;
  else if (k == "decreased" || k == "decreasedvalue" || k == "dec")
    o = ScanOption::soDecreasedValue;
  else if (k == "decreasedby" || k == "decreasedvalueby" || k == "decby")
    o = ScanOption::soDecreasedValueBy;
  else if (k == "changed" || k == "chg")
    o = ScanOption::soChanged;
  else if (k == "unchanged" || k == "same" || k == "sameasfirst" || k == "un")
    o = ScanOption::soUnchanged;
  else
    found = false;

  if (ok) *ok = found;
  return o;
}

const char* ScanOptionName(ScanOption o) {
  switch (o) {
    case ScanOption::soUnknownValue: return "unknown";
    case ScanOption::soExactValue: return "exact";
    case ScanOption::soValueBetween: return "between";
    case ScanOption::soBiggerThan: return "bigger";
    case ScanOption::soSmallerThan: return "smaller";
    case ScanOption::soIncreasedValue: return "increased";
    case ScanOption::soIncreasedValueBy: return "increasedby";
    case ScanOption::soDecreasedValue: return "decreased";
    case ScanOption::soDecreasedValueBy: return "decreasedby";
    case ScanOption::soChanged: return "changed";
    case ScanOption::soUnchanged: return "unchanged";
    case ScanOption::soForgot: return "forgot";
    case ScanOption::soCustom: return "custom";
  }
  return "unknown";
}

bool ScanOptionNeedsValue(ScanOption o) {
  switch (o) {
    case ScanOption::soExactValue:
    case ScanOption::soValueBetween:
    case ScanOption::soBiggerThan:
    case ScanOption::soSmallerThan:
    case ScanOption::soIncreasedValueBy:
    case ScanOption::soDecreasedValueBy:
      return true;
    default:
      return false;
  }
}

bool ScanOptionNeedsSecondValue(ScanOption o) {
  return o == ScanOption::soValueBetween;
}

bool ScanOptionUsesPreviousValue(ScanOption o) {
  switch (o) {
    case ScanOption::soIncreasedValue:
    case ScanOption::soIncreasedValueBy:
    case ScanOption::soDecreasedValue:
    case ScanOption::soDecreasedValueBy:
    case ScanOption::soChanged:
    case ScanOption::soUnchanged:
      return true;
    default:
      return false;
  }
}

FastScanMethod FastScanMethodFromName(const std::string& s, bool* ok) {
  const std::string k = Canonical(s);
  bool found = true;
  FastScanMethod m = FastScanMethod::fsmAligned;

  if (k == "notaligned" || k == "none" || k == "off" || k == "0")
    m = FastScanMethod::fsmNotAligned;
  else if (k == "aligned" || k == "align" || k == "1")
    m = FastScanMethod::fsmAligned;
  else if (k == "lastdigits" || k == "digits" || k == "2")
    m = FastScanMethod::fsmLastDigits;
  else
    found = false;

  if (ok) *ok = found;
  return m;
}

const char* ScanRegionPreferenceName(ScanRegionPreference p) {
  switch (p) {
    case ScanRegionPreference::scanExclude: return "排除";
    case ScanRegionPreference::scanInclude: return "包含";
    default: return "不关心";
  }
}

std::string AllVariableTypeNames() {
  return "byte|word|dword|qword|float|double|string|wstring|aob|binary|all";
}

std::string AllScanOptionNames() {
  return "exact|between|bigger|smaller|unknown|increased|increasedby|decreased|decreasedby|changed|unchanged";
}

std::string AllFastScanMethodNames() { return "notaligned|aligned|lastdigits"; }

}  // namespace ce
