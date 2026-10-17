//=============================================================================
//  ScanEngine.cpp
//  内存扫描引擎实现 —— 逐段对应 memscan.pas 的原始算法。
//=============================================================================
#include "ScanEngine.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <numeric>

#include "CEUtil.h"

namespace ce {
namespace {

constexpr size_t kChunkSize = 1u << 20;
constexpr size_t kReadSlack = 64;        
constexpr ptruint kPageMask = ~static_cast<ptruint>(0xFFF);
constexpr qword kMaxImageBytes = 8ull * 1024 * 1024 * 1024;  // 未知值镜像上限 8GB

inline ptruint PageOf(ptruint a) { return a & kPageMask; }

bool IsNegativeLiteral(const std::string& s) {
  const std::string t = util::Trim(s);
  return !t.empty() && t[0] == '-';
}

// 排序 + 合并重叠区间
void MergeIntervals(std::vector<AddressRange>* v) {
  if (v == nullptr || v->empty()) return;
  std::sort(v->begin(), v->end(),
            [](const AddressRange& a, const AddressRange& b) { return a.start < b.start; });
  std::vector<AddressRange> merged;
  merged.push_back((*v)[0]);
  for (size_t i = 1; i < v->size(); ++i) {
    AddressRange& last = merged.back();
    if ((*v)[i].start <= last.stop) {
      last.stop = std::max(last.stop, (*v)[i].stop);
    } else {
      merged.push_back((*v)[i]);
    }
  }
  v->swap(merged);
}

// 与区间集合的重叠字节数
qword OverlapBytes(const std::vector<MemoryRegion>& regions,
                   const std::vector<AddressRange>& intervals) {
  if (intervals.empty()) return 0;
  qword total = 0;
  for (const MemoryRegion& r : regions) {
    const AddressRange region{r.BaseAddress, r.BaseAddress + r.MemorySize};
    for (const AddressRange& iv : intervals) {
      const ptruint lo = std::max(region.start, iv.start);
      const ptruint hi = std::min(region.stop, iv.stop);
      if (hi > lo) total += static_cast<qword>(hi - lo);
    }
  }
  return total;
}

// 一个待扫描的数据块
struct Task {
  ptruint regionBase = 0;
  qword regionSize = 0;
  ptruint chunkStart = 0;
  size_t chunkLen = 0;
};

// 工作线程上下文
struct WorkerContext {
  ScanEngine* engine = nullptr;
  const std::vector<Task>* tasks = nullptr;
  size_t taskBegin = 0;
  size_t taskEnd = 0;
  ScanEngine::ResultBuffer* out = nullptr;
  std::atomic<qword>* scanned = nullptr;
  std::atomic<bool>* cancelFlag = nullptr;
  qword valueSize = 1;
  qword stepSize = 1;
  qword startOffset = 0;
};

// 计算“本块起始处”在相位序列中的第一个候选偏移
inline qword FirstCandidateOffset(qword offsetInRegion, qword startOffset, qword stepSize) {
  if (offsetInRegion >= startOffset) {
    const qword d = offsetInRegion - startOffset;
    const qword k = (d + stepSize - 1) / stepSize;
    return startOffset + k * stepSize - offsetInRegion;
  }
  return startOffset - offsetInRegion;
}

int HardwareThreads() {
  SYSTEM_INFO si{};
  ::GetNativeSystemInfo(&si);
  const int n = static_cast<int>(si.dwNumberOfProcessors);
  return n > 0 ? n : 1;
}

}  // namespace

//=============================================================================
//  工作线程主体（对应 CE 的 TScanner.execute）
//=============================================================================
DWORD WINAPI ScanEngine::ScanWorkerProc(void* context) {
  auto* ctx = static_cast<WorkerContext*>(context);
  if (ctx == nullptr || ctx->engine == nullptr) return 0;

  ScanEngine* engine = ctx->engine;
  std::vector<ubyte> buffer;
  const size_t overlap =
      ctx->valueSize > 1 ? static_cast<size_t>(ctx->valueSize - 1) : static_cast<size_t>(0);

  for (size_t i = ctx->taskBegin; i < ctx->taskEnd; ++i) {
    if (ctx->cancelFlag->load() || engine->cancelled_.load()) break;

    const Task& t = (*ctx->tasks)[i];
    const qword offsetInRegion = static_cast<qword>(t.chunkStart - t.regionBase);
    const qword firstPos = FirstCandidateOffset(offsetInRegion, ctx->startOffset, ctx->stepSize);

    // 读取长度 = 本块 + 跨块重叠，且不超过所在区域末尾
    const qword regionRemaining = t.regionSize - offsetInRegion;
    size_t want = t.chunkLen + overlap;
    if (static_cast<qword>(want) > regionRemaining) want = static_cast<size_t>(regionRemaining);
    if (want > t.chunkLen + overlap) want = t.chunkLen + overlap;

    buffer.assign(want + static_cast<size_t>(ctx->valueSize) + kReadSlack, 0);
    const size_t got = engine->process_.ReadPartial(t.chunkStart, buffer.data(), want);

    // 本块只负责偏移不超过 chunkLen-1 的位置，跨块部分交给下一块，避免重复
    const qword lastPosInChunk = static_cast<qword>(t.chunkLen) - 1;
    if (got >= static_cast<size_t>(ctx->valueSize)) {
      engine->ScanChunk(t.chunkStart, buffer.data(), got, firstPos, lastPosInChunk, ctx->out);
    }

    ctx->scanned->fetch_add(static_cast<qword>(t.chunkLen));
  }
  return 0;
}

//=============================================================================
//  构造 / 析构 / 重置
//=============================================================================
ScanEngine::ScanEngine(ProcessMemory& process) : process_(process) {}
ScanEngine::~ScanEngine() { ReleaseImage(); }

void ScanEngine::ReleaseImage() {
  if (imageBase_ != nullptr) {
    ::VirtualFree(imageBase_, 0, MEM_RELEASE);
    imageBase_ = nullptr;
  }
  imageSize_ = 0;
  imageRegions_.clear();
}

void ScanEngine::Reset() {
  addresses_.clear();
  memory_.clear();
  regions_.clear();
  stats_ = ScanStats{};
  mode_ = ScanMode::kNone;
  cancelled_ = false;
  lastError_.clear();
  ReleaseImage();
}

void ScanEngine::SetError(const std::string& message) { lastError_ = message; }

//=============================================================================
//  参数计算：值宽度 / 步进 / 对齐
//  移植 TScanController.fillVariableAndFastScanAlignSize (memscan.pas:6117)
//=============================================================================
bool ScanEngine::CalculateValueSize(const ScanRequest& request, std::string* error) {
  const VariableType type = request.variableType;
  const bool unknown = (request.scanOption == ScanOption::soUnknownValue);

  int align = 1;
  int size = 0;

  switch (type) {
    case VariableType::vtByte:
      size = 1;
      align = 1;
      break;
    case VariableType::vtWord:
      size = 2;
      align = 2;
      break;
    case VariableType::vtDword:
      size = 4;
      align = 4;
      break;
    case VariableType::vtQword:
      size = 8;
      align = 4;
      break;
    case VariableType::vtSingle:
      size = 4;
      align = 4;
      break;
    case VariableType::vtDouble:
      size = 8;
      align = 4;
      break;
    case VariableType::vtAll:
      size = 8;
      align = 1;
      break;
    case VariableType::vtByteArray:
    case VariableType::vtByteArrays: {
      if (unknown) {
        size = 1;
      } else {
        size = 0;
        for (const AobPattern& p : request.aobPatterns) {
          if (p.valid) size = std::max(size, p.Length());
        }
        if (size <= 0) {
          if (error) *error = "特征码为空";
          return false;
        }
      }
      align = 1;
      break;
    }
    case VariableType::vtString:
    case VariableType::vtUnicodeString: {
      const std::string& s = request.scanString.empty() ? request.value1 : request.scanString;
      if (unknown) {
        size = 1;
      } else {
        if (s.empty()) {
          if (error) *error = "字符串为空";
          return false;
        }
        size = static_cast<int>(s.size());
        if (type == VariableType::vtUnicodeString) size *= 2;
      }
      align = 1;
      break;
    }
    default:
      if (error) {
        *error = std::string("暂不支持的数据类型: ") + VariableTypeName(type) +
                 "（binary / grouped / custom 等特殊类型尚未移植）";
      }
      return false;
  }

  valueSize_ = size;

  fastScanAlignSize_ = (request.fastScanAlignSize > 0) ? request.fastScanAlignSize : align;
  fastScanDigitCount_ = request.fastScanDigitCount > 0 ? request.fastScanDigitCount : 1;
  fastScanMethod_ = request.fastScanMethod;

  startOffset_ = 0;
  if (request.fastScanMethod == FastScanMethod::fsmAligned) {
    stepSize_ = static_cast<qword>(fastScanAlignSize_);
  } else if (request.fastScanMethod == FastScanMethod::fsmLastDigits) {
    qword s = 1;
    for (int i = 0; i < fastScanDigitCount_; ++i) s *= 16;
    stepSize_ = s;
    startOffset_ = static_cast<qword>(fastScanAlignSize_);
  } else {
    stepSize_ = 1;
  }

  if (request.isUnique || request.onlyOne) {
    stepSize_ = 1;
    startOffset_ = 0;
  }
  if (stepSize_ < 1) stepSize_ = 1;

  return true;
}

//=============================================================================
//  数值解析：configurescanroutine (memscan.pas:4564)
//=============================================================================
bool ScanEngine::ConfigureScanRoutine(const ScanRequest& request, std::string* error) {
  value_ = 0;
  value2_ = 0;
  dvalue_ = 0.0;
  dvalue2_ = 0.0;
  svalue_ = 0.0;
  svalue2_ = 0.0;
  mindvalue_ = 0.0;
  maxdvalue_ = 0.0;
  minsvalue_ = 0.0;
  maxsvalue_ = 0.0;
  floatAccuracy_ = 0;

  scanOption_ = request.scanOption;
  currentType_ = request.variableType;
  percentage_ = request.percentage;
  hexadecimal_ = request.hexadecimal;
  caseSensitive_ = request.caseSensitive;
  roundingType_ = request.roundingType;
  onlyOne_ = request.onlyOne;
  inverseScan_ = request.inverseScan;

  signedMode_ = IsNegativeLiteral(request.value1) || IsNegativeLiteral(request.value2);

  const VariableType type = request.variableType;
  const bool isFloatType = (type == VariableType::vtSingle || type == VariableType::vtDouble);
  const bool isAll = (type == VariableType::vtAll);

  //--- 1. 需要用户输入数值的模式 ------------------------------------------
  if (ScanOptionNeedsValue(scanOption_)) {
    if (util::Trim(request.value1).empty()) {
      if (error) *error = "该扫描方式需要提供数值（--value）";
      return false;
    }

    const bool integerType = (type == VariableType::vtByte || type == VariableType::vtWord ||
                              type == VariableType::vtDword || type == VariableType::vtQword ||
                              isAll);

    if (integerType) {
      bool neg = false;
      if (!util::ParseInteger(request.value1, hexadecimal_, &value_, &neg)) {
        if (isAll || percentage_) {
          double d = 0.0;
          if (percentage_) {
            if (!util::ParsePercentage(request.value1, &d)) d = 0.0;
          } else {
            if (!util::ParseFloat(request.value1, &d)) d = 0.0;
          }
          value_ = static_cast<qword>(static_cast<long long>(std::trunc(d)));
        } else {
          if (error) *error = "不是合法的数值: " + request.value1;
          return false;
        }
      }

      if (scanOption_ == ScanOption::soValueBetween) {
        if (!util::ParseInteger(request.value2, hexadecimal_, &value2_, &neg)) {
          if (isAll || percentage_) {
            double d = 0.0;
            if (percentage_) {
              if (!util::ParsePercentage(request.value2, &d)) d = 0.0;
            } else {
              if (!util::ParseFloat(request.value2, &d)) d = 0.0;
            }
            value2_ = static_cast<qword>(static_cast<long long>(std::trunc(d)));
          } else {
            if (error) *error = "不是合法的数值（第二个值）: " + request.value2;
            return false;
          }
        }
      }
    }
  }

  //--- 2. 浮点 / 百分比 阈值 ---------------------------------------------
  if (percentage_ || isFloatType || isAll) {
    double d1 = 0.0;
    double d2 = 0.0;

    const bool hasValue1 = !util::Trim(request.value1).empty();
    const bool hasValue2 = !util::Trim(request.value2).empty();

    if (hasValue1) {
      if (percentage_) {
        if (!util::ParsePercentage(request.value1, &d1)) d1 = 0.0;
      } else if (!util::ParseFloat(request.value1, &d1)) {
        if (isFloatType) {
          if (error) *error = "不是合法的浮点数: " + request.value1;
          return false;
        }
        d1 = 0.0;
      }
    }

    if (percentage_ || scanOption_ == ScanOption::soValueBetween) {
      if (!hasValue2) {
        // 宽容处理：未给出第二个值时沿用第一个（CE 原版此处会直接报错）
        d2 = d1;
      } else if (percentage_) {
        if (!util::ParsePercentage(request.value2, &d2)) d2 = d1;
      } else if (!util::ParseFloat(request.value2, &d2)) {
        if (isFloatType) {
          if (error) *error = "不是合法的浮点数（第二个值）: " + request.value2;
          return false;
        }
        d2 = d1;
      }
    } else {
      d2 = d1;
    }

    if (percentage_) {
      if (d1 > d2) std::swap(d1, d2);
      d1 /= 100.0;
      d2 /= 100.0;
    }

    svalue_ = d1;
    svalue2_ = d2;

    // floataccuracy：按输入字符串的小数位数推断（memscan.pas:4845）
    if (request.floatAccuracy >= 0) {
      floatAccuracy_ = request.floatAccuracy;
    } else {
      floatAccuracy_ = util::ComputeFloatAccuracy(request.value1);
    }

    if (floatAccuracy_ != 0 && !percentage_) {
      svalue_ = util::RoundTo(svalue_, -floatAccuracy_);
      svalue2_ = util::RoundTo(svalue2_, -floatAccuracy_);
      d1 = util::RoundTo(d1, -floatAccuracy_);
      d2 = util::RoundTo(d2, -floatAccuracy_);
    }

    dvalue_ = d1;
    dvalue2_ = d2;

    if (floatAccuracy_ != 0) {
      const double eps = 1.0 / std::pow(10.0, static_cast<double>(floatAccuracy_));
      mindvalue_ = dvalue_ - eps;
      maxdvalue_ = dvalue_ + eps;
      minsvalue_ = svalue_ - eps;
      maxsvalue_ = svalue_ + eps;
    } else {
      mindvalue_ = dvalue_ - 1.0;
      maxdvalue_ = dvalue_ + 1.0;
      minsvalue_ = svalue_ - 1.0;
      maxsvalue_ = svalue_ + 1.0;
    }
  }

  // 递增/递减“固定值”为 0 时，CE 会退化成普通的递增/递减判定
  if ((scanOption_ == ScanOption::soIncreasedValueBy ||
       scanOption_ == ScanOption::soDecreasedValueBy) &&
      value_ == 0 && dvalue_ == 0.0 && !percentage_) {
    scanOption_ = (scanOption_ == ScanOption::soIncreasedValueBy)
                      ? ScanOption::soIncreasedValue
                      : ScanOption::soDecreasedValue;
  }

  //--- 3. 字符串 / 特征码 -------------------------------------------------
  textPattern_.clear();
  if (type == VariableType::vtString || type == VariableType::vtUnicodeString) {
    const std::string& s = request.scanString.empty() ? request.value1 : request.scanString;
    if (type == VariableType::vtUnicodeString) {
      const std::wstring w = util::Utf8ToWide(s);
      textPattern_.resize(w.size() * 2);
      if (!w.empty()) std::memcpy(&textPattern_[0], w.data(), textPattern_.size());
    } else {
      textPattern_ = s;
    }
  }

  aobPatterns_ = request.aobPatterns;
  if ((type == VariableType::vtByteArray || type == VariableType::vtByteArrays) &&
      aobPatterns_.empty()) {
    const AobPattern p = ParseAobPattern(request.value1, true);
    if (!p.valid) {
      if (error) *error = "特征码解析失败: " + p.error;
      return false;
    }
    aobPatterns_.push_back(p);
  }
  for (const AobPattern& p : aobPatterns_) {
    if (!p.valid) {
      if (error) *error = "特征码解析失败: " + p.error;
      return false;
    }
  }

  return true;
}

//=============================================================================
//  区域枚举 + 排除过滤
//  移植 TScanController.firstScan 的区域循环 (memscan.pas:6978-7288)
//=============================================================================
bool ScanEngine::BuildRegions(const ScanRequest& request, std::string* error) {
  regions_.clear();
  stats_.regionCount = 0;
  stats_.regionSkipped = 0;
  stats_.totalBytes = 0;

  const RegionFilter& filter = request.regionFilter;

  //--- 地址区间规则预处理 ------------------------------------------------
  mergedExclude_.clear();
  mergedInclude_.clear();
  hasRangeRules_ = false;

  for (const AddressRange& r : filter.excludeRanges) {
    if (r.stop > r.start) mergedExclude_.push_back(r);
  }
  for (const AddressRange& r : filter.includeRanges) {
    if (r.stop > r.start) mergedInclude_.push_back(r);
  }
  MergeIntervals(&mergedExclude_);
  MergeIntervals(&mergedInclude_);
  hasRangeRules_ = !mergedExclude_.empty() || !mergedInclude_.empty();

  //--- 地址窗口 ----------------------------------------------------------
  ptruint minAddress = 0;
  ptruint maxAddress = 0;
  process_.AddressRange(&minAddress, &maxAddress);

  ptruint start = filter.startAddress != 0 ? filter.startAddress : minAddress;
  ptruint stop = filter.stopAddress != 0 ? filter.stopAddress : maxAddress;
  if (start < minAddress) start = minAddress;
  if (stop > maxAddress) stop = maxAddress;
  if (start >= stop) {
    if (error) *error = "扫描范围为空";
    return false;
  }

  // CE：非 onlyOne / isUnique 时把起点向下对齐到 8 字节
  if (!request.onlyOne && !request.isUnique) {
    if ((start % 8) != 0) start -= (start % 8);
  }

  const std::vector<ModuleEntry>& modules = process_.CachedModules();

  qword total = 0;
  ptruint current = start;
  MEMORY_BASIC_INFORMATION mbi{};

  while (current < stop) {
    if (::VirtualQueryEx(process_.Handle(), reinterpret_cast<LPCVOID>(current), &mbi,
                         sizeof(mbi)) == 0) {
      break;
    }

    const ptruint rawBase = reinterpret_cast<ptruint>(mbi.BaseAddress);
    const qword rawSize = static_cast<qword>(mbi.RegionSize);
    if (rawSize == 0) break;

    // 64 位溢出保护（对应 CE 的 currentBaseAddress+mbi.RegionSize>currentBaseAddress）
    const ptruint next = rawBase + static_cast<ptruint>(rawSize);
    if (next <= rawBase) break;

    ptruint base = rawBase;
    qword size = rawSize;
    if (base < start) {
      size -= static_cast<qword>(start - base);
      base = start;
    }
    if (base + size > stop) size = static_cast<qword>(stop - base);

    if (size > 0) {
      const RegionDecision decision = EvaluateRegion(mbi, filter, modules);
      if (decision.valid) {
        MemoryRegion region;
        region.BaseAddress = base;
        region.MemorySize = size;
        region.startaddress = total;  // 未知值扫描时在镜像中的起始偏移
        regions_.push_back(region);
        total += size;
        ++stats_.regionCount;
      } else {
        ++stats_.regionSkipped;
      }
    }

    current = next;
  }

  if (regions_.empty()) {
    if (error) {
      *error = "在当前的排除条件下没有任何可扫描的内存区域";
      if (stats_.regionSkipped > 0) {
        *error += "（已跳过 " + std::to_string(stats_.regionSkipped) + " 个区域）";
      }
    }
    return false;
  }

  //--- 统计真正会被扫描的字节数（扣除区间排除）--------------------------
  qword effective = total;
  if (!mergedExclude_.empty()) effective -= OverlapBytes(regions_, mergedExclude_);
  if (!mergedInclude_.empty()) effective = OverlapBytes(regions_, mergedInclude_);
  stats_.totalBytes = effective;

  return true;
}

//=============================================================================
//  地址区间拦截
//=============================================================================
bool ScanEngine::AddressBlocked(ptruint address) const {
  if (!hasRangeRules_) return false;

  if (!mergedExclude_.empty()) {
    const auto it = std::upper_bound(
        mergedExclude_.begin(), mergedExclude_.end(), address,
        [](ptruint value, const AddressRange& r) { return value < r.start; });
    if (it != mergedExclude_.begin()) {
      const AddressRange& prev = *(it - 1);
      if (address >= prev.start && address < prev.stop) return true;
    }
  }

  if (!mergedInclude_.empty()) {
    const auto it = std::upper_bound(
        mergedInclude_.begin(), mergedInclude_.end(), address,
        [](ptruint value, const AddressRange& r) { return value < r.start; });
    if (it == mergedInclude_.begin()) return true;
    const AddressRange& prev = *(it - 1);
    if (!(address >= prev.start && address < prev.stop)) return true;
  }

  return false;
}

//=============================================================================
//  判定函数族
//=============================================================================
template <typename T, typename TS>
bool ScanEngine::CompareIntegral(const ubyte* newValue, const ubyte* oldValue) const {
  const T n = ReadAs<T>(newValue);
  const T o = oldValue != nullptr ? ReadAs<T>(oldValue) : static_cast<T>(0);

  //--- 百分比模式（memscan.pas: ByteBetweenPercentage 等）---------------
  if (percentage_) {
    const double nd = static_cast<double>(n);
    const double od = static_cast<double>(o);
    switch (scanOption_) {
      case ScanOption::soValueBetween:
        return nd > std::trunc(od * svalue_) && nd <= std::trunc(od * svalue2_);
      case ScanOption::soIncreasedValueBy:
        return nd > std::trunc(od + od * svalue_) && nd < std::trunc(od + od * svalue2_);
      case ScanOption::soDecreasedValueBy:
        return nd > std::trunc(od - od * svalue2_) && nd < std::trunc(od - od * svalue_);
      default:
        return false;
    }
  }

  const T v1 = static_cast<T>(value_);
  const T v2 = static_cast<T>(value2_);

  switch (scanOption_) {
    case ScanOption::soUnknownValue:
    case ScanOption::soForgot:
      return true;

    case ScanOption::soExactValue:
      return n == v1;

    case ScanOption::soValueBetween:
      if (signedMode_) {
        return static_cast<TS>(n) >= static_cast<TS>(v1) &&
               static_cast<TS>(n) <= static_cast<TS>(v2);
      }
      return n >= v1 && n <= v2;

    case ScanOption::soBiggerThan:
      return n > v1;

    case ScanOption::soSmallerThan:
      return n < v1;

    case ScanOption::soIncreasedValue:
      return n > o;

    case ScanOption::soIncreasedValueBy:
      // 在 64 位域内做加减后截断，等价于 Pascal 的定宽回绕
      return n == static_cast<T>(static_cast<qword>(o) + static_cast<qword>(v1));

    case ScanOption::soDecreasedValue:
      return n < o;

    case ScanOption::soDecreasedValueBy:
      return n == static_cast<T>(static_cast<qword>(o) - static_cast<qword>(v1));

    case ScanOption::soChanged:
      return n != o;

    case ScanOption::soUnchanged:
      return n == o;

    default:
      return false;
  }
}

template <typename T>
bool ScanEngine::CompareFloat(const ubyte* newValue, const ubyte* oldValue) const {
  const double n = static_cast<double>(ReadAs<T>(newValue));
  const double o = oldValue != nullptr ? static_cast<double>(ReadAs<T>(oldValue)) : 0.0;

  const bool isSingle = (sizeof(T) == sizeof(float));
  const double v1 = isSingle ? svalue_ : dvalue_;
  const double v2 = isSingle ? svalue2_ : dvalue2_;
  const double minv = isSingle ? minsvalue_ : mindvalue_;
  const double maxv = isSingle ? maxsvalue_ : maxdvalue_;

  if (percentage_) {
    switch (scanOption_) {
      case ScanOption::soValueBetween:
        return n > o * v1 && n <= o * v2;
      case ScanOption::soIncreasedValueBy:
        return n > o + o * v1 && n < o + o * v2;
      case ScanOption::soDecreasedValueBy:
        return n > o - o * v2 && n < o - o * v1;
      default:
        return false;
    }
  }

  switch (scanOption_) {
    case ScanOption::soUnknownValue:
    case ScanOption::soForgot:
      return true;

    case ScanOption::soExactValue:
      switch (roundingType_) {
        case RoundingType::rtRounded:
          return util::RoundTo(n, -floatAccuracy_) == util::RoundTo(v1, -floatAccuracy_);
        case RoundingType::rtExtremerounded:
          return n >= minv && n <= maxv;
        case RoundingType::rtTruncated:
          return n >= v1 && n < maxv;
      }
      return false;

    case ScanOption::soValueBetween:
      return n >= v1 && n <= v2;

    case ScanOption::soBiggerThan:
      return n > v1;

    case ScanOption::soSmallerThan:
      return n < v1;

    case ScanOption::soIncreasedValue:
      return n > o;

    case ScanOption::soIncreasedValueBy:
      return n == o + v1;

    case ScanOption::soDecreasedValue:
      return n < o;

    case ScanOption::soDecreasedValueBy:
      return n == o - v1;

    case ScanOption::soChanged:
      return n != o;

    case ScanOption::soUnchanged:
      return n == o;

    default:
      return false;
  }
}

namespace {

bool CompareBytes(const ubyte* a, const ubyte* b, size_t n, bool caseSensitive) {
  if (caseSensitive) return std::memcmp(a, b, n) == 0;
  for (size_t i = 0; i < n; ++i) {
    ubyte x = a[i];
    ubyte y = b[i];
    if (x >= 'A' && x <= 'Z') x = static_cast<ubyte>(x + 32);
    if (y >= 'A' && y <= 'Z') y = static_cast<ubyte>(y + 32);
    if (x != y) return false;
  }
  return true;
}

}  // namespace

//-----------------------------------------------------------------------------
//  总判定入口（对应 configurescanroutine 选出的 checkroutine）
//-----------------------------------------------------------------------------
bool ScanEngine::CheckValue(ptruint address, const ubyte* newValue, const ubyte* oldValue) const {
  //--- 特征码 ------------------------------------------------------------
  if (currentType_ == VariableType::vtByteArray || currentType_ == VariableType::vtByteArrays) {
    for (const AobPattern& p : aobPatterns_) {
      if (p.valid && MatchAobAuto(newValue, p)) return !inverseScan_;
    }
    return inverseScan_;
  }

  //--- 字符串 ------------------------------------------------------------
  if (currentType_ == VariableType::vtString || currentType_ == VariableType::vtUnicodeString) {
    if (textPattern_.empty()) return inverseScan_;
    const bool hit =
        CompareBytes(newValue, reinterpret_cast<const ubyte*>(textPattern_.data()), textPattern_.size(), caseSensitive_);
    return hit != inverseScan_;
  }

  //--- vtAll：逐个标量类型尝试，任一命中即算命中 (memscan.pas:1785) ------
  if (currentType_ == VariableType::vtAll) {
    const bool fast = (fastScanMethod_ != FastScanMethod::fsmNotAligned);
    const bool d2 = fast ? ((address % 2) == 0) : true;
    const bool d4 = fast ? ((address % 4) == 0) : true;

    // CE 的 vtAll 分支不再套用外层 xor，而是每个子类型各自 xor
    auto match = [this](bool r) { return r != inverseScan_; };

    bool any = false;
    any = any || match(CompareIntegral<ubyte, std::int8_t>(newValue, oldValue));
    any = any || (d2 && match(CompareIntegral<uword, std::int16_t>(newValue, oldValue)));
    any = any || (d4 && match(CompareIntegral<dword, std::int32_t>(newValue, oldValue)));
    any = any || (d4 && match(CompareIntegral<qword, std::int64_t>(newValue, oldValue)));
    any = any || (d4 && match(CompareFloat<float>(newValue, oldValue)));
    any = any || (d4 && match(CompareFloat<double>(newValue, oldValue)));
    return any;
  }

  //--- 标量 --------------------------------------------------------------
  bool hit = false;
  switch (currentType_) {
    case VariableType::vtByte:
      hit = CompareIntegral<ubyte, std::int8_t>(newValue, oldValue);
      break;
    case VariableType::vtWord:
      hit = CompareIntegral<uword, std::int16_t>(newValue, oldValue);
      break;
    case VariableType::vtDword:
      hit = CompareIntegral<dword, std::int32_t>(newValue, oldValue);
      break;
    case VariableType::vtQword:
      hit = CompareIntegral<qword, std::int64_t>(newValue, oldValue);
      break;
    case VariableType::vtSingle:
      hit = CompareFloat<float>(newValue, oldValue);
      break;
    case VariableType::vtDouble:
      hit = CompareFloat<double>(newValue, oldValue);
      break;
    default:
      return false;
  }
  return hit != inverseScan_;
}

//=============================================================================
//  单块扫描（对应 TScanner.FirstScanmem，memscan.pas:3859）
//=============================================================================
void ScanEngine::ScanChunk(ptruint bufferAddress, const ubyte* buffer, size_t validSize,
                           qword firstPos, qword lastPosInclusive, ResultBuffer* out) const {
  if (out == nullptr || buffer == nullptr) return;
  if (valueSize_ <= 0) return;
  if (validSize < static_cast<size_t>(valueSize_)) return;

  const qword maxByBuffer = static_cast<qword>(validSize - static_cast<size_t>(valueSize_));
  qword lastPos = lastPosInclusive;
  if (lastPos > maxByBuffer) lastPos = maxByBuffer;
  if (firstPos > lastPos) return;

  for (qword pos = firstPos; pos <= lastPos; pos += stepSize_) {
    const ubyte* p = buffer + pos;
    const ptruint address = bufferAddress + pos;

    if (hasRangeRules_ && AddressBlocked(address)) continue;

    if (CheckValue(address, p, nullptr)) {
      out->Add(address, p, valueSize_);
      if (onlyOne_) return;
    }
  }
}

//=============================================================================
//  结果合并
//=============================================================================
void ScanEngine::MergeResults(std::vector<ResultBuffer>& buffers, bool sortByAddress) {
  size_t total = 0;
  for (const ResultBuffer& b : buffers) total += b.Count();

  addresses_.clear();
  memory_.clear();
  addresses_.reserve(total);
  memory_.reserve(total * static_cast<size_t>(valueSize_));

  for (ResultBuffer& b : buffers) {
    addresses_.insert(addresses_.end(), b.addresses.begin(), b.addresses.end());
    memory_.insert(memory_.end(), b.memory.begin(), b.memory.end());
  }

  if (!sortByAddress || addresses_.size() < 2) return;

  // 快速路径：地址已升序（各线程按连续区块分配任务时几乎总是成立）
  bool sorted = true;
  for (size_t i = 1; i < addresses_.size(); ++i) {
    if (addresses_[i] < addresses_[i - 1]) {
      sorted = false;
      break;
    }
  }
  if (sorted) return;

  const size_t n = addresses_.size();
  const size_t vs = static_cast<size_t>(valueSize_);

  std::vector<size_t> idx(n);
  std::iota(idx.begin(), idx.end(), static_cast<size_t>(0));
  std::sort(idx.begin(), idx.end(),
            [this](size_t a, size_t b) { return addresses_[a] < addresses_[b]; });

  std::vector<ptruint> sortedAddresses(n);
  std::vector<ubyte> sortedMemory(n * vs);
  for (size_t i = 0; i < n; ++i) {
    sortedAddresses[i] = addresses_[idx[i]];
    std::memcpy(&sortedMemory[i * vs], &memory_[idx[i] * vs], vs);
  }
  addresses_.swap(sortedAddresses);
  memory_.swap(sortedMemory);
}

//=============================================================================
//  首次扫描（TScanner.firstscan / TScanController.firstScan）
//=============================================================================
bool ScanEngine::FirstScan(const ScanRequest& request, std::string* error) {
  Reset();

  if (!process_.IsOpen()) {
    SetError("尚未附加到任何进程");
    if (error) *error = lastError_;
    return false;
  }

  util::Stopwatch stopwatch;

  if (!CalculateValueSize(request, error)) return false;
  if (!ConfigureScanRoutine(request, error)) return false;
  if (!BuildRegions(request, error)) return false;

  isAobMode_ =
      (currentType_ == VariableType::vtByteArray || currentType_ == VariableType::vtByteArrays);

  //--- 未知初始值：保存整块旧内存镜像（memscan.pas:7323-7347）----------
  if (request.scanOption == ScanOption::soUnknownValue) {
    if (stats_.totalBytes == 0 || stats_.totalBytes > kMaxImageBytes) {
      if (error) {
        *error = "未知初始值扫描需要把整块内存保存为镜像，当前需要 " +
                 util::FormatSize(stats_.totalBytes) + "，超过上限 " +
                 util::FormatSize(kMaxImageBytes) +
                 "。请用 --exclude-module / --exclude-range 缩小范围。";
      }
      return false;
    }

    void* image = ::VirtualAlloc(nullptr, static_cast<SIZE_T>(stats_.totalBytes) + 8192,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (image == nullptr) {
      if (error) {
        *error =
            "为未知值扫描分配内存镜像失败（需要 " + util::FormatSize(stats_.totalBytes) + "）";
      }
      return false;
    }
    imageBase_ = image;
    imageSize_ = stats_.totalBytes;
    imageRegions_ = regions_;

    auto* base = static_cast<ubyte*>(image);
    qword done = 0;
    for (const MemoryRegion& r : regions_) {
      ubyte* dst = base + r.startaddress;
      const size_t got = process_.ReadPartial(r.BaseAddress, dst, static_cast<size_t>(r.MemorySize));
      if (got < r.MemorySize) {
        std::memset(dst + got, 0, static_cast<size_t>(r.MemorySize) - got);
      }
      done += r.MemorySize;
      if (progress_) progress_(done, stats_.totalBytes);
    }

    addresses_.clear();
    memory_.clear();
    mode_ = ScanMode::kMemoryImage;
    stats_.scannedBytes = stats_.totalBytes;
    stats_.threadCount = 1;
    stats_.elapsedSeconds = stopwatch.Elapsed();
    return true;
  }

  //--- 普通首次扫描：分块 + 多线程 ---------------------------------------
  std::vector<Task> tasks;
  for (const MemoryRegion& r : regions_) {
    for (qword off = 0; off < r.MemorySize; off += kChunkSize) {
      Task t;
      t.regionBase = r.BaseAddress;
      t.regionSize = r.MemorySize;
      t.chunkStart = r.BaseAddress + off;
      t.chunkLen = static_cast<size_t>(
          std::min<qword>(static_cast<qword>(kChunkSize), r.MemorySize - off));
      tasks.push_back(t);
    }
  }

  if (tasks.empty()) {
    if (error) *error = "没有可扫描的数据块";
    return false;
  }

  int threadCount = request.threadCount > 0 ? request.threadCount : HardwareThreads();
  if (threadCount < 1) threadCount = 1;
  if (onlyOne_ || request.isUnique) threadCount = 1;
  if (tasks.size() < 4) threadCount = 1;
  if (threadCount > static_cast<int>(tasks.size())) threadCount = static_cast<int>(tasks.size());
  if (threadCount > 64) threadCount = 64;
  stats_.threadCount = threadCount;

  std::vector<ResultBuffer> buffers(static_cast<size_t>(threadCount));

  // 按累计字节数把任务切成连续区块，使结果天然保持地址升序
  std::vector<qword> prefix(tasks.size() + 1, 0);
  for (size_t i = 0; i < tasks.size(); ++i) {
    prefix[i + 1] = prefix[i] + static_cast<qword>(tasks[i].chunkLen);
  }
  const qword grandTotal = prefix.back();

  std::vector<WorkerContext> contexts(static_cast<size_t>(threadCount));
  size_t taskCursor = 0;
  for (int t = 0; t < threadCount; ++t) {
    const qword want =
        grandTotal * static_cast<qword>(t + 1) / static_cast<qword>(threadCount);
    size_t end = taskCursor;
    while (end < tasks.size() && prefix[end] < want) ++end;
    if (end == taskCursor && taskCursor < tasks.size()) end = taskCursor + 1;
    if (t == threadCount - 1) end = tasks.size();

    WorkerContext& ctx = contexts[static_cast<size_t>(t)];
    ctx.engine = this;
    ctx.tasks = &tasks;
    ctx.taskBegin = taskCursor;
    ctx.taskEnd = end;
    ctx.out = &buffers[static_cast<size_t>(t)];
    ctx.scanned = &scannedBytes_;
    ctx.cancelFlag = &cancelFlag_;
    ctx.valueSize = static_cast<qword>(valueSize_);
    ctx.stepSize = stepSize_;
    ctx.startOffset = startOffset_;

    taskCursor = end;
  }

  scannedBytes_.store(0);
  cancelFlag_.store(false);

  std::vector<HANDLE> handles;
  handles.reserve(static_cast<size_t>(threadCount));
  for (int t = 0; t < threadCount; ++t) {
    HANDLE h = ::CreateThread(nullptr, 0, &ScanEngine::ScanWorkerProc,
                              &contexts[static_cast<size_t>(t)], 0, nullptr);
    if (h == nullptr) break;
    handles.push_back(h);
  }

  if (handles.empty()) {
    // 线程创建失败：在当前线程直接跑完
    std::vector<ResultBuffer> single(1);
    WorkerContext ctx = contexts[0];
    ctx.out = &single[0];
    ScanWorkerProc(&ctx);
    scannedBytes_.store(grandTotal);
    if (progress_) progress_(grandTotal, stats_.totalBytes);
    MergeResults(single, true);
    mode_ = ScanMode::kResultList;
    stats_.scannedBytes = scannedBytes_.load();
    stats_.elapsedSeconds = stopwatch.Elapsed();
    return true;
  }

  // 主线程负责等待与进度汇报
  const DWORD waitCount = static_cast<DWORD>(handles.size());
  for (;;) {
    const DWORD r = ::WaitForMultipleObjects(waitCount, handles.data(), TRUE, 120);
    if (progress_) progress_(scannedBytes_.load(), stats_.totalBytes);
    if (r == WAIT_OBJECT_0) break;
    if (r == WAIT_FAILED) break;
    if (cancelled_.load()) cancelFlag_.store(true);
    if (r != WAIT_TIMEOUT && r != WAIT_OBJECT_0) break;
  }

  if (progress_) progress_(scannedBytes_.load(), stats_.totalBytes);
  for (HANDLE h : handles) ::CloseHandle(h);

  stats_.scannedBytes = scannedBytes_.load();
  stats_.cancelled = cancelled_.load();

  MergeResults(buffers, true);
  mode_ = ScanMode::kResultList;
  stats_.elapsedSeconds = stopwatch.Elapsed();
  return true;
}

//=============================================================================
//  后续扫描：遍历结果列表（移植 TScanner.nextnextscanmem，memscan.pas:4446）
//=============================================================================
bool ScanEngine::RescanResultList(const ScanRequest& request, std::string* error) {
  (void)request;
  (void)error;

  const size_t vs = static_cast<size_t>(valueSize_);
  const std::vector<ptruint> oldAddresses = addresses_;
  const std::vector<ubyte> oldMemory = memory_;

  ResultBuffer out;
  out.addresses.reserve(oldAddresses.size());
  out.memory.reserve(oldMemory.size());

  std::vector<ubyte> buffer;

  const size_t n = oldAddresses.size();
  size_t i = 0;
  while (i < n) {
    if (cancelled_) break;

    const ptruint pageBase = PageOf(oldAddresses[i]);

    // 同一个 4KB 页内的结果合并为一次读取（CE 的优化，memscan.pas:4510）
    size_t j = i + 1;
    while (j < n &&
           PageOf(oldAddresses[j] + static_cast<ptruint>(vs) - 1) == pageBase) {
      ++j;
    }
    const size_t last = j - 1;

    const ptruint base = oldAddresses[i];
    const size_t span = static_cast<size_t>(oldAddresses[last] - base) + vs;

    buffer.assign(span + vs + kReadSlack, 0);
    const size_t got = process_.ReadPartial(base, buffer.data(), span);

    if (got >= vs) {
      for (size_t k = i; k <= last; ++k) {
        const size_t off = static_cast<size_t>(oldAddresses[k] - base);
        if (off + vs > got) continue;
        const ubyte* newValue = buffer.data() + off;
        const ubyte* oldValue = oldMemory.data() + k * vs;
        if (CheckValue(oldAddresses[k], newValue, oldValue)) {
          out.Add(oldAddresses[k], newValue, valueSize_);
        }
      }
    }

    i = last + 1;
    if (progress_) progress_(i, n);
  }

  addresses_.clear();
  memory_.clear();
  addresses_.swap(out.addresses);
  memory_.swap(out.memory);
  return true;
}

//=============================================================================
//  后续扫描：遍历“未知初始值”的内存镜像（memscan.pas:4205）
//=============================================================================
bool ScanEngine::RescanImage(const ScanRequest& request, std::string* error) {
  (void)request;
  (void)error;

  if (imageBase_ == nullptr) {
    if (error) *error = "内部错误：未知值镜像不存在";
    return false;
  }

  const size_t vs = static_cast<size_t>(valueSize_);
  const ubyte* image = static_cast<const ubyte*>(imageBase_);

  ResultBuffer out;
  std::vector<ubyte> buffer;

  qword processed = 0;
  for (const MemoryRegion& r : imageRegions_) {
    const ubyte* imageRegion = image + r.startaddress;

    for (qword off = 0; off < r.MemorySize; off += kChunkSize) {
      if (cancelled_) break;

      const size_t len = static_cast<size_t>(
          std::min<qword>(static_cast<qword>(kChunkSize), r.MemorySize - off));
      const ptruint address = r.BaseAddress + off;

      buffer.assign(len + vs + kReadSlack, 0);
      const size_t got = process_.ReadPartial(address, buffer.data(), len);
      if (got < vs) {
        processed += len;
        continue;
      }

      // 与区域起点保持相同的相位
      const qword firstPos = FirstCandidateOffset(off, startOffset_, stepSize_);
      const size_t scanLast = (len >= vs) ? (len - vs) : 0;
      if (len >= vs) {
        for (qword pos = firstPos; pos <= static_cast<qword>(scanLast); pos += stepSize_) {
          if (pos + vs > got) break;
          const ptruint addr = address + pos;
          if (hasRangeRules_ && AddressBlocked(addr)) continue;

          const ubyte* newValue = buffer.data() + pos;
          const ubyte* oldValue = imageRegion + off + pos;
          if (CheckValue(addr, newValue, oldValue)) {
            out.Add(addr, newValue, valueSize_);
          }
        }
      }

      processed += len;
      if (progress_) progress_(processed, stats_.totalBytes);
    }
  }

  addresses_.clear();
  memory_.clear();
  addresses_.swap(out.addresses);
  memory_.swap(out.memory);
  return true;
}

//=============================================================================
//  后续扫描入口
//=============================================================================
bool ScanEngine::NextScan(const ScanRequest& request, std::string* error) {
  if (!process_.IsOpen()) {
    SetError("尚未附加到任何进程");
    if (error) *error = lastError_;
    return false;
  }
  if (mode_ == ScanMode::kNone) {
    if (error) *error = "还没有执行过首次扫描";
    return false;
  }

  util::Stopwatch stopwatch;
  cancelled_ = false;

  const int savedValueSize = valueSize_;
  if (!CalculateValueSize(request, error)) return false;
  if (mode_ == ScanMode::kResultList && valueSize_ != savedValueSize) {
    if (error) {
      *error = "继续扫描不能改变数据宽度（首次为 " + std::to_string(savedValueSize) +
               " 字节，本次为 " + std::to_string(valueSize_) + " 字节）";
    }
    valueSize_ = savedValueSize;
    return false;
  }
  if (!ConfigureScanRoutine(request, error)) return false;

  stats_.scannedBytes = 0;
  stats_.cancelled = false;
  stats_.threadCount = 1;

  const bool ok = (mode_ == ScanMode::kMemoryImage) ? RescanImage(request, error)
                                                    : RescanResultList(request, error);
  if (!ok) return false;

  mode_ = ScanMode::kResultList;
  stats_.elapsedSeconds = stopwatch.Elapsed();
  stats_.scannedBytes = static_cast<qword>(addresses_.size());
  stats_.cancelled = cancelled_.load();
  return true;
}

//=============================================================================
//  区域枚举 / 报告
//=============================================================================
bool ScanEngine::EnumerateRegions(const RegionFilter& filter, std::vector<MemoryRegion>* regions,
                                  std::string* error) {
  if (regions == nullptr) {
    if (error) *error = "内部错误：regions 为空";
    return false;
  }
  if (!process_.IsOpen()) {
    if (error) *error = "尚未附加到任何进程";
    return false;
  }

  ScanRequest request;
  request.regionFilter = filter;
  request.scanOption = ScanOption::soExactValue;

  if (!BuildRegions(request, error)) return false;
  *regions = regions_;
  return true;
}

bool ScanEngine::DescribeRegions(const RegionFilter& filter, std::vector<RegionReportRow>* rows,
                                 std::string* error) {
  if (rows == nullptr) {
    if (error) *error = "内部错误：rows 为空";
    return false;
  }
  if (!process_.IsOpen()) {
    if (error) *error = "尚未附加到任何进程";
    return false;
  }

  rows->clear();

  ptruint minAddress = 0;
  ptruint maxAddress = 0;
  process_.AddressRange(&minAddress, &maxAddress);

  const ptruint start = filter.startAddress != 0 ? filter.startAddress : minAddress;
  const ptruint stop = filter.stopAddress != 0 ? filter.stopAddress : maxAddress;

  const std::vector<ModuleEntry>& modules = process_.CachedModules();

  ptruint current = start;
  MEMORY_BASIC_INFORMATION mbi{};
  while (current < stop) {
    if (::VirtualQueryEx(process_.Handle(), reinterpret_cast<LPCVOID>(current), &mbi,
                         sizeof(mbi)) == 0) {
      break;
    }

    const ptruint rawBase = reinterpret_cast<ptruint>(mbi.BaseAddress);
    const qword rawSize = static_cast<qword>(mbi.RegionSize);
    if (rawSize == 0) break;
    const ptruint next = rawBase + static_cast<ptruint>(rawSize);
    if (next <= rawBase) break;

    RegionReportRow row;
    row.region.BaseAddress = rawBase;
    row.region.MemorySize = rawSize;
    row.decision = EvaluateRegion(mbi, filter, modules);
    row.kept = row.decision.valid;

    rows->push_back(std::move(row));
    current = next;
  }

  return true;
}

//=============================================================================
//  结果访问 / 写回
//=============================================================================
std::vector<ubyte> ScanEngine::ValueAt(size_t index) const {
  if (index >= addresses_.size() || valueSize_ <= 0) return std::vector<ubyte>();
  const size_t offset = index * static_cast<size_t>(valueSize_);
  if (offset + static_cast<size_t>(valueSize_) > memory_.size()) return std::vector<ubyte>();
  return std::vector<ubyte>(memory_.begin() + static_cast<std::ptrdiff_t>(offset),
                            memory_.begin() +
                                static_cast<std::ptrdiff_t>(offset + valueSize_));
}

std::vector<ubyte> ScanEngine::ReadCurrent(size_t index) const {
  if (index >= addresses_.size() || valueSize_ <= 0) return std::vector<ubyte>();
  std::vector<ubyte> buffer(static_cast<size_t>(valueSize_), 0);
  if (!process_.Read(addresses_[index], buffer.data(), buffer.size())) {
    return std::vector<ubyte>();
  }
  return buffer;
}

bool ScanEngine::WriteRaw(ptruint address, const std::vector<ubyte>& data,
                          std::string* error) const {
  size_t written = 0;
  if (!process_.Write(address, data.data(), data.size(), &written) || written != data.size()) {
    if (error) {
      *error = "写入失败: " + ProcessMemory::Win32ErrorString(0) + "（地址 0x" +
               util::FormatHex(address) + "）";
    }
    return false;
  }
  return true;
}

namespace {

// 把用户输入的文本按类型编码为字节序列
bool EncodeValueForType(VariableType type, const std::string& text, bool hexadecimal,
                        std::vector<ubyte>* out, std::string* error) {
  out->clear();
  switch (type) {
    case VariableType::vtByte:
    case VariableType::vtWord:
    case VariableType::vtDword:
    case VariableType::vtQword: {
      qword v = 0;
      bool neg = false;
      if (!util::ParseInteger(text, hexadecimal, &v, &neg)) {
        if (error) *error = "不是合法的整数: " + text;
        return false;
      }
      const int size = VariableTypeSize(type);
      out->resize(static_cast<size_t>(size));
      for (int i = 0; i < size; ++i) {
        (*out)[static_cast<size_t>(i)] = static_cast<ubyte>((v >> (8 * i)) & 0xFF);
      }
      return true;
    }
    case VariableType::vtSingle: {
      double d = 0.0;
      if (!util::ParseFloat(text, &d)) {
        if (error) *error = "不是合法的浮点数: " + text;
        return false;
      }
      const float f = static_cast<float>(d);
      out->resize(sizeof(float));
      std::memcpy(out->data(), &f, sizeof(float));
      return true;
    }
    case VariableType::vtDouble: {
      double d = 0.0;
      if (!util::ParseFloat(text, &d)) {
        if (error) *error = "不是合法的浮点数: " + text;
        return false;
      }
      out->resize(sizeof(double));
      std::memcpy(out->data(), &d, sizeof(double));
      return true;
    }
    case VariableType::vtString: {
      out->assign(text.begin(), text.end());
      return true;
    }
    case VariableType::vtUnicodeString: {
      const std::wstring w = util::Utf8ToWide(text);
      out->resize(w.size() * 2);
      if (!w.empty()) std::memcpy(out->data(), w.data(), out->size());
      return true;
    }
    case VariableType::vtByteArray: {
      const AobPattern p = ParseAobPattern(text, true);
      if (!p.valid) {
        if (error) *error = "特征码解析失败: " + p.error;
        return false;
      }
      out->resize(static_cast<size_t>(p.Length()));
      for (int i = 0; i < p.Length(); ++i) {
        const std::int32_t b = p.bytes[static_cast<size_t>(i)];
        (*out)[static_cast<size_t>(i)] = static_cast<ubyte>(b < 0 ? 0 : (b & 0xFF));
      }
      return true;
    }
    default:
      if (error) *error = "该类型暂不支持写入";
      return false;
  }
}

constexpr char kFileMagic[8] = {'C', 'E', 'S', 'C', 'A', 'N', 'V', 'C'};
constexpr std::uint32_t kFileVersion = 1;

template <typename T>
void WritePod(std::ostream& os, const T& value) {
  os.write(reinterpret_cast<const char*>(&value), sizeof(T));
}

template <typename T>
bool ReadPod(std::istream& is, T* value) {
  is.read(reinterpret_cast<char*>(value), sizeof(T));
  return is.good();
}

}  // namespace

bool ScanEngine::WriteParsed(size_t index, const ScanRequest& request, std::string* error) {
  if (index >= addresses_.size()) {
    if (error) *error = "结果索引越界";
    return false;
  }

  std::vector<ubyte> data;
  if (!EncodeValueForType(currentType_, request.value1, request.hexadecimal, &data, error)) {
    return false;
  }

  if (data.size() != static_cast<size_t>(valueSize_)) {
    if (error) {
      *error = "值的宽度 (" + std::to_string(data.size()) + " 字节) 与扫描类型宽度 (" +
               std::to_string(valueSize_) + " 字节) 不一致";
    }
    return false;
  }

  if (!WriteRaw(addresses_[index], data, error)) return false;

  // 同步快照，便于后续扫描以新值为基准
  const size_t offset = index * static_cast<size_t>(valueSize_);
  if (offset + data.size() <= memory_.size()) {
    std::memcpy(&memory_[offset], data.data(), data.size());
  }
  return true;
}

//=============================================================================
//  结果存取
//=============================================================================
bool ScanEngine::SaveResults(const std::string& path, std::string* error) const {
  std::ofstream os(path, std::ios::binary | std::ios::trunc);
  if (!os) {
    if (error) *error = "无法写入文件: " + path;
    return false;
  }

  os.write(kFileMagic, sizeof(kFileMagic));
  WritePod(os, kFileVersion);
  WritePod(os, static_cast<std::int32_t>(currentType_));
  WritePod(os, static_cast<std::int32_t>(valueSize_));
  WritePod(os, static_cast<std::uint64_t>(addresses_.size()));

  const size_t vs = static_cast<size_t>(valueSize_);
  for (size_t i = 0; i < addresses_.size(); ++i) {
    WritePod(os, static_cast<std::uint64_t>(addresses_[i]));
    if (vs > 0 && (i + 1) * vs <= memory_.size()) {
      os.write(reinterpret_cast<const char*>(&memory_[i * vs]), static_cast<std::streamsize>(vs));
    }
  }

  if (!os.good()) {
    if (error) *error = "写入结果文件时出错: " + path;
    return false;
  }
  return true;
}

bool ScanEngine::LoadResults(const std::string& path, std::string* error) {
  std::ifstream is(path, std::ios::binary);
  if (!is) {
    if (error) *error = "无法读取文件: " + path;
    return false;
  }

  char magic[8] = {0};
  is.read(magic, sizeof(magic));
  if (!is.good() || std::memcmp(magic, kFileMagic, sizeof(kFileMagic)) != 0) {
    if (error) *error = "不是本工具的结果文件: " + path;
    return false;
  }

  std::uint32_t version = 0;
  std::int32_t type = 0;
  std::int32_t valueSize = 0;
  std::uint64_t count = 0;
  if (!ReadPod(is, &version) || !ReadPod(is, &type) || !ReadPod(is, &valueSize) ||
      !ReadPod(is, &count)) {
    if (error) *error = "结果文件头损坏";
    return false;
  }
  if (version != kFileVersion) {
    if (error) *error = "结果文件版本不支持: " + std::to_string(version);
    return false;
  }
  if (valueSize <= 0 || valueSize > 4096) {
    if (error) *error = "结果文件中的值宽度非法";
    return false;
  }

  Reset();
  currentType_ = static_cast<VariableType>(type);
  valueSize_ = valueSize;
  addresses_.resize(static_cast<size_t>(count));
  memory_.resize(static_cast<size_t>(count) * static_cast<size_t>(valueSize));

  const size_t vs = static_cast<size_t>(valueSize);
  for (std::uint64_t i = 0; i < count; ++i) {
    std::uint64_t address = 0;
    if (!ReadPod(is, &address)) {
      if (error) *error = "结果文件在读取地址时被截断";
      return false;
    }
    addresses_[static_cast<size_t>(i)] = static_cast<ptruint>(address);
    is.read(reinterpret_cast<char*>(&memory_[static_cast<size_t>(i) * vs]),
            static_cast<std::streamsize>(vs));
    if (!is.good()) {
      if (error) *error = "结果文件在读取数值时被截断";
      return false;
    }
  }

  mode_ = ScanMode::kResultList;
  stats_ = ScanStats{};
  return true;
}

}  // namespace ce
