#pragma once
//=============================================================================
//  ScanEngine.h
//  内存扫描引擎 —— 移植 memscan.pas 的 TScanner / TScanController 主体。
//
//  移植来源与对应关系：
//      TScanner.configurescanroutine   -> ScanEngine::ConfigureScanRoutine
//      TScanner.FirstScanmem           -> ScanEngine::ScanChunk
//      TScanner.nextnextscanmem        -> ScanEngine::RescanResultList
//      TScanner.nextnextscanmemAll     -> ScanEngine::RescanImage
//      TScanner.firstscan              -> ScanEngine::FirstScan
//      TScanController.firstScan       -> ScanEngine::BuildRegions（含区域排除）
//
//  CE 中约 200 个逐类型判定函数（ByteExact / DWordBetween / SingleExact / ...）
//  在 C++ 中收敛为两个模板：CompareIntegral<T,TS> 与 CompareFloat<T>，
//  行为逐类型保持一致，代码量降到可维护范围。
//
//  多线程：按区域切分任务，每个线程独立收集结果，最后合并排序。
//  对应 CE 的 TScanner 工作线程池；结果集合与单线程完全一致。
//=============================================================================
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <atomic>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "CETypes.h"
#include "PatternScan.h"
#include "ProcessMemory.h"
#include "RegionFilter.h"

namespace ce {

//-----------------------------------------------------------------------------
// 一次扫描的完整参数
//-----------------------------------------------------------------------------
struct ScanRequest {
  VariableType variableType = VariableType::vtDword;
  ScanOption scanOption = ScanOption::soExactValue;

  std::string value1;
  std::string value2;

  bool hexadecimal = false;
  bool percentage = false;    // 百分比扫描
  bool caseSensitive = true;  // 字符串扫描

  FastScanMethod fastScanMethod = FastScanMethod::fsmAligned;
  int fastScanAlignSize = 0;   // 0 = 按类型取默认对齐
  int fastScanDigitCount = 1;

  RoundingType roundingType = RoundingType::rtRounded;
  int floatAccuracy = -1;  // -1 = 按输入字符串自动推断

  bool onlyOne = false;   // 只取第一个命中
  bool isUnique = false;  // 允许不对齐（逐字节）
  bool inverseScan = false;  // 反向扫描：排除命中项

  int threadCount = 0;  // 0 = 自动

  RegionFilter regionFilter;

  std::vector<AobPattern> aobPatterns;  // vtByteArray / vtByteArrays
  std::string scanString;               // 字符串扫描的原始文本

  void SetType(VariableType t) { variableType = t; }
  void SetOption(ScanOption o) { scanOption = o; }
};

//-----------------------------------------------------------------------------
// 扫描统计
//-----------------------------------------------------------------------------
struct ScanStats {
  qword totalBytes = 0;    // 命中过滤后待扫描的总字节
  qword scannedBytes = 0;  // 实际扫描字节
  int regionCount = 0;     // 参与扫描的区域数
  int regionSkipped = 0;   // 因“排除”规则被跳过的区域数
  int threadCount = 0;
  double elapsedSeconds = 0.0;
  bool cancelled = false;
};

//-----------------------------------------------------------------------------
// 结果列表模式
//-----------------------------------------------------------------------------
enum class ScanMode {
  kNone = 0,     // 尚未扫描
  kResultList,   // 首次扫描得到地址列表 -> 后续扫描遍历列表
  kMemoryImage,  // 未知初始值：保存整块旧内存镜像 -> 后续扫描遍历镜像
};

//-----------------------------------------------------------------------------
class ScanEngine {
 public:
  using ProgressFn = std::function<void(qword scanned, qword total)>;

  // 扫描过程中每个工作线程的结果收集缓冲
  struct ResultBuffer {
    std::vector<ptruint> addresses;
    std::vector<ubyte> memory;

    void Clear() {
      addresses.clear();
      memory.clear();
    }
    void Add(ptruint address, const ubyte* value, int size) {
      addresses.push_back(address);
      memory.insert(memory.end(), value, value + size);
    }
    size_t Count() const { return addresses.size(); }
  };

  // 区域报告行（regions 子命令使用）
  struct RegionReportRow {
    MemoryRegion region;
    RegionDecision decision;
    bool kept = false;
  };

  explicit ScanEngine(ProcessMemory& process);
  ~ScanEngine();

  ScanEngine(const ScanEngine&) = delete;
  ScanEngine& operator=(const ScanEngine&) = delete;

  //--- 主流程 -------------------------------------------------------------
  void Reset();  // 等同于 CE 的“新扫描”

  bool FirstScan(const ScanRequest& request, std::string* error);
  bool NextScan(const ScanRequest& request, std::string* error);

  // 只枚举并过滤区域，不扫描
  bool EnumerateRegions(const RegionFilter& filter, std::vector<MemoryRegion>* regions,
                        std::string* error);
  bool DescribeRegions(const RegionFilter& filter, std::vector<RegionReportRow>* rows,
                       std::string* error);

  //--- 结果访问 -----------------------------------------------------------
  size_t ResultCount() const { return addresses_.size(); }
  ptruint AddressAt(size_t index) const { return addresses_[index]; }
  std::vector<ubyte> ValueAt(size_t index) const;
  int ValueSize() const { return valueSize_; }
  const std::vector<MemoryRegion>& Regions() const { return regions_; }
  ScanMode Mode() const { return mode_; }
  const ScanStats& Stats() const { return stats_; }
  const std::string& LastError() const { return lastError_; }

  std::vector<ubyte> ReadCurrent(size_t index) const;

  //--- 写回 ---------------------------------------------------------------
  bool WriteRaw(ptruint address, const std::vector<ubyte>& data, std::string* error) const;
  bool WriteParsed(size_t index, const ScanRequest& request, std::string* error);

  //--- 存取 ---------------------------------------------------------------
  bool SaveResults(const std::string& path, std::string* error) const;
  bool LoadResults(const std::string& path, std::string* error);

  //--- 进度 / 取消 --------------------------------------------------------
  void SetProgressCallback(ProgressFn fn) { progress_ = std::move(fn); }
  void Cancel() { cancelled_ = true; }
  bool IsCancelled() const { return cancelled_; }

  VariableType CurrentType() const { return currentType_; }

 private:
  //--- 配置（configurescanroutine）---------------------------------------
  bool ConfigureScanRoutine(const ScanRequest& request, std::string* error);
  bool CalculateValueSize(const ScanRequest& request, std::string* error);

  //--- 区域枚举（TScanController.firstScan）------------------------------
  bool BuildRegions(const ScanRequest& request, std::string* error);

  //--- 判定（checkroutine）-----------------------------------------------
  bool CheckValue(ptruint address, const ubyte* newValue, const ubyte* oldValue) const;
  // 地址是否被 --exclude-range / --include-range 拦截
  bool AddressBlocked(ptruint address) const;

  template <typename T, typename TS>
  bool CompareIntegral(const ubyte* newValue, const ubyte* oldValue) const;

  template <typename T>
  bool CompareFloat(const ubyte* newValue, const ubyte* oldValue) const;

  template <typename T>
  static T ReadAs(const ubyte* p) {
    T value;
    std::memcpy(&value, p, sizeof(T));
    return value;
  }

  //--- 扫描实现 ----------------------------------------------------------
  // 在一段连续缓冲上按步进查找（bufferAddress 为缓冲首字节对应的目标地址）
  void ScanChunk(ptruint bufferAddress, const ubyte* buffer, size_t validSize, qword firstPos,
                 qword lastPosInChunk, ResultBuffer* out) const;

  bool RescanResultList(const ScanRequest& request, std::string* error);
  bool RescanImage(const ScanRequest& request, std::string* error);

  void MergeResults(std::vector<ResultBuffer>& buffers, bool sortByAddress);
  void SetError(const std::string& message);
  void ReleaseImage();

  // 工作线程入口（对应 CE 的 TScanner.execute）
  static DWORD WINAPI ScanWorkerProc(void* context);

  //--- 成员 --------------------------------------------------------------
  ProcessMemory& process_;
  std::vector<ptruint> addresses_;
  std::vector<ubyte> memory_;  // 与 addresses_ 平行，每项 valueSize_ 字节
  std::vector<MemoryRegion> regions_;
  ScanStats stats_;
  std::string lastError_;

  ScanMode mode_ = ScanMode::kNone;
  VariableType currentType_ = VariableType::vtDword;

  // configurescanroutine 的解析结果
  qword value_ = 0;
  qword value2_ = 0;
  double dvalue_ = 0.0;
  double dvalue2_ = 0.0;
  double svalue_ = 0.0;
  double svalue2_ = 0.0;
  double mindvalue_ = 0.0;
  double maxdvalue_ = 0.0;
  double minsvalue_ = 0.0;
  double maxsvalue_ = 0.0;
  bool signedMode_ = false;
  bool percentage_ = false;
  bool hexadecimal_ = false;
  bool unicodeString_ = false;
  bool caseSensitive_ = true;
  bool luaFormula_ = false;  // 保留字段：本移植未实现 Lua 公式

  ScanOption scanOption_ = ScanOption::soExactValue;
  RoundingType roundingType_ = RoundingType::rtRounded;
  int floatAccuracy_ = 0;

  FastScanMethod fastScanMethod_ = FastScanMethod::fsmAligned;
  int fastScanAlignSize_ = 4;
  int fastScanDigitCount_ = 1;

  bool onlyOne_ = false;
  bool inverseScan_ = false;
  int threadCount_ = 0;

  int valueSize_ = 4;      // 单个值的字节宽度
  qword stepSize_ = 1;     // 步进
  qword startOffset_ = 0;  // 起始偏移（末位数字扫描）

  bool isAobMode_ = false;
  std::vector<AobPattern> aobPatterns_;
  std::string textPattern_;  // 字符串扫描的字节序列

  // 地址区间规则（预合并、排序，便于二分）
  std::vector<AddressRange> mergedExclude_;
  std::vector<AddressRange> mergedInclude_;
  bool hasRangeRules_ = false;

  // 未知初始值扫描的旧内存镜像
  void* imageBase_ = nullptr;
  qword imageSize_ = 0;
  std::vector<MemoryRegion> imageRegions_;

  std::atomic<bool> cancelled_{false};
  std::atomic<qword> scannedBytes_{0};
  std::atomic<bool> cancelFlag_{false};
  ProgressFn progress_;
};

}  // namespace ce
