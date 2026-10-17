#pragma once
//=============================================================================
//  RegionFilter.h
//  「区域排除 / 包含」筛选器 —— 本移植工具的核心能力。
//
//  移植来源:
//     memscan.pas  TMemScan.parseProtectionflags      (8679) 保护标志字符串解析
//     memscan.pas  TScanner.configurescanroutine      (scanWritable / scanExecutable ...)
//     memscan.pas  TScanController.isValidregion      (6887) 单地址有效性判定
//     memscan.pas  TScanController.firstScan          (6978) 区域枚举时的过滤
//
//  CE 原来的三态字段（scanWritable / scanExecutable / scanCopyOnWrite / scanDirty）
//  在本移植中完整保留，并额外补充了面向“排除工具”的实用维度：
//     · 按模块排除 / 仅包含（excludeModules / includeModules）
//     · 按地址区间排除 / 仅包含（excludeRanges / includeRanges）
//     · 按页类型排除（MEM_PRIVATE / MEM_IMAGE / MEM_MAPPED）
//=============================================================================
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <vector>

#include "CETypes.h"
#include "ProcessMemory.h"

namespace ce {

//-----------------------------------------------------------------------------
// 区域过滤条件
//-----------------------------------------------------------------------------
struct RegionFilter {
  //--- CE 原生三态字段（memscan.pas）-------------------------------------
  ScanRegionPreference scanWritable = ScanRegionPreference::scanDontCare;
  ScanRegionPreference scanExecutable = ScanRegionPreference::scanDontCare;
  ScanRegionPreference scanCopyOnWrite = ScanRegionPreference::scanDontCare;
  ScanRegionPreference scanDirty = ScanRegionPreference::scanDontCare;  // CE 仅在 darwin 生效

  //--- CE 页类型开关 ------------------------------------------------------
  bool scan_mem_private = true;  // 扫描 MEM_PRIVATE
  bool scan_mem_image = true;    // 扫描 MEM_IMAGE
  bool scan_mem_mapped = true;   // 扫描 MEM_MAPPED

  bool skip_PAGE_NOCACHE = false;
  bool skip_PAGE_WRITECOMBINE = false;

  bool scan_MEM_MAPPED = true;  // 对应 CE 的 Scan_MEM_MAPPED（false => VQE_NOSHARED）
  bool scan_pagedonly = false;
  bool scan_dirtyonly = false;

  //--- 排除 / 包含 列表（“排除工具”主要入口）-----------------------------
  std::vector<std::wstring> excludeModules;          // 命中即排除该模块所属区域
  std::vector<std::wstring> includeModules;          // 非空时只保留这些模块的区域
  std::vector<AddressRange> excludeRanges;           // 命中即排除的地址区间
  std::vector<AddressRange> includeRanges;           // 非空时只保留落在其中的地址

  //--- 人为限定的扫描窗口 -------------------------------------------------
  ptruint startAddress = 0;
  ptruint stopAddress = 0;  // 0 表示使用系统允许的最大用户态地址

  // 便捷设置：--exec-only / --write-only 等
  void SetWritableOnly() { scanWritable = ScanRegionPreference::scanInclude; }
  void SetExcludeWritable() { scanWritable = ScanRegionPreference::scanExclude; }
  void SetExecutableOnly() { scanExecutable = ScanRegionPreference::scanInclude; }
  void SetExcludeExecutable() { scanExecutable = ScanRegionPreference::scanExclude; }
  void SetCopyOnWriteOnly() { scanCopyOnWrite = ScanRegionPreference::scanInclude; }
  void SetExcludeCopyOnWrite() { scanCopyOnWrite = ScanRegionPreference::scanExclude; }

  bool HasExclusionRules() const {
    return !excludeModules.empty() || !includeModules.empty() || !excludeRanges.empty() ||
           !includeRanges.empty() || scanWritable == ScanRegionPreference::scanExclude ||
           scanExecutable == ScanRegionPreference::scanExclude ||
           scanCopyOnWrite == ScanRegionPreference::scanExclude;
  }
};

//-----------------------------------------------------------------------------
// 单个区域的判定结果（供 regions 列表 / 扫描解释使用）
//-----------------------------------------------------------------------------
struct RegionDecision {
  bool valid = false;  // 最终是否会被扫描
  bool writable = false;
  bool executable = false;
  bool copyOnWrite = false;
  bool isPrivate = false;
  bool isImage = false;
  bool isMapped = false;

  std::wstring module;       // 所属模块名（可能为空）
  std::string excludeReason; // 被排除的原因（valid=false 时才有意义）
};

//-----------------------------------------------------------------------------
// 保护标志字符串解析  ——  完整移植 TMemScan.parseProtectionflags
//
//   语法：前缀 + 关键字
//     '+'  -> 随后的关键字设为 include
//     '-'  -> 随后的关键字设为 exclude
//     '*'  -> 随后的关键字设为 dontcare
//     关键字: W=可写  X=可执行  C=写时复制  D=dirty
//   例：  "+W-C"  只扫描可写、且非写时复制的区域
//         "-X"    排除可执行区域
//   解析前三个三态字段会被重置为 scanDontCare（与 CE 行为一致）
//-----------------------------------------------------------------------------
void ParseProtectionFlags(const std::string& flags, RegionFilter* filter);

// 把当前三态字段还原为同样的标志串（用于展示）
std::string ProtectionFlagsToString(const RegionFilter& filter);

//-----------------------------------------------------------------------------
// 区域判定
//-----------------------------------------------------------------------------
// 等价于 memscan.pas 中 isValidregion + firstScan 的过滤分支组合
RegionDecision EvaluateRegion(const MEMORY_BASIC_INFORMATION& mbi, const RegionFilter& filter,
                              const std::vector<ModuleEntry>& modules);

// 单地址判定（等价 TScanController.isValidregion）
bool IsAddressValid(HANDLE process, ptruint address, const RegionFilter& filter,
                    const std::vector<ModuleEntry>& modules);

// 地址是否命中排除区间 / 不在包含区间内
bool IsAddressExcludedByRange(ptruint address, const RegionFilter& filter);

//-----------------------------------------------------------------------------
// 模块级 排除/包含 规则
//-----------------------------------------------------------------------------
enum class ModuleRuleResult {
  kNotApplicable = 0,     // 不受模块规则影响
  kExcludedByModule = 1,  // 命中 excludeModules
  kOutsideIncludeList = 2 // includeModules 非空，但该区域不属于其中任何模块
};

// 模块名匹配（忽略大小写，自动兼容带/不带 .exe/.dll 后缀）
bool ModuleNameMatches(const std::vector<std::wstring>& names, const std::wstring& moduleName);

ModuleRuleResult ApplyModuleRules(ptruint baseAddress, qword size, const RegionFilter& filter,
                                  const std::vector<ModuleEntry>& modules,
                                  std::wstring* matchedModule);

}  // namespace ce
