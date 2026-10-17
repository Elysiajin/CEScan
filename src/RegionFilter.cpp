//=============================================================================
//  RegionFilter.cpp
//  区域排除/包含 规则的实现。逐条对应 memscan.pas 中的判定分支。
//=============================================================================
#include "RegionFilter.h"

#include <algorithm>
#include <cctype>
#include <cwchar>

#include "CEUtil.h"

namespace ce {
namespace {

// 把 "-W+X*C" 这类标志串规范化
std::string Upper(const std::string& s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  return r;
}

std::wstring StripModuleSuffix(std::wstring name) {
  std::wstring lower = util::ToLower(name);
  for (const wchar_t* suffix : {L".exe", L".dll", L".sys", L".ocx", L".node"}) {
    const size_t len = std::wcslen(suffix);
    if (lower.size() > len && lower.compare(lower.size() - len, len, suffix) == 0) {
      return lower.substr(0, lower.size() - len);
    }
  }
  return lower;
}

}  // namespace

//-----------------------------------------------------------------------------
// 保护标志字符串解析 —— 完整移植 TMemScan.parseProtectionflags (memscan.pas:8679)
//-----------------------------------------------------------------------------
void ParseProtectionFlags(const std::string& flags, RegionFilter* filter) {
  if (filter == nullptr) return;

  filter->scanWritable = ScanRegionPreference::scanDontCare;
  filter->scanExecutable = ScanRegionPreference::scanDontCare;
  filter->scanCopyOnWrite = ScanRegionPreference::scanDontCare;
  filter->scanDirty = ScanRegionPreference::scanDontCare;

  const std::string upper = Upper(flags);
  ScanRegionPreference current = ScanRegionPreference::scanDontCare;

  for (char c : upper) {
    switch (c) {
      case '-':
        current = ScanRegionPreference::scanExclude;
        break;
      case '+':
        current = ScanRegionPreference::scanInclude;
        break;
      case '*':
        current = ScanRegionPreference::scanDontCare;
        break;
      case 'W':
        filter->scanWritable = current;
        current = ScanRegionPreference::scanDontCare;
        break;
      case 'C':
        filter->scanCopyOnWrite = current;
        current = ScanRegionPreference::scanDontCare;
        break;
      case 'X':
        filter->scanExecutable = current;
        current = ScanRegionPreference::scanDontCare;
        break;
      case 'D':
        filter->scanDirty = current;
        current = ScanRegionPreference::scanDontCare;
        break;
      default:
        break;  // 其余字符（分隔符等）忽略，与 CE 一致
    }
  }
}

std::string ProtectionFlagsToString(const RegionFilter& filter) {
  std::string out;
  auto append = [&out](ScanRegionPreference p, char key) {
    switch (p) {
      case ScanRegionPreference::scanInclude:
        out += '+';
        out += key;
        break;
      case ScanRegionPreference::scanExclude:
        out += '-';
        out += key;
        break;
      case ScanRegionPreference::scanDontCare:
      default:
        break;
    }
  };
  append(filter.scanWritable, 'W');
  append(filter.scanExecutable, 'X');
  append(filter.scanCopyOnWrite, 'C');
  return out.empty() ? std::string("(无)") : out;
}

//-----------------------------------------------------------------------------
// 地址 / 模块 规则
//-----------------------------------------------------------------------------
bool IsAddressExcludedByRange(ptruint address, const RegionFilter& filter) {
  for (const AddressRange& r : filter.excludeRanges) {
    if (r.Contains(address)) return true;
  }
  if (!filter.includeRanges.empty()) {
    bool inside = false;
    for (const AddressRange& r : filter.includeRanges) {
      if (r.Contains(address)) {
        inside = true;
        break;
      }
    }
    if (!inside) return true;
  }
  return false;
}

bool ModuleNameMatches(const std::vector<std::wstring>& names, const std::wstring& moduleName) {
  const std::wstring target = StripModuleSuffix(moduleName);
  for (const std::wstring& n : names) {
    if (StripModuleSuffix(n) == target) return true;
  }
  return false;
}

ModuleRuleResult ApplyModuleRules(ptruint baseAddress, qword size, const RegionFilter& filter,
                                  const std::vector<ModuleEntry>& modules,
                                  std::wstring* matchedModule) {
  if (matchedModule) matchedModule->clear();

  if (baseAddress == 0 || size == 0) return ModuleRuleResult::kNotApplicable;
  const ptruint regionEnd = baseAddress + size;

  // includeModules 非空 => 只保留落在这些模块里的区域
  if (!filter.includeModules.empty()) {
    std::wstring hit;
    for (const ModuleEntry& m : modules) {
      if (!ModuleNameMatches(filter.includeModules, m.name)) continue;
      if (baseAddress < m.base + m.size && m.base < regionEnd) {
        hit = m.name;
        break;
      }
    }
    if (hit.empty()) return ModuleRuleResult::kOutsideIncludeList;
    if (matchedModule) *matchedModule = hit;
  }

  // excludeModules 命中 => 排除
  for (const ModuleEntry& m : modules) {
    if (!ModuleNameMatches(filter.excludeModules, m.name)) continue;
    if (baseAddress < m.base + m.size && m.base < regionEnd) {
      if (matchedModule) *matchedModule = m.name;
      return ModuleRuleResult::kExcludedByModule;
    }
  }

  return ModuleRuleResult::kNotApplicable;
}

//-----------------------------------------------------------------------------
// 区域判定 —— 等价 memscan.pas:7188-7250 的过滤链
//-----------------------------------------------------------------------------
RegionDecision EvaluateRegion(const MEMORY_BASIC_INFORMATION& mbi, const RegionFilter& filter,
                              const std::vector<ModuleEntry>& modules) {
  RegionDecision d;
  d.valid = false;

  const ptruint base = reinterpret_cast<ptruint>(mbi.BaseAddress);
  const qword size = static_cast<qword>(mbi.RegionSize);

  // --- 1. 基础可读性判定（memscan.pas:7188-7196）-------------------------
  if (mbi.State != MEM_COMMIT) {
    d.excludeReason = "未提交 (State != MEM_COMMIT)";
    return d;
  }
  if ((mbi.Protect & PAGE_GUARD) != 0) {
    d.excludeReason = "有 PAGE_GUARD 保护";
    return d;
  }
  if ((mbi.Protect & PAGE_NOACCESS) != 0) {
    d.excludeReason = "PAGE_NOACCESS 不可访问";
    return d;
  }

  // --- 2. 页类型 ---------------------------------------------------------
  d.isPrivate = (mbi.Type == MEM_PRIVATE);
  d.isImage = (mbi.Type == MEM_IMAGE);
  d.isMapped = (mbi.Type == MEM_MAPPED);

  if (!filter.scan_mem_private && d.isPrivate) {
    d.excludeReason = "已按设置排除 MEM_PRIVATE";
    return d;
  }
  if (!filter.scan_mem_image && d.isImage) {
    d.excludeReason = "已按设置排除 MEM_IMAGE";
    return d;
  }
  if (!filter.scan_mem_mapped && d.isMapped) {
    d.excludeReason = "已按设置排除 MEM_MAPPED";
    return d;
  }

  // 注：CE 原文此处用 mbi._type 与 PAGE_NOCACHE/PAGE_WRITECOMBINE 比较，
  //     但其语义属于 Protect 字段，这里按语义取 Protect（偏差已在 README 说明）。
  if (filter.skip_PAGE_NOCACHE && (mbi.Protect & PAGE_NOCACHE) != 0) {
    d.excludeReason = "PAGE_NOCACHE";
    return d;
  }
  if (filter.skip_PAGE_WRITECOMBINE && (mbi.Protect & PAGE_WRITECOMBINE) != 0) {
    d.excludeReason = "PAGE_WRITECOMBINE";
    return d;
  }

  // --- 3. 保护属性三态（memscan.pas:7210-7242）---------------------------
  d.writable = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE |
                                PAGE_EXECUTE_WRITECOPY)) != 0;
  d.executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                 PAGE_EXECUTE_WRITECOPY)) != 0;
  d.copyOnWrite = (mbi.Protect & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;

  switch (filter.scanWritable) {
    case ScanRegionPreference::scanInclude:
      if (!d.writable) {
        d.excludeReason = "要求 +W（可写）但该区域不可写";
        return d;
      }
      break;
    case ScanRegionPreference::scanExclude:
      if (d.writable) {
        d.excludeReason = "命中 -W（排除可写区域）";
        return d;
      }
      break;
    default:
      break;
  }

  switch (filter.scanExecutable) {
    case ScanRegionPreference::scanInclude:
      if (!d.executable) {
        d.excludeReason = "要求 +X（可执行）但该区域不可执行";
        return d;
      }
      break;
    case ScanRegionPreference::scanExclude:
      if (d.executable) {
        d.excludeReason = "命中 -X（排除可执行区域）";
        return d;
      }
      break;
    default:
      break;
  }

  switch (filter.scanCopyOnWrite) {
    case ScanRegionPreference::scanInclude:
      if (!d.copyOnWrite) {
        d.excludeReason = "要求 +C（写时复制）但该区域不是";
        return d;
      }
      break;
    case ScanRegionPreference::scanExclude:
      if (d.copyOnWrite) {
        d.excludeReason = "命中 -C（排除写时复制区域）";
        return d;
      }
      break;
    default:
      break;
  }

  // --- 4. 模块规则 -------------------------------------------------------
  std::wstring module;
  const ModuleRuleResult modRule = ApplyModuleRules(base, size, filter, modules, &module);
  if (modRule == ModuleRuleResult::kExcludedByModule) {
    d.module = module;
    d.excludeReason = "命中 --exclude-module: " + util::WideToUtf8(module);
    return d;
  }
  if (modRule == ModuleRuleResult::kOutsideIncludeList) {
    d.excludeReason = "不在 --include-module 指定范围内";
    return d;
  }
  d.module = module;

  // --- 5. 地址区间规则 ---------------------------------------------------
  if (!filter.excludeRanges.empty()) {
    const ptruint end = base + size;
    for (const AddressRange& r : filter.excludeRanges) {
      if (base < r.stop && r.start < end) {
        d.excludeReason = "命中 --exclude-range";
        return d;
      }
    }
  }
  if (!filter.includeRanges.empty()) {
    const ptruint end = base + size;
    bool overlaps = false;
    for (const AddressRange& r : filter.includeRanges) {
      if (base < r.stop && r.start < end) {
        overlaps = true;
        break;
      }
    }
    if (!overlaps) {
      d.excludeReason = "不在 --include-range 指定范围内";
      return d;
    }
  }

  d.valid = true;
  return d;
}

//-----------------------------------------------------------------------------
// 单地址判定 —— 等价 TScanController.isValidregion (memscan.pas:6887)
//-----------------------------------------------------------------------------
bool IsAddressValid(HANDLE process, ptruint address, const RegionFilter& filter,
                    const std::vector<ModuleEntry>& modules) {
  if (address < filter.startAddress) return false;
  if (address >= filter.stopAddress) return false;
  if (IsAddressExcludedByRange(address, filter)) return false;

  MEMORY_BASIC_INFORMATION mbi{};
  if (::VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
    return false;

  const RegionDecision decision = EvaluateRegion(mbi, filter, modules);
  return decision.valid;
}

}  // namespace ce
