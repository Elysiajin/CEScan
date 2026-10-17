#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include "CETypes.h"
#include "CEUtil.h"
#include "ProcessMemory.h"
#include "RegionFilter.h"
#include "ScanEngine.h"

using namespace ce;

namespace {

//=============================================================================
// 控制台辅助
//=============================================================================
void SetupConsole() {
  ::SetConsoleOutputCP(CP_UTF8);
  ::SetConsoleCP(CP_UTF8);
}

void PrintSeparator(char c = '=') { std::cout << std::string(78, c) << "\n"; }

void PrintBanner() {
  std::cout << "\n";
  PrintSeparator('=');
  std::cout << "  CEScan  ——  Cheat Engine 内存搜索 / 区域排除工具（VC++ 移植版）\n";
  std::cout << "  移植自 Cheat Engine: memscan.pas / commontypedefs.pas / parsers.pas\n";
  PrintSeparator('=');
  std::cout << "\n";
}

void PrintUsage() {
  std::cout <<
      R"(用法:
  CEScan.exe [命令] [选项]

命令:
  list                          列出当前所有进程
  regions  <进程>               列出目标进程内存区域，并标注被"排除"的区域
  scan     <进程> [扫描选项]    执行首次扫描，打印结果
  next     <进程> [扫描选项]    继续扫描（需配合 --load 载入上次结果）
  interactive                   交互式扫描（无参数时的默认行为）

进程指定:
  --pid  <数字>                 按 PID 选择进程
  --name <映像名>               按映像名选择，例如 notepad 或 notepad.exe

数据类型:
  -t, --type <类型>             byte|word|dword|qword|float|double|string|wstring|aob|all
                                (默认 dword)

扫描方式:
  -m, --mode <方式>             exact|between|bigger|smaller|unknown|
                                increased|increasedby|decreased|decreasedby|
                                changed|unchanged            (默认 exact)
  -v, --value <值>              扫描值（between 时为下限）
      --value2 <值>             扫描值（between 时为上限）
      --hex                     数值按十六进制解析
      --pct                     百分比模式，例如 --mode increasedby --value 10% --value2 20%
      --no-case                 字符串扫描忽略大小写

扫描精度:
      --align <n>               对齐字节数，0 = 逐字节（默认按类型）
      --last-digits <n>         末位数字固定扫描
      --rounding <类型>         rounded|extremerounded|truncated（浮点，默认 rounded）
      --accuracy <n>            浮点小数位数（默认按输入推断）
      --only-one                只取第一个命中
      --unique                  允许不对齐
      --inverse                 反向扫描：排除命中项
      --threads <n>             扫描线程数（默认 CPU 核心数）

区域排除（本工具的核心能力）:
      --exclude-module <名>     排除某个模块的地址空间（可重复）
      --include-module <名>     只扫描某个模块（可重复）
      --exclude-range <起-止>   排除地址区间（可重复），例如 0x1000-0x2000
      --include-range <起-止>   只扫描地址区间（可重复）
      --range <起-止>           限定扫描窗口
      --protect <标志串>        保护标志，例如 "+W-C" 表示只扫可写且非写时复制
                                (+ 包含, - 排除, * 不关心; W=可写 X=可执行 C=写时复制)
      --write-only              等价于 --protect +W
      --no-write                等价于 --protect -W
      --exec-only               等价于 --protect +X
      --no-exec                 等价于 --protect -X
      --no-private              不扫描 MEM_PRIVATE
      --no-image                不扫描 MEM_IMAGE
      --no-mapped               不扫描 MEM_MAPPED
      --page-nocache            跳过 PAGE_NOCACHE
      --page-writecombine       跳过 PAGE_WRITECOMBINE

结果处理:
      --show <n>                显示前 n 条结果（默认 50）
      --save <文件>             保存结果到文件
      --load <文件>             载入结果文件（供 next 使用）
      --write <值>              把值写入结果中的第 N 项
      --index <n>               与 --write 搭配，指定第几项（从 0 开始）
      --quiet                   不打印进度

示例:
  CEScan.exe list
  CEScan.exe regions --name notepad --protect "-W"
  CEScan.exe scan --name notepad --type dword --mode exact --value 100
  CEScan.exe scan --name game --type float --mode unknown > res.bin --exclude-module kernel32
  CEScan.exe scan --pid 1234 -t dword -m increasedby -v 10 --exclude-module chrome
)";
}

//=============================================================================
// 参数解析
//=============================================================================
struct Options {
  std::string command;
  std::wstring processName;
  DWORD pid = 0;

  ScanRequest request;
  std::vector<std::string> excludeModulesUtf8, includeModulesUtf8;

  int showCount = 50;
  bool hasShow = true;
  size_t writeIndex = 0;
  std::string writeValue;
  bool hasWrite = false;
  std::string savePath;
  std::string loadPath;
  bool quiet = false;
  bool wantHelp = false;
};

bool ParseRangeText(const std::string& text, AddressRange* range) {
  std::string s = util::Trim(text);
  if (s.empty()) return false;

  size_t sep = std::string::npos;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '-' || s[i] == ':' || s[i] == '~') {
      if (i > 0) {  // 跳过开头的负号
        sep = i;
        break;
      }
    }
  }
  if (sep == std::string::npos) return false;

  const std::string a = util::Trim(s.substr(0, sep));
  const std::string b = util::Trim(s.substr(sep + 1));
  if (a.empty() || b.empty()) return false;

  bool neg = false;
  qword start = 0;
  qword stop = 0;
  if (!util::ParseInteger(a, false, &start, &neg)) return false;
  if (!util::ParseInteger(b, false, &stop, &neg)) return false;
  if (stop <= start) return false;

  range->start = static_cast<ptruint>(start);
  range->stop = static_cast<ptruint>(stop);
  return true;
}

bool ParseArgList(int argc, char** argv, Options* opt, std::string* error) {
  opt->request.regionFilter.scanWritable = ScanRegionPreference::scanDontCare;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto nextValue = [&](const char* name) -> std::string {
      if (i + 1 >= argc) {
        *error = std::string("选项 ") + name + " 缺少参数";
        return std::string();
      }
      return std::string(argv[++i]);
    };

    auto asInt = [&](const std::string& s, long long* out) -> bool {
      char* end = nullptr;
      const long long v = std::strtoll(s.c_str(), &end, 0);
      if (end == s.c_str() || (end != nullptr && *end != '\0')) return false;
      *out = v;
      return true;
    };

    if (arg == "-h" || arg == "--help" || arg == "/?") {
      opt->wantHelp = true;
      return true;
    } else if (arg == "list" || arg == "regions" || arg == "scan" || arg == "next" ||
               arg == "interactive") {
      opt->command = arg;
    } else if (arg == "--pid") {
      long long v = 0;
      const std::string s = nextValue("--pid");
      if (s.empty() || !asInt(s, &v) || v <= 0) {
        *error = "--pid 需要一个正整数";
        return false;
      }
      opt->pid = static_cast<DWORD>(v);
    } else if (arg == "--name") {
      const std::string s = nextValue("--name");
      if (s.empty()) {
        *error = "--name 需要一个进程名";
        return false;
      }
      opt->processName = util::Utf8ToWide(s);
    } else if (arg == "-t" || arg == "--type") {
      const std::string s = nextValue("--type");
      bool ok = false;
      const VariableType t = VariableTypeFromName(s, &ok);
      if (!ok) {
        *error = "未知的数据类型: " + s + "（可选: " + AllVariableTypeNames() + "）";
        return false;
      }
      opt->request.variableType = t;
    } else if (arg == "-m" || arg == "--mode") {
      const std::string s = nextValue("--mode");
      bool ok = false;
      const ScanOption o = ScanOptionFromName(s, &ok);
      if (!ok) {
        *error = "未知的扫描方式: " + s + "（可选: " + AllScanOptionNames() + "）";
        return false;
      }
      opt->request.scanOption = o;
    } else if (arg == "-v" || arg == "--value") {
      opt->request.value1 = nextValue("--value");
      opt->request.scanString = opt->request.value1;
    } else if (arg == "--value2") {
      opt->request.value2 = nextValue("--value2");
    } else if (arg == "--hex") {
      opt->request.hexadecimal = true;
    } else if (arg == "--pct" || arg == "--percentage") {
      opt->request.percentage = true;
    } else if (arg == "--no-case") {
      opt->request.caseSensitive = false;
    } else if (arg == "--align") {
      long long v = 0;
      const std::string s = nextValue("--align");
      if (!asInt(s, &v) || v < 0) {
        *error = "--align 需要一个非负整数";
        return false;
      }
      if (v == 0) {
        opt->request.fastScanMethod = FastScanMethod::fsmNotAligned;
        opt->request.fastScanAlignSize = 0;
      } else {
        opt->request.fastScanMethod = FastScanMethod::fsmAligned;
        opt->request.fastScanAlignSize = static_cast<int>(v);
      }
    } else if (arg == "--last-digits") {
      long long v = 0;
      const std::string s = nextValue("--last-digits");
      if (!asInt(s, &v) || v <= 0 || v > 8) {
        *error = "--last-digits 需要 1..8 之间的整数";
        return false;
      }
      opt->request.fastScanMethod = FastScanMethod::fsmLastDigits;
      opt->request.fastScanDigitCount = static_cast<int>(v);
    } else if (arg == "--rounding") {
      const std::string s = nextValue("--rounding");
      if (s == "rounded") {
        opt->request.roundingType = RoundingType::rtRounded;
      } else if (s == "extremerounded" || s == "extreme") {
        opt->request.roundingType = RoundingType::rtExtremerounded;
      } else if (s == "truncated" || s == "trunc") {
        opt->request.roundingType = RoundingType::rtTruncated;
      } else {
        *error = "--rounding 只能是 rounded / extremerounded / truncated";
        return false;
      }
    } else if (arg == "--accuracy") {
      long long v = 0;
      const std::string s = nextValue("--accuracy");
      if (!asInt(s, &v) || v < 0 || v > 9) {
        *error = "--accuracy 需要 0..9 之间的整数";
        return false;
      }
      opt->request.floatAccuracy = static_cast<int>(v);
    } else if (arg == "--only-one") {
      opt->request.onlyOne = true;
    } else if (arg == "--unique") {
      opt->request.isUnique = true;
    } else if (arg == "--inverse") {
      opt->request.inverseScan = true;
    } else if (arg == "--threads") {
      long long v = 0;
      const std::string s = nextValue("--threads");
      if (!asInt(s, &v) || v < 1 || v > 64) {
        *error = "--threads 需要 1..64 之间的整数";
        return false;
      }
      opt->request.threadCount = static_cast<int>(v);
    } else if (arg == "--exclude-module" || arg == "--include-module" || arg == "--exclude-range" ||
               arg == "--include-range" || arg == "--range" || arg == "--protect") {
      const std::string s = nextValue(arg.c_str());
      if (s.empty()) {
        *error = arg + " 缺少参数";
        return false;
      }
      RegionFilter& f = opt->request.regionFilter;
      if (arg == "--exclude-module") {
        f.excludeModules.push_back(util::Utf8ToWide(s));
      } else if (arg == "--include-module") {
        f.includeModules.push_back(util::Utf8ToWide(s));
      } else if (arg == "--protect") {
        ParseProtectionFlags(s, &f);
      } else {
        AddressRange range;
        if (!ParseRangeText(s, &range)) {
          *error = arg + " 的区间格式不正确（应为 起-止，例如 0x1000-0x2000）: " + s;
          return false;
        }
        if (arg == "--exclude-range") {
          f.excludeRanges.push_back(range);
        } else if (arg == "--include-range") {
          f.includeRanges.push_back(range);
        } else {
          f.startAddress = range.start;
          f.stopAddress = range.stop;
        }
      }
    } else if (arg == "--write-only") {
      opt->request.regionFilter.SetWritableOnly();
    } else if (arg == "--no-write") {
      opt->request.regionFilter.SetExcludeWritable();
    } else if (arg == "--exec-only") {
      opt->request.regionFilter.SetExecutableOnly();
    } else if (arg == "--no-exec") {
      opt->request.regionFilter.SetExcludeExecutable();
    } else if (arg == "--cow-only") {
      opt->request.regionFilter.SetCopyOnWriteOnly();
    } else if (arg == "--no-private") {
      opt->request.regionFilter.scan_mem_private = false;
    } else if (arg == "--no-image") {
      opt->request.regionFilter.scan_mem_image = false;
    } else if (arg == "--no-mapped") {
      opt->request.regionFilter.scan_mem_mapped = false;
    } else if (arg == "--page-nocache") {
      opt->request.regionFilter.skip_PAGE_NOCACHE = true;
    } else if (arg == "--page-writecombine") {
      opt->request.regionFilter.skip_PAGE_WRITECOMBINE = true;
    } else if (arg == "--show") {
      long long v = 0;
      const std::string s = nextValue("--show");
      if (!asInt(s, &v) || v < 0) {
        *error = "--show 需要一个非负整数";
        return false;
      }
      opt->showCount = static_cast<int>(v);
    } else if (arg == "--save") {
      opt->savePath = nextValue("--save");
    } else if (arg == "--load") {
      opt->loadPath = nextValue("--load");
    } else if (arg == "--write") {
      opt->writeValue = nextValue("--write");
      opt->hasWrite = true;
    } else if (arg == "--index") {
      long long v = 0;
      const std::string s = nextValue("--index");
      if (!asInt(s, &v) || v < 0) {
        *error = "--index 需要一个非负整数";
        return false;
      }
      opt->writeIndex = static_cast<size_t>(v);
    } else if (arg == "--quiet") {
      opt->quiet = true;
    } else {
      *error = "无法识别的参数: " + arg;
      return false;
    }
  }
  return true;
}

//=============================================================================
// 进程选择
//=============================================================================
bool AttachProcess(const Options& opt, ProcessMemory* pm, std::string* error) {
  if (opt.pid != 0) return pm->Open(opt.pid, error);
  if (!opt.processName.empty()) {
    DWORD matched = 0;
    if (!pm->OpenByName(opt.processName, &matched, error)) return false;
    if (matched != 0) {
      std::cout << "已选择进程: " << util::WideToUtf8(pm->Name()) << " (PID "
                << pm->Pid() << ")\n";
    }
    return true;
  }
  *error = "请用 --pid 或 --name 指定目标进程";
  return false;
}

//=============================================================================
// 输出辅助
//=============================================================================
void PrintResults(const ScanEngine& engine, int limit) {
  const size_t total = engine.ResultCount();
  std::cout << "\n结果数量: " << util::FormatThousands(total) << "\n";

  if (total == 0) return;

  const size_t shown = (limit < 0) ? total : std::min<size_t>(total, static_cast<size_t>(limit));
  std::cout << "地址                 值\n";
  PrintSeparator('-');
  for (size_t i = 0; i < shown; ++i) {
    const std::vector<ubyte> value = engine.ValueAt(i);
    char addr[64];
    std::snprintf(addr, sizeof(addr), "0x%016llX",
                  static_cast<unsigned long long>(engine.AddressAt(i)));
    std::cout << addr << "   "
              << util::FormatTypedValue(value.data(), static_cast<int>(value.size()),
                                        engine.CurrentType())
              << "\n";
  }
  if (shown < total) {
    std::cout << "... 其余 " << util::FormatThousands(total - shown)
              << " 条未显示（用 --show 调整）\n";
  }
}

void PrintRegionRows(const std::vector<ScanEngine::RegionReportRow>& rows, bool onlyKept,
                     bool onlySkipped) {
  size_t keptCount = 0;
  size_t skippedCount = 0;
  qword keptBytes = 0;

  std::cout << "\n";
  PrintSeparator('-');
  std::cout << "  基址                 大小        类型   保护        模块            判定\n";
  PrintSeparator('-');

  for (const auto& row : rows) {
    const bool kept = row.kept;
    if (kept) {
      ++keptCount;
      keptBytes += row.region.MemorySize;
    } else {
      ++skippedCount;
    }
    if ((onlyKept && !kept) || (onlySkipped && kept)) continue;

    char base[64];
    std::snprintf(base, sizeof(base), "0x%016llX",
                  static_cast<unsigned long long>(row.region.BaseAddress));

    std::cout << base << "  " << util::FormatSize(row.region.MemorySize) << "\t"
              << (row.decision.isPrivate ? "PRIV" : (row.decision.isImage ? "IMG " : "MAP "))
              << "  " << (row.decision.writable ? "W" : "-") << (row.decision.executable ? "X" : "-")
              << (row.decision.copyOnWrite ? "C" : "-") << "\t"
              << (row.decision.module.empty() ? "-" : util::WideToUtf8(row.decision.module))
              << "\t";

    if (kept) {
      std::cout << "扫描\n";
    } else {
      std::cout << "排除: " << row.decision.excludeReason << "\n";
    }
  }

  PrintSeparator('-');
  std::cout << "合计: " << rows.size() << " 个区域，保留 " << keptCount << " 个 ("
            << util::FormatSize(keptBytes) << ")，排除 " << skippedCount << " 个\n\n";
}

//=============================================================================
// 命令实现
//=============================================================================
int CmdList() {
  const std::vector<ProcessEntry> processes = ProcessMemory::ListProcesses();
  std::cout << "\n共 " << processes.size() << " 个进程\n\n";
  std::cout << "PID      映像名                          窗口标题\n";
  PrintSeparator('-');
  for (const ProcessEntry& p : processes) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%-8lu", static_cast<unsigned long>(p.pid));
    std::string line = std::string(buf) + " " + util::WideToUtf8(p.name);
    if (line.size() < 42) line.resize(42, ' ');
    line += util::WideToUtf8(p.windowTitle);
    std::cout << line << "\n";
  }
  std::cout << "\n";
  return 0;
}

int CmdRegions(const Options& opt) {
  std::string error;
  ProcessMemory pm;
  if (!AttachProcess(opt, &pm, &error)) {
    std::cerr << "错误: " << error << "\n";
    return 1;
  }

  ScanEngine engine(pm);
  std::vector<ScanEngine::RegionReportRow> rows;
  if (!engine.DescribeRegions(opt.request.regionFilter, &rows, &error)) {
    std::cerr << "错误: " << error << "\n";
    return 1;
  }

  std::cout << "目标进程: " << util::WideToUtf8(pm.Name()) << " (PID " << pm.Pid() << ")\n";
  std::cout << "保护标志: " << ProtectionFlagsToString(opt.request.regionFilter) << "\n";
  PrintRegionRows(rows, false, false);
  return 0;
}

int CmdScan(const Options& opt, bool continueScan) {
  std::string error;
  ProcessMemory pm;
  if (!AttachProcess(opt, &pm, &error)) {
    std::cerr << "错误: " << error << "\n";
    return 1;
  }

  ScanEngine engine(pm);
  if (!continueScan) {
    engine.Reset();
  } else if (!opt.loadPath.empty()) {
    if (!engine.LoadResults(opt.loadPath, &error)) {
      std::cerr << "错误: " << error << "\n";
      return 1;
    }
    std::cout << "已载入结果: " << util::FormatThousands(engine.ResultCount()) << " 条\n";
  }

  if (!opt.quiet) {
    engine.SetProgressCallback([](qword scanned, qword total) {
      static int tick = 0;
      if (total == 0) return;
      if ((++tick % 8) != 0) return;
      const double pct = 100.0 * static_cast<double>(scanned) / static_cast<double>(total);
      std::cout << "\r  扫描进度: " << util::FormatSize(scanned) << " / "
                << util::FormatSize(total) << "  (" << static_cast<int>(pct) << "%)   "
                << std::flush;
    });
  }

  const bool ok = continueScan ? engine.NextScan(opt.request, &error)
                               : engine.FirstScan(opt.request, &error);
  if (!opt.quiet) std::cout << "\r" << std::string(72, ' ') << "\r";

  if (!ok) {
    std::cerr << "错误: " << error << "\n";
    return 1;
  }

  const ScanStats& stats = engine.Stats();
  std::cout << (continueScan ? "继续扫描" : "首次扫描") << "完成\n";
  std::cout << "  数据类型 : " << VariableTypeName(engine.CurrentType()) << " ("
            << engine.ValueSize() << " 字节)\n";
  std::cout << "  扫描方式 : " << ScanOptionName(opt.request.scanOption) << "\n";
  std::cout << "  区域数量 : " << stats.regionCount << " 个参与, " << stats.regionSkipped
            << " 个被排除\n";
  std::cout << "  扫描字节 : " << util::FormatSize(stats.totalBytes) << "\n";
  std::cout << "  线程数量 : " << stats.threadCount << "\n";
  std::cout << "  耗时     : " << stats.elapsedSeconds << " 秒\n";
  if (stats.cancelled) std::cout << "  (已被用户中断)\n";

  PrintResults(engine, opt.showCount);

  if (opt.hasWrite) {
    if (!engine.WriteParsed(opt.writeIndex, opt.request, &error)) {
      std::cerr << "写入失败: " << error << "\n";
      return 1;
    }
    std::cout << "已写入第 " << opt.writeIndex << " 项\n";
  }

  if (!opt.savePath.empty()) {
    if (!engine.SaveResults(opt.savePath, &error)) {
      std::cerr << "保存失败: " << error << "\n";
      return 1;
    }
    std::cout << "结果已保存到: " << opt.savePath << "\n";
  }

  return 0;
}

//=============================================================================
// 交互模式
//=============================================================================
std::string PromptLine(const std::string& prompt) {
  std::cout << prompt << std::flush;
  std::string line;
  if (!std::getline(std::cin, line)) return std::string();
  return util::Trim(line);
}

int PromptInt(const std::string& prompt, int defaultValue) {
  const std::string s = PromptLine(prompt);
  if (s.empty()) return defaultValue;
  char* end = nullptr;
  const long v = std::strtol(s.c_str(), &end, 0);
  if (end == s.c_str()) return defaultValue;
  return static_cast<int>(v);
}

struct Session {
  std::unique_ptr<ProcessMemory> process;
  std::unique_ptr<ScanEngine> engine;
  ScanRequest request;
};

bool SessionEnsureProcess(Session* session) {
  if (session->process && session->process->IsOpen()) return true;

  std::cout << "\n请输入目标进程名（例如 notepad）或 PID：";
  const std::string input = PromptLine("");
  if (input.empty()) return false;

  auto pm = std::make_unique<ProcessMemory>();
  std::string error;
  bool ok = false;

  char* end = nullptr;
  const long pid = std::strtol(input.c_str(), &end, 10);
  if (end != input.c_str() && pid > 0) {
    ok = pm->Open(static_cast<DWORD>(pid), &error);
  } else {
    DWORD matched = 0;
    ok = pm->OpenByName(util::Utf8ToWide(input), &matched, &error);
  }

  if (!ok) {
    std::cerr << "附加失败: " << error << "\n";
    return false;
  }

  std::cout << "已附加: " << util::WideToUtf8(pm->Name()) << " (PID " << pm->Pid() << ")"
            << (pm->IsTargetWOW64() ? "  [32 位进程]" : "") << "\n";

  session->process = std::move(pm);
  session->engine = std::make_unique<ScanEngine>(*session->process);
  return true;
}

void InteractiveScanSettings(ScanRequest* request) {
  std::cout << "\n--- 扫描设置 ---\n";
  std::cout << "可用类型: " << AllVariableTypeNames() << "\n";
  const std::string type = PromptLine(std::string("数据类型 [") +
                                      VariableTypeName(request->variableType) + "]: ");
  if (!type.empty()) {
    bool ok = false;
    const VariableType t = VariableTypeFromName(type, &ok);
    if (ok) request->variableType = t;
  }

  std::cout << "可用方式: " << AllScanOptionNames() << "\n";
  const std::string mode = PromptLine(std::string("扫描方式 [") +
                                      ScanOptionName(request->scanOption) + "]: ");
  if (!mode.empty()) {
    bool ok = false;
    const ScanOption o = ScanOptionFromName(mode, &ok);
    if (ok) request->scanOption = o;
  }

  if (ScanOptionNeedsValue(request->scanOption)) {
    request->value1 = PromptLine("扫描值: ");
    request->scanString = request->value1;
    if (ScanOptionNeedsSecondValue(request->scanOption)) {
      request->value2 = PromptLine("扫描值（上限）: ");
    } else if (request->percentage) {
      request->value2 = PromptLine("百分比上限（可直接回车）: ");
    }
  }
}

void InteractiveRegionSettings(ScanRequest* request) {
  RegionFilter& f = request->regionFilter;
  std::cout << "\n--- 区域排除设置 ---\n";
  std::cout << "当前保护标志: " << ProtectionFlagsToString(f) << "\n";
  std::cout << "格式: [+-*][WXC] 组合，例如 -W 表示排除可写区域，+W-C 表示只扫可写非写时复制\n";
  const std::string flags = PromptLine("保护标志（回车保持不变）: ");
  if (!flags.empty()) ParseProtectionFlags(flags, &f);

  const std::string excl = PromptLine("排除模块（逗号分隔，回车不变）: ");
  if (!excl.empty()) {
    f.excludeModules.clear();
    for (const std::string& part : util::Split(excl, ',')) {
      const std::string t = util::Trim(part);
      if (!t.empty()) f.excludeModules.push_back(util::Utf8ToWide(t));
    }
  }

  const std::string incl = PromptLine("仅扫描模块（逗号分隔，回车不变）: ");
  if (!incl.empty()) {
    f.includeModules.clear();
    for (const std::string& part : util::Split(incl, ',')) {
      const std::string t = util::Trim(part);
      if (!t.empty()) f.includeModules.push_back(util::Utf8ToWide(t));
    }
  }

  const std::string exclRange = PromptLine("排除地址区间（如 0x1000-0x2000，回车不变）: ");
  if (!exclRange.empty()) {
    AddressRange r;
    if (ParseRangeText(exclRange, &r)) f.excludeRanges.push_back(r);
    else std::cout << "  区间格式无法识别，已忽略\n";
  }
}

void InteractiveShowRegions(Session* session) {
  if (!SessionEnsureProcess(session)) return;

  std::vector<ScanEngine::RegionReportRow> rows;
  std::string error;
  if (!session->engine->DescribeRegions(session->request.regionFilter, &rows, &error)) {
    std::cerr << "错误: " << error << "\n";
    return;
  }

  std::cout << "\n查看方式: 1=全部  2=只看保留  3=只看被排除\n";
  const int mode = PromptInt("选择 [1]: ", 1);
  PrintRegionRows(rows, mode == 2, mode == 3);
}

int CmdInteractive() {
  Session session;
  session.request.variableType = VariableType::vtDword;
  session.request.scanOption = ScanOption::soExactValue;

  PrintBanner();

  for (;;) {
    std::cout << "\n";
    PrintSeparator('-');
    if (session.process && session.process->IsOpen()) {
      std::cout << "  目标: " << util::WideToUtf8(session.process->Name()) << " (PID "
                << session.process->Pid() << ")";
      if (session.engine) {
        std::cout << "   结果: " << util::FormatThousands(session.engine->ResultCount())
                  << " 条";
      }
      std::cout << "\n";
    } else {
      std::cout << "  尚未选择目标进程\n";
    }
    PrintSeparator('-');
    std::cout <<
        "  1) 选择/切换目标进程\n"
        "  2) 设置扫描类型与方式\n"
        "  3) 设置区域排除规则\n"
        "  4) 查看内存区域（含排除结果）\n"
        "  5) 执行首次扫描\n"
        "  6) 继续扫描（缩小结果）\n"
        "  7) 显示结果\n"
        "  8) 修改某个结果的值\n"
        "  9) 保存 / 载入结果\n"
        "  0) 退出\n";

    const std::string choice = PromptLine("\n请选择: ");

    if (choice == "0" || choice == "q" || choice == "exit") break;

    if (choice == "1") {
      session.engine.reset();
      session.process.reset();
      SessionEnsureProcess(&session);

    } else if (choice == "2") {
      InteractiveScanSettings(&session.request);

    } else if (choice == "3") {
      InteractiveRegionSettings(&session.request);

    } else if (choice == "4") {
      InteractiveShowRegions(&session);

    } else if (choice == "5") {
      if (!SessionEnsureProcess(&session)) continue;
      InteractiveScanSettings(&session.request);

      session.engine->SetProgressCallback([](qword scanned, qword total) {
        static int tick = 0;
        if (total == 0) return;
        if ((++tick % 16) != 0) return;
        std::cout << "\r  扫描中: " << static_cast<int>(100.0 * static_cast<double>(scanned) /
                                                       static_cast<double>(total))
                  << "%   " << std::flush;
      });

      std::string error;
      const bool ok = session.engine->FirstScan(session.request, &error);
      std::cout << "\r" << std::string(40, ' ') << "\r";
      if (!ok) {
        std::cerr << "扫描失败: " << error << "\n";
      } else {
        const ScanStats& st = session.engine->Stats();
        std::cout << "扫描完成: " << util::FormatThousands(session.engine->ResultCount())
                  << " 条结果，扫描 " << util::FormatSize(st.totalBytes) << "，用时 "
                  << st.elapsedSeconds << " 秒（" << st.regionCount << " 个区域，"
                  << st.threadCount << " 线程）\n";
        PrintResults(*session.engine, 20);
      }

    } else if (choice == "6") {
      if (!session.engine || session.engine->Mode() == ScanMode::kNone) {
        std::cout << "请先执行首次扫描\n";
        continue;
      }
      InteractiveScanSettings(&session.request);
      std::string error;
      if (!session.engine->NextScan(session.request, &error)) {
        std::cerr << "继续扫描失败: " << error << "\n";
      } else {
        std::cout << "继续扫描完成: " << util::FormatThousands(session.engine->ResultCount())
                  << " 条结果\n";
        PrintResults(*session.engine, 20);
      }

    } else if (choice == "7") {
      if (!session.engine || session.engine->Mode() == ScanMode::kNone) {
        std::cout << "还没有扫描结果\n";
        continue;
      }
      const int n = PromptInt("显示多少条 [50]: ", 50);
      PrintResults(*session.engine, n);

    } else if (choice == "8") {
      if (!session.engine || session.engine->ResultCount() == 0) {
        std::cout << "还没有扫描结果\n";
        continue;
      }
      const int index = PromptInt("结果序号（从 0 开始）: ", -1);
      if (index < 0 || static_cast<size_t>(index) >= session.engine->ResultCount()) {
        std::cout << "序号超出范围\n";
        continue;
      }
      const std::string value = PromptLine("要写入的值: ");
      session.request.value1 = value;
      std::string error;
      if (!session.engine->WriteParsed(static_cast<size_t>(index), session.request, &error)) {
        std::cerr << "写入失败: " << error << "\n";
      } else {
        std::cout << "已写入 0x" << util::FormatHex(session.engine->AddressAt(
                          static_cast<size_t>(index)))
                  << "\n";
      }

    } else if (choice == "9") {
      std::cout << "  1) 保存结果\n  2) 载入结果\n";
      const int sub = PromptInt("选择: ", 1);
      const std::string path = PromptLine("文件路径: ");
      if (path.empty()) continue;

      if (!SessionEnsureProcess(&session)) continue;
      std::string error;

      if (sub == 1) {
        if (!session.engine->SaveResults(path, &error)) {
          std::cerr << "保存失败: " << error << "\n";
        } else {
          std::cout << "已保存 " << util::FormatThousands(session.engine->ResultCount())
                    << " 条结果到 " << path << "\n";
        }
      } else {
        if (!session.engine->LoadResults(path, &error)) {
          std::cerr << "载入失败: " << error << "\n";
        } else {
          std::cout << "已载入 " << util::FormatThousands(session.engine->ResultCount())
                    << " 条结果\n";
        }
      }
    }
  }

  std::cout << "\n再见。\n";
  return 0;
}

}  // namespace

//=============================================================================
int cli_main(int argc, char** argv) {
  SetupConsole();

  if (argc <= 1) {
    return CmdInteractive();
  }

  Options opt;
  std::string error;
  if (!ParseArgList(argc, argv, &opt, &error)) {
    std::cerr << "参数错误: " << error << "\n\n";
    PrintUsage();
    return 2;
  }

  if (opt.wantHelp) {
    PrintBanner();
    PrintUsage();
    return 0;
  }

  if (opt.command.empty()) {
    PrintBanner();
    PrintUsage();
    return 2;
  }

  if (opt.command == "interactive") return CmdInteractive();
  if (opt.command == "list") {
    PrintBanner();
    return CmdList();
  }
  if (opt.command == "regions") {
    PrintBanner();
    return CmdRegions(opt);
  }
  if (opt.command == "scan") {
    PrintBanner();
    return CmdScan(opt, false);
  }
  if (opt.command == "next") {
    PrintBanner();
    return CmdScan(opt, true);
  }

  PrintBanner();
  PrintUsage();
  return 2;
}
