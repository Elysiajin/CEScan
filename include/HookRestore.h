#pragma once
// ============================================================================
//  HookRestore.h —— VM / HOOK 还原字节自动查找
//
//  把《VM还原档案》里靠手做的事自动化：
//    ① 判断某个地址是不是被 HOOK 了（函数头被换成 jmp/call 等）
//    ② 顺着"跳回来"的那条 jmp/call/push，反推出被覆盖掉的原始字节
//
//  档案里的一手做法（原话）：
//    "他调回来的是下一句 00A53D9E 所以我们就搜索 jmp 00A53D9E"        → 搜索跳回点
//    "刚刚好 7 个字节，于是还原了就是 009F644D = 64 89 0D 00 00 00 00"  → 跳回指令前面那几字节就是还原字节
//    "HOOK 了 5 个字节，然后 NOP 填充了 2 个字节…跳回的地址就是 A+7"      → 需要跳过 NOP 再算跳回点
//
//  这就是本模块的两个核心函数：FindRestoreBytes()（搜跳回点 + 取前置字节）
//  与 AnalyzeHook()（判定 HOOK + 组织跳回点候选）。
//
//  与 CE 的关系：CE 的"谁访问了这个值"只给出命中指令；
//  这里在命中之后自动多走一步"还原"，并把结论写到输出窗口 + 本地记录文件。
// ============================================================================
#include <cstdio>
#include <string>
#include <vector>

#include "CETypes.h"
#include "ProcessMemory.h"

namespace ce {

// ---------------------------------------------------------------------------
//  一次还原分析的结果
// ---------------------------------------------------------------------------
struct RestoreResult {
  ptruint addr = 0;              // 被分析的地址（通常是命中指令地址 RIP）
  bool    readable = false;      // 该地址读得动
  std::vector<ubyte> curBytes;   // addr 处当前指令字节
  std::string curHex;            // "E9 4A 78 65 01"
  std::string curDisasm;         // "jmp 0x020B771F"

  bool        isHook = false;    // 判定为 HOOK
  std::string hookKind;          // "jmp rel32" / "call rel32" / "jmp rel8" / "jmp [rip+disp]" …
  ptruint     hookTarget = 0;    // HOOK 跳去的地址（VM 区）
  int         hookLen = 0;       // HOOK 实际覆盖的字节数（含尾部 NOP 填充）
  ptruint     resumeAddr = 0;    // 跳回点 = addr + hookLen

  bool               found = false;   // 是否找到还原字节
  ptruint            restoreSite = 0; // "跳回指令"所在地址（还原代码的最后一条）
  ptruint            totalScanned = 0;// 共扫描了多少字节（诊断用）
  size_t             execRegions = 0; // 进程里可执行区域个数
  size_t             execBytes = 0;   // 可执行区域总字节
  bool               hintScanned = false; // 是否扫到了"HOOK 跳去的那一页"
  std::vector<ubyte> origBytes;       // 还原字节
  std::string        origHex;         // "55 8B EC 6A FF"
  std::string        origDisasm;      // "push ebp / mov ebp, esp / push -1"
  int                confidence = 0;  // 2=高(边界对齐干净) 1=低(直接取前置字节) 0=未找到
  std::string        method;          // 用的是哪种办法
  std::string        note;            // 备注 / 失败原因

  // 多级回溯（《VM还原档案》3/1.txt：一级凑不齐就往上追一级）
  int         chainDepth = 0;   // 0/1=一级就够；>=2 表示靠多级回溯拼出来的
  std::string chainPath;        // 各级 "目标→命中点(取N字节)" 的文字链，便于核对
};

// 分析一个地址：判断是否 HOOK，并尽力自动找回还原字节。
// scanWholeMemory=false 时只扫"已加载模块之外"的私有可执行区（更快）。
RestoreResult AnalyzeHook(ProcessMemory& proc, ptruint addr,
                          bool scanWholeMemory = true);

// 只做"搜索跳回点 + 取前置字节"这一步（给定跳回点与 HOOK 长度）。
// hintAddr != 0 时先扫它所在的那一页/区域（一般就是 HOOK 跳去的 VM 区，
// 跳回指令几乎总在那里），命中就立刻返回，不必全内存扫。
RestoreResult FindRestoreBytes(ProcessMemory& proc, ptruint addr,
                               ptruint resumeAddr, int hookLen,
                               ptruint hintAddr = 0);

// 结果转文本：单行摘要 / 多行详情（写输出窗口与本地文件用）
std::string FormatRestoreLine(const RestoreResult& r);
std::string FormatRestoreDetail(const RestoreResult& r);

// 结果转「手工写法」块：还原字节怎么写回去的步骤（\r\n 分行）。
// 调用方逐行加 "# " 前缀发输出窗口，并整段进剪贴板，方便照着手工操作。
std::string FormatRestoreRecipe(const RestoreResult& r);

// ---------------------------------------------------------------------------
//  本地记录文件：<exe 所在目录>/还原记录_YYYYMMDD_HHMMSS.txt
// ---------------------------------------------------------------------------
class RestoreJournal {
 public:
  ~RestoreJournal();

  // 首次调用时按当前时间创建文件（追加写，立即刷盘）
  bool Open();
  void Write(const std::string& line);
  void WriteRaw(const std::string& text);

  const std::string& Path() const { return path_; }   // 供日志中显示（ANSI）
  bool IsOpen() const { return fp_ != nullptr; }

 private:
  FILE*       fp_ = nullptr;
  std::string path_;
};

// ===========================================================================
//  访问性质自动分类
//
//  背景：页守卫命中只告诉我们"谁访问了这个值"，但访问者身份差别很大：
//    · 游戏主逻辑的普通读写（正常）
//    · 反作弊线程来核对数值（检测）
//    · CRC/完整性校验线程扫代码（CRC）
//    · VM 柱/蹦床里的代码（被保护程序搬进匿名内存的代码，还原场景的主角）
//  这里把判定自动化，结论直接显示在监视窗口新增的「访问性质」列里。
//
//  判定信号（确定性规则，全部可解释）：
//    S1 指令本身：crc32 指令 / 累加器类(add/xor/ror…) / cmp·test 直接比对
//       / 普通 mov 读写 / rep 串搬运
//    S2 RIP 所在区域：不在任何已加载模块的匿名可执行内存 = VM/蹦床/动态代码
//       （这正是《VM还原档案》处理的那类区域，铁证级信号）
//    S3 行为特征：同一 RIP 命中多次后，间隔规律且高频 = 校验/检测线程在轮询
// ===========================================================================
enum class AccessKind {
  Unknown = 0,   // 特征不足
  Normal,        // 普通访问/写入（游戏逻辑）
  Detect,        // 检测（比对、轮询核对）
  CRC,           // CRC/完整性校验（累加、逐字节扫、rep 搬运）
  VM,            // VM 柱/蹦床/匿名内存里的代码
};

struct AccessVerdict {
  AccessKind  kind = AccessKind::Unknown;
  int         confidence = 0;   // 0~3，越大越可信
  std::string label;            // 中文短标签（「访问性质」列直接显示）
  std::string reason;           // 判定依据（更多信息框/日志展示）
};

// 静态判定：单条命中就能做（指令文本 + RIP 是否在模块里 + 是否写入）。
// moduleEmpty = RIP 不在任何已加载模块内（Debugger 的 ModuleOf 返回空即 true）。
AccessVerdict ClassifyAccessStatic(const std::string& disasm, bool write,
                                   bool moduleEmpty);

// 行为修正：同一 RIP 命中多次后补充轮询规律性。
//   count       命中总次数（<3 时不参与判定，原样返回）
//   avgInterval 平均命中间隔（毫秒）
//   jitter      间隔抖动系数 = 平均绝对偏差 / 平均值（0~1，越小越规律）
// 普通访问/待定 + 规律高频 → 升级为"疑似轮询"；已有 CRC/VM 判定 → 提升置信度。
AccessVerdict RefineAccessVerdict(const AccessVerdict& base,
                                  int count, double avgInterval, double jitter);

}  // namespace ce
