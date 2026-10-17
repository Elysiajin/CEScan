// ============================================================================
//  StrSearch.cpp —— OD 中文搜索引擎实现（VirtualQueryEx 遍历 + ReadPartial 提取）
// ============================================================================
#include "StrSearch.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <functional>
#include <algorithm>
#include <thread>
#include <atomic>
#include <mutex>

namespace ce {

namespace {

// 快捷别名（静态成员函数指针不可 using，直接定义为本地内联）
inline bool IsPrintableAscii(ubyte b) { return b >= 0x20 && b <= 0x7E; }
inline bool IsGbkLead(ubyte b) { return b >= 0x81 && b <= 0xFE; }
inline bool IsGbkTrail(ubyte b) { return (b >= 0x40 && b <= 0x7E) || (b >= 0x80 && b <= 0xFE); }

// ASCII 模式：提取一段缓冲区里的字符串（支持 GBK 双字节中文）
void ExtractAscii(const ubyte* p, size_t n, ptruint base, int minLen,
                  bool requireChinese, std::vector<StrHit>& out) {
  size_t i = 0;
  while (i < n) {
    size_t start = i;
    size_t chars = 0;
    bool hasChinese = false;
    while (i < n) {
      ubyte b = p[i];
      if (IsPrintableAscii(b)) { ++i; ++chars; }
      else if (IsGbkLead(b) && i + 1 < n && IsGbkTrail(p[i + 1])) {
        if (b >= 0xB0 && b <= 0xF7 && p[i + 1] >= 0xA1) hasChinese = true;
        i += 2; ++chars;
      }
      else break;
    }
    if ((int)chars >= minLen && (!requireChinese || hasChinese)) {
      StrHit h;
      h.address = base + start;
      h.length = (int)(i - start);
      h.kind = 0;
      int wn = ::MultiByteToWideChar(936, 0, (const char*)(p + start), h.length, nullptr, 0);
      if (wn > 0 && wn < 4096) {
        h.text.resize(wn);
        ::MultiByteToWideChar(936, 0, (const char*)(p + start), h.length, &h.text[0], wn);
        out.push_back(std::move(h));
      }
    }
    ++i;
  }
}

// UNICODE 模式：UTF-16LE
void ExtractUnicode(const ubyte* p, size_t n, ptruint base, int minLen,
                    bool requireChinese, std::vector<StrHit>& out) {
  size_t i = 0;
  while (i + 1 < n) {
    size_t start = i;
    size_t chars = 0;
    bool hasChinese = false;
    while (i + 1 < n) {
      wchar_t wc;
      std::memcpy(&wc, p + i, 2);
      bool printable =
          (wc >= 0x20 && wc <= 0x7E) ||
          (wc >= 0x4E00 && wc <= 0x9FFF) ||
          (wc >= 0x3000 && wc <= 0x303F) ||
          (wc >= 0xFF00 && wc <= 0xFFEF);
      if (!printable) break;
      if (wc >= 0x4E00 && wc <= 0x9FFF) hasChinese = true;
      i += 2; ++chars;
    }
    if ((int)chars >= minLen && (!requireChinese || hasChinese)) {
      StrHit h;
      h.address = base + start;
      h.length = (int)(i - start);
      h.kind = 1;
      h.text.assign((const wchar_t*)(p + start), chars);
      out.push_back(std::move(h));
    }
    i += 2;
  }
}

} // anonymous namespace

bool StrSearch::Run(HANDLE hProc, const StrSearchOptions& opt,
                    std::vector<StrHit>& out,
                    std::function<bool(int)> progress,
                    std::string* error) {
  out.clear();
  if (!hProc) { if (error) *error = "进程句柄为空"; return false; }

  SYSTEM_INFO si{};
  ::GetSystemInfo(&si);
  ptruint addr = (ptruint)si.lpMinimumApplicationAddress;
  const ptruint maxAddr = (ptruint)si.lpMaximumApplicationAddress;

  // 先统计总量
  struct Rg { ptruint base; size_t size; };
  std::vector<Rg> regions;
  MEMORY_BASIC_INFORMATION mbi{};
  while (addr < maxAddr) {
    if (::VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) == 0) break;
    if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS &&
        !(mbi.Protect & PAGE_GUARD) && mbi.RegionSize < (1ull << 30)) {
      regions.push_back({(ptruint)mbi.BaseAddress, (size_t)mbi.RegionSize});
    }
    addr = (ptruint)mbi.BaseAddress + mbi.RegionSize;
  }

  qword total = 0;
  for (auto& r : regions) total += r.size;

  const size_t kChunk = 1 << 20;

  // 并行线程数：取硬件并发，封顶 8，且不超过区域数
  unsigned nproc = std::thread::hardware_concurrency();
  unsigned tcnt = (nproc ? nproc : 2u);
  if (tcnt > 8) tcnt = 8;
  if (tcnt > regions.size()) tcnt = (unsigned)regions.size();

  // 每个线程独立收集到本地 part[id]，最后再合并（避免并发写共享 vector）
  std::vector<std::vector<StrHit>> part(tcnt);
  std::atomic<qword> done{0};
  std::atomic<bool> cancelled{false};
  std::mutex cb;  // 串行化进度回调，避免多线程并发刷新 GUI

  auto worker = [&](unsigned id) {
    std::vector<ubyte> buf(kChunk);
    std::vector<StrHit>& local = part[id];
    for (size_t rij = id; rij < regions.size(); rij += tcnt) {
      const Rg& r = regions[rij];
      if (cancelled.load()) break;
      ptruint a = r.base;
      size_t remain = r.size;
      while (remain > 0) {
        SIZE_T want = (SIZE_T)std::min<size_t>(kChunk, remain);
        SIZE_T got = 0;
        // 读取失败读到 0 -> 跳过该区域（不中断整体扫描）
        if (!::ReadProcessMemory(hProc, (LPCVOID)a, buf.data(), want, &got) || got == 0)
          break;
        if (opt.mode == 0 || opt.mode == 2)
          ExtractAscii(buf.data(), got, a, opt.minLength, opt.requireChinese, local);
        if (opt.mode == 1 || opt.mode == 2)
          ExtractUnicode(buf.data(), got, a, opt.minLength, opt.requireChinese, local);
        a += got;
        remain -= got;
        // 进度：按 ~1MB 粒度上报一次（跨线程合计），回调在互斥锁内串行执行
        qword prev = done.fetch_add(got);
        qword now = prev + got;
        if (progress && total && (prev >> 20) != (now >> 20)) {
          int pct = (int)(now * 100 / total);
          std::lock_guard<std::mutex> lk(cb);
          if (!progress(pct)) cancelled.store(true);
        }
        if (cancelled.load()) break;
      }
      if (local.size() > 500000) cancelled.store(true);  // 单线程上限，防止内存爆炸
    }
  };

  std::vector<std::thread> ts;
  ts.reserve(tcnt);
  for (unsigned i = 0; i < tcnt; ++i) ts.emplace_back(worker, i);
  for (auto& t : ts) t.join();

  if (cancelled.load()) { out.clear(); return false; }

  out.clear();
  out.reserve(part.size() * 4096);
  for (auto& v : part) out.insert(out.end(), v.begin(), v.end());
  if (out.size() > 500000) out.resize(500000);  // 全局安全上限 50 万条
  return true;
}

} // namespace ce
