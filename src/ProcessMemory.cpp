//=============================================================================
//  ProcessMemory.cpp
//=============================================================================
#include "ProcessMemory.h"

#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>

#include "CEUtil.h"

#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#endif

namespace ce {
namespace {

std::wstring NormalizeImageName(const std::wstring& name) {
  std::wstring n = name;
  if (n.size() < 4 || !util::IEquals(n.substr(n.size() - 4), L".exe")) n += L".exe";
  return n;
}

}  // namespace

//-----------------------------------------------------------------------------
ProcessMemory::~ProcessMemory() { Close(); }

void ProcessMemory::Close() {
  if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
    ::CloseHandle(handle_);
  }
  handle_ = nullptr;
  pid_ = 0;
  name_.clear();
  moduleCache_.clear();
  moduleCacheValid_ = false;
}

//-----------------------------------------------------------------------------
bool ProcessMemory::EnableDebugPrivilege() {
  HANDLE token = nullptr;
  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    return false;

  TOKEN_PRIVILEGES tp{};
  tp.PrivilegeCount = 1;
  if (!::LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
    ::CloseHandle(token);
    return false;
  }

  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  const BOOL ok = ::AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
  const DWORD last = ::GetLastError();
  ::CloseHandle(token);
  return ok != FALSE && last == ERROR_SUCCESS;
}

std::string ProcessMemory::Win32ErrorString(DWORD code) {
  if (code == 0) code = ::GetLastError();
  LPWSTR buffer = nullptr;
  const DWORD n = ::FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&buffer),
      0, nullptr);

  std::string result = "Win32 错误 " + std::to_string(code);
  if (n != 0 && buffer != nullptr) {
    std::wstring msg(buffer, n);
    while (!msg.empty() && (msg.back() == L'\r' || msg.back() == L'\n' || msg.back() == L' '))
      msg.pop_back();
    if (!msg.empty()) result += ": " + util::WideToUtf8(msg);
  } else {
    switch (code) {
      case ERROR_ACCESS_DENIED: result += ": 访问被拒绝（需要管理员权限 / SeDebugPrivilege）"; break;
      case ERROR_INVALID_PARAMETER: result += ": 参数无效（进程可能已退出）"; break;
      default: break;
    }
  }
  if (buffer != nullptr) ::LocalFree(buffer);
  return result;
}

//-----------------------------------------------------------------------------
bool ProcessMemory::Open(DWORD pid, std::string* error) {
  Close();
  if (pid == 0) {
    if (error) *error = "PID 不能为 0（System Idle Process 无法扫描）";
    return false;
  }

  EnableDebugPrivilege();  // 失败不致命，仅影响高权限进程

  const DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                       PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION;
  HANDLE h = ::OpenProcess(access, FALSE, pid);
  if (h == nullptr) {
    // 退一步：只读
    h = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  }

  if (h == nullptr) {
    if (error) {
      *error = "无法打开进程 " + std::to_string(pid) + "，" +
               Win32ErrorString(::GetLastError());
      if (::GetLastError() == ERROR_ACCESS_DENIED)
        *error += "（请尝试以管理员身份运行本程序）";
    }
    return false;
  }

  handle_ = h;
  pid_ = pid;

  // 计算目标与自身的位数关系
  BOOL targetWow64 = FALSE;
  BOOL selfWow64 = FALSE;
  ::IsWow64Process(handle_, &targetWow64);
  ::IsWow64Process(::GetCurrentProcess(), &selfWow64);
  selfIs64_ = (selfWow64 == FALSE);
  isWOW64_ = (targetWow64 != FALSE);

  // 取映像名
  {
    std::vector<wchar_t> buffer(MAX_PATH * 2);
    DWORD size = static_cast<DWORD>(buffer.size());
    if (::QueryFullProcessImageNameW(handle_, 0, buffer.data(), &size)) {
      name_ = buffer.data();
      const size_t slash = name_.find_last_of(L"\\/");
      if (slash != std::wstring::npos) name_ = name_.substr(slash + 1);
    } else {
      name_ = L"pid_" + std::to_wstring(pid);
    }
  }

  moduleCacheValid_ = false;
  return true;
}

//-----------------------------------------------------------------------------
std::vector<ProcessEntry> ProcessMemory::ListProcesses() {
  std::vector<ProcessEntry> list;

  HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return list;

  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (::Process32FirstW(snapshot, &pe)) {
    do {
      ProcessEntry entry;
      entry.pid = pe.th32ProcessID;
      entry.name = pe.szExeFile;

      // 尝试取主窗口标题（不需要权限）
      HWND hwnd = nullptr;
      struct FindCtx {
        DWORD pid;
        HWND result;
      } ctx{pe.th32ProcessID, nullptr};

      ::EnumWindows(
          [](HWND w, LPARAM param) -> BOOL {
            auto* c = reinterpret_cast<FindCtx*>(param);
            DWORD wpid = 0;
            ::GetWindowThreadProcessId(w, &wpid);
            if (wpid == c->pid && ::IsWindowVisible(w) && ::GetWindow(w, GW_OWNER) == nullptr) {
              const int len = ::GetWindowTextLengthW(w);
              if (len > 0) {
                c->result = w;
                return FALSE;
              }
            }
            return TRUE;
          },
          reinterpret_cast<LPARAM>(&ctx));
      hwnd = ctx.result;

      if (hwnd != nullptr) {
        const int len = ::GetWindowTextLengthW(hwnd);
        if (len > 0) {
          std::vector<wchar_t> title(static_cast<size_t>(len) + 1);
          ::GetWindowTextW(hwnd, title.data(), len + 1);
          entry.windowTitle = title.data();
        }
      }

      list.push_back(std::move(entry));
    } while (::Process32NextW(snapshot, &pe));
  }

  ::CloseHandle(snapshot);

  std::sort(list.begin(), list.end(), [](const ProcessEntry& a, const ProcessEntry& b) {
    return a.pid < b.pid;
  });
  return list;
}

//-----------------------------------------------------------------------------
bool ProcessMemory::OpenByName(const std::wstring& imageName, DWORD* matchedPid,
                               std::string* error) {
  const std::wstring wanted = NormalizeImageName(imageName);
  const std::wstring wantedNoExe = wanted.substr(0, wanted.size() - 4);

  std::vector<DWORD> matches;

  for (const ProcessEntry& entry : ListProcesses()) {
    const std::wstring found = NormalizeImageName(entry.name);
    const std::wstring foundNoExe = found.substr(0, found.size() - 4);
    if (util::IEquals(found, wanted) || util::IEquals(foundNoExe, wantedNoExe)) {
      matches.push_back(entry.pid);
    }
  }

  if (matches.empty()) {
    if (error) *error = "未找到名为 " + util::WideToUtf8(imageName) + " 的进程";
    return false;
  }

  // 多个同名进程时选择 PID 最大的（通常是最近启动的实例）
  const DWORD pid = *std::max_element(matches.begin(), matches.end());
  if (matchedPid) *matchedPid = pid;
  if (matches.size() > 1) {
    // 不视为错误，但把选择结果通过 Name() 反馈
  }
  return Open(pid, error);
}

//-----------------------------------------------------------------------------
bool ProcessMemory::Read(ptruint address, void* buffer, size_t size, size_t* bytesRead) const {
  SIZE_T read = 0;
  const BOOL ok = ::ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address), buffer,
                                      size, &read);
  if (bytesRead) *bytesRead = static_cast<size_t>(read);
  return ok != FALSE;
}

size_t ProcessMemory::ReadPartial(ptruint address, void* buffer, size_t size) const {
  if (size == 0) return 0;

  SIZE_T read = 0;
  if (::ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address), buffer, size, &read) &&
      read == size) {
    return size;
  }

  // 整块失败：退化为按 4KB 页逐页读取，能读多少算多少
  const size_t pageSize = 4096;
  size_t total = 0;
  while (total < size) {
    const size_t remain = size - total;
    const size_t chunk = std::min(remain, pageSize);
    SIZE_T got = 0;
    if (::ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address + total),
                            static_cast<unsigned char*>(buffer) + total, chunk, &got)) {
      total += static_cast<size_t>(got);
      if (got == 0) break;
    } else {
      break;
    }
  }
  return total;
}

bool ProcessMemory::Write(ptruint address, const void* buffer, size_t size,
                          size_t* bytesWritten) const {
  SIZE_T written = 0;
  const BOOL ok = ::WriteProcessMemory(handle_, reinterpret_cast<LPVOID>(address),
                                       buffer, size, &written);
  if (bytesWritten) *bytesWritten = static_cast<size_t>(written);
  return ok != FALSE;
}

//-----------------------------------------------------------------------------
std::vector<ModuleEntry> ProcessMemory::Modules() const {
  std::vector<ModuleEntry> list;
  if (!IsOpen()) return list;

  HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
  if (snapshot == INVALID_HANDLE_VALUE) {
    // 32/64 位不匹配时退化到 EnumProcessModulesEx + QueryFullProcessImageName
    HMODULE modules[1024];
    DWORD needed = 0;
    if (::EnumProcessModulesEx(handle_, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
      const DWORD count = needed / sizeof(HMODULE);
      for (DWORD i = 0; i < count && i < 1024; ++i) {
        ModuleEntry entry;
        entry.base = reinterpret_cast<ptruint>(modules[i]);
        std::vector<wchar_t> nameBuf(MAX_PATH * 2);
        if (::GetModuleBaseNameW(handle_, modules[i], nameBuf.data(),
                                 static_cast<DWORD>(nameBuf.size()))) {
          entry.name = nameBuf.data();
        }
        std::vector<wchar_t> pathBuf(MAX_PATH * 4);
        if (::GetModuleFileNameExW(handle_, modules[i], pathBuf.data(),
                                   static_cast<DWORD>(pathBuf.size()))) {
          entry.path = pathBuf.data();
        }
        MODULEINFO info{};
        if (::GetModuleInformation(handle_, modules[i], &info, sizeof(info))) {
          entry.size = info.SizeOfImage;
        }
        list.push_back(std::move(entry));
      }
    }
    return list;
  }

  MODULEENTRY32W me{};
  me.dwSize = sizeof(me);
  if (::Module32FirstW(snapshot, &me)) {
    do {
      ModuleEntry entry;
      entry.name = me.szModule;
      entry.path = me.szExePath;
      entry.base = reinterpret_cast<ptruint>(me.modBaseAddr);
      entry.size = me.modBaseSize;
      list.push_back(std::move(entry));
    } while (::Module32NextW(snapshot, &me));
  }
  ::CloseHandle(snapshot);
  return list;
}

const std::vector<ModuleEntry>& ProcessMemory::CachedModules() {
  if (!moduleCacheValid_) {
    moduleCache_ = Modules();
    moduleCacheValid_ = true;
  }
  return moduleCache_;
}

const ModuleEntry* ProcessMemory::FindModule(const std::vector<ModuleEntry>& modules,
                                             ptruint address) {
  for (const ModuleEntry& m : modules) {
    if (m.Contains(address)) return &m;
  }
  return nullptr;
}

//-----------------------------------------------------------------------------
void ProcessMemory::AddressRange(ptruint* minAddress, ptruint* maxAddress) const {
  SYSTEM_INFO si{};
  ::GetNativeSystemInfo(&si);

  const ptruint lowest = reinterpret_cast<ptruint>(si.lpMinimumApplicationAddress);
  const ptruint highest = reinterpret_cast<ptruint>(si.lpMaximumApplicationAddress);

  if (isWOW64_ && selfIs64_) {
    // 32 位目标：把可扫描范围限制在低 4GB 地址空间内
    const ptruint cap = static_cast<ptruint>(0xFFFFFFFFULL);
    if (minAddress) *minAddress = lowest;
    if (maxAddress) *maxAddress = (highest < cap) ? highest : cap;
    return;
  }
  if (minAddress) *minAddress = lowest;
  if (maxAddress) *maxAddress = highest;
}

std::wstring ProcessMemory::ImagePath() const {
  if (!IsOpen()) return std::wstring();
  std::vector<wchar_t> buffer(MAX_PATH * 4);
  DWORD size = static_cast<DWORD>(buffer.size());
  if (::QueryFullProcessImageNameW(handle_, 0, buffer.data(), &size)) return buffer.data();
  return std::wstring();
}

}  // namespace ce
