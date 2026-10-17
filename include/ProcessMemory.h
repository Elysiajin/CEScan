#pragma once
//=============================================================================
//  ProcessMemory.h
//  目标进程接入层：进程枚举 / 打开 / 读写内存 / 模块枚举 / 地址空间范围。
//
//  对应原始 CE 中的：
//      ProcessHandlerUnit.pas   (processhandle / getprocesslist / 32-64 位判定)
//      NewKernelHandler.pas     (ReadProcessMemory / VirtualQueryEx 包装)
//      processlist.pas          (进程列表)
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

namespace ce {

//-----------------------------------------------------------------------------
// 进程列表项
//-----------------------------------------------------------------------------
struct ProcessEntry {
  DWORD pid = 0;
  std::wstring name;         // 映像名，例如 "notepad.exe"
  std::wstring windowTitle;  // 主窗口标题（可能为空）
};

//-----------------------------------------------------------------------------
// 模块列表项
//-----------------------------------------------------------------------------
struct ModuleEntry {
  std::wstring name;
  std::wstring path;
  ptruint base = 0;
  qword size = 0;

  bool Contains(ptruint address) const {
    return address >= base && address < base + size;
  }
};

//-----------------------------------------------------------------------------
// 进程内存访问器
//-----------------------------------------------------------------------------
class ProcessMemory {
 public:
  ProcessMemory() = default;
  ~ProcessMemory();

  ProcessMemory(const ProcessMemory&) = delete;
  ProcessMemory& operator=(const ProcessMemory&) = delete;

  // 按 PID 打开（自动尝试提升 SeDebugPrivilege）
  bool Open(DWORD pid, std::string* error = nullptr);
  // 按映像名打开（大小写不敏感，可带或不带 .exe）
  bool OpenByName(const std::wstring& imageName, DWORD* matchedPid = nullptr,
                  std::string* error = nullptr);

  void Close();
  bool IsOpen() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

  HANDLE Handle() const { return handle_; }
  DWORD Pid() const { return pid_; }
  const std::wstring& Name() const { return name_; }

  // 目标是否为 32 位进程运行在 64 位系统上
  bool IsTargetWOW64() const { return isWOW64_; }
  bool IsCurrentProcess64() const { return selfIs64_; }

  bool Read(ptruint address, void* buffer, size_t size, size_t* bytesRead = nullptr) const;
  // 读取失败时按页回退，返回实际读到的字节数（对应 CE 分块读取的容错）
  size_t ReadPartial(ptruint address, void* buffer, size_t size) const;

  bool Write(ptruint address, const void* buffer, size_t size, size_t* bytesWritten = nullptr) const;

  std::vector<ModuleEntry> Modules() const;
  const std::vector<ModuleEntry>& CachedModules();

  // 可用的用户态地址范围（由 GetSystemInfo 推导）
  void AddressRange(ptruint* minAddress, ptruint* maxAddress) const;

  // 返回进程主模块所在路径（可能为空）
  std::wstring ImagePath() const;

  //--- 静态工具 -----------------------------------------------------------
  static std::vector<ProcessEntry> ListProcesses();
  static bool EnableDebugPrivilege();
  static std::string Win32ErrorString(DWORD code);
  static const ModuleEntry* FindModule(const std::vector<ModuleEntry>& modules, ptruint address);

 private:
  HANDLE handle_ = nullptr;
  DWORD pid_ = 0;
  std::wstring name_;
  bool isWOW64_ = false;
  bool selfIs64_ = true;
  mutable std::vector<ModuleEntry> moduleCache_;
  mutable bool moduleCacheValid_ = false;
};

}  // namespace ce
