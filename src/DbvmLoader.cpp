// ============================================================================
//  DbvmLoader.cpp —— DBVM 加载器实现（端口 CE 的 dbk32/DBK32functions.pas）
//
//  主要对应关系：
//    LoadDriver()  ←  CE 的 LoadDBK32（DBK32functions.pas ~L3260-3450）
//    Launch()      ←  CE 的 internal_LaunchDBVM（DBK32functions.pas L2814-2888）
//    Unload()      ←  CE 的 dbvm 卸载（Kernelmodule unloader 同款 SCM 流程）
//
//  已核实的关键常量（与 CE 逐位一致）：
//    IOCTL_CE_LAUNCHDBVM = 0x22E0E8
//    LAUNCHDBVM 输入结构 = { QWORD dbvmimgpath（指向 NT 路径串 \??\...）,
//                            DWORD cpuid }（CE 未加 packed，按默认 8 对齐 16 字节）
//    服务类型 SERVICE_KERNEL_DRIVER / DEMAND_START / ERROR_NORMAL
//    注册表键  HKLM\SYSTEM\CurrentControlSet\Services\<服务名>
//              A=\Device\<服务名>  B=\DosDevices\<服务名>
//              C=\BaseNamedObjects\<进程事件名>  D=\BaseNamedObjects\<线程事件名>
// ============================================================================
#include "DbvmLoader.h"

#include <winsvc.h>

#include <cstdio>

namespace ce {
namespace {

std::wstring AnsiToWide(const std::string& s) {
  if (s.empty()) return L"";
  const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
  std::wstring w(n > 0 ? n - 1 : 0, L'\0');
  if (n > 0) ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
  return w;
}

std::string WideToAnsi(const std::wstring& w) {
  if (w.empty()) return "";
  const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
  std::string s(n > 0 ? n - 1 : 0, '\0');
  if (n > 0) ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], n, nullptr, nullptr);
  return s;
}

bool FileExistsW(const std::wstring& path) {
  const DWORD attr = ::GetFileAttributesW(path.c_str());
  return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

// 把全路径末尾的文件名换成 newName（旧 MSVC 没有 std::filesystem，手写）
std::wstring ReplaceFilename(const std::wstring& full, const std::wstring& newName) {
  const size_t pos = full.find_last_of(L"\\/");
  if (pos == std::wstring::npos) return newName;
  return full.substr(0, pos + 1) + newName;
}

}  // namespace

void DbvmLoader::SetError(std::string* errOut, const std::string& msg) const {
  if (errOut) *errOut = msg;
}

std::string DbvmLoader::ResolveVmdiskPath() const {
  if (!cfg_.vmdiskPath.empty()) return WideToAnsi(cfg_.vmdiskPath);
  // 默认取驱动文件同目录下的 vmdisk.img
  return WideToAnsi(ReplaceFilename(cfg_.driverPath, L"vmdisk.img"));
}

// 启用当前进程的 SeDebugPrivilege。
// dbk 驱动的 DispatchCreate 用 SeSinglePrivilegeCheck(SE_DEBUG_PRIVILEGE)
// 校验打开者，管理员进程默认「持有但禁用」该特权，不启用直接打开设备会
// 得到 STATUS_UNSUCCESSFUL → 用户态 GLE=31。CE 原版在加载 dbk 前同样会
// enable debug privilege。
static void EnableDebugPrivilege() {
  HANDLE hToken = nullptr;
  if (!::OpenProcessToken(::GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    return;
  TOKEN_PRIVILEGES tp{};
  tp.PrivilegeCount = 1;
  if (::LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ::AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
  }
  ::CloseHandle(hToken);
}

// ---------------------------------------------------------------------------
//  LoadDriver —— SCM 创建/打开内核驱动服务，配置注册表，启动，打开设备
// ---------------------------------------------------------------------------
bool DbvmLoader::LoadDriver(std::string* errOut) {
  if (loaded_) return true;

  // 打开驱动设备前必须启用 SeDebugPrivilege（驱动的 DispatchCreate 校验，
  // 未启用时 CreateFile 返回 GLE=31）
  EnableDebugPrivilege();

  // 1) 驱动文件必须存在（CE 从安装目录复制 dbk64.sys；没有就明确报错）
  if (cfg_.driverPath.empty()) {
    SetError(errOut, "未配置驱动文件路径（dbk64.sys）");
    return false;
  }
  if (!FileExistsW(cfg_.driverPath)) {
    SetError(errOut, "驱动文件不存在: " + WideToAnsi(cfg_.driverPath) +
                     "\n请从 Cheat Engine 安装目录复制 dbk64.sys（内嵌 DBVM offload）到本程序目录");
    return false;
  }

  // 2) 打开 SCM 数据库（需要管理员权限）
  SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
  if (!scm) {
    char buf[160];
    std::snprintf(buf, sizeof(buf), "OpenSCManager 失败 GLE=%lu（加载内核驱动需要管理员权限）",
                  ::GetLastError());
    SetError(errOut, buf);
    return false;
  }

  // 3) 打开已有服务，否则创建；创建后确保二进制路径正确
  SC_HANDLE svc = ::OpenServiceW(scm, cfg_.serviceName.c_str(), SERVICE_ALL_ACCESS);
  if (svc) {
    ::ChangeServiceConfigW(svc, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                           SERVICE_ERROR_NORMAL, cfg_.driverPath.c_str(), nullptr,
                           nullptr, nullptr, nullptr, nullptr,
                           cfg_.serviceName.c_str());
  } else {
    svc = ::CreateServiceW(scm, cfg_.serviceName.c_str(), cfg_.serviceName.c_str(),
                           SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                           SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                           cfg_.driverPath.c_str(), nullptr, nullptr, nullptr,
                           nullptr, nullptr);
  }
  if (!svc) {
    char buf[160];
    std::snprintf(buf, sizeof(buf), "创建/打开驱动服务 %ls 失败 GLE=%lu",
                  cfg_.serviceName.c_str(), ::GetLastError());
    ::CloseServiceHandle(scm);
    SetError(errOut, buf);
    return false;
  }

  // 4) 注册表配置（驱动 DriverEntry 读取，对应 CE 写 A/B/C/D）
  HKEY key = nullptr;
  const std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\" + cfg_.serviceName;
  if (::RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS) {
    const std::wstring a = L"\\Device\\" + cfg_.serviceName;
    const std::wstring b = L"\\DosDevices\\" + cfg_.serviceName;
    const std::wstring c = L"\\BaseNamedObjects\\" + cfg_.processEvent;
    const std::wstring d = L"\\BaseNamedObjects\\" + cfg_.threadEvent;
    ::RegSetValueExW(key, L"A", 0, REG_SZ,
                     reinterpret_cast<const BYTE*>(a.c_str()),
                     static_cast<DWORD>((a.size() + 1) * sizeof(wchar_t)));
    ::RegSetValueExW(key, L"B", 0, REG_SZ,
                     reinterpret_cast<const BYTE*>(b.c_str()),
                     static_cast<DWORD>((b.size() + 1) * sizeof(wchar_t)));
    ::RegSetValueExW(key, L"C", 0, REG_SZ,
                     reinterpret_cast<const BYTE*>(c.c_str()),
                     static_cast<DWORD>((c.size() + 1) * sizeof(wchar_t)));
    ::RegSetValueExW(key, L"D", 0, REG_SZ,
                     reinterpret_cast<const BYTE*>(d.c_str()),
                     static_cast<DWORD>((d.size() + 1) * sizeof(wchar_t)));
    ::RegCloseKey(key);
  }

  // 5) 启动驱动服务
  if (!::StartServiceW(svc, 0, nullptr)) {
    const DWORD le = ::GetLastError();
    ::CloseServiceHandle(svc);
    ::CloseServiceHandle(scm);
    if (le == ERROR_SERVICE_ALREADY_RUNNING) {
      // 已在运行，继续打开设备
    } else if (le == 577 /*ERROR_INVALID_IMAGE_HASH*/) {
      SetError(errOut,
               "驱动签名校验失败（GLE=577）\n需要 F8 禁用驱动签名，或使用已签名的 dbk64.sys");
      return false;
    } else {
      char buf[200];
      std::snprintf(buf, sizeof(buf), "启动驱动服务失败 GLE=%lu\n(1056=已在运行；577=签名问题；$800B010C=被易受攻击驱动拦截)",
                    le);
      SetError(errOut, buf);
      return false;
    }
  }
  ::CloseServiceHandle(svc);
  ::CloseServiceHandle(scm);

  // 6) 打开设备（驱动创建 \??\CEDRIVER73 → \\.\CEDRIVER73）
  hDev_ = ::CreateFileW(cfg_.deviceName.c_str(), GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                        OPEN_EXISTING, 0, nullptr);
  if (hDev_ == INVALID_HANDLE_VALUE) {
    char buf[160];
    std::snprintf(buf, sizeof(buf), "打开驱动设备 %ls 失败 GLE=%lu（驱动可能未正确初始化）",
                  cfg_.deviceName.c_str(), ::GetLastError());
    SetError(errOut, buf);
    return false;
  }

  loaded_ = true;
  return true;
}

// ---------------------------------------------------------------------------
//  Launch —— 触发 DBVM 启动（对应 CE internal_LaunchDBVM）
// ---------------------------------------------------------------------------
bool DbvmLoader::Launch(std::string* errOut) {
  if (!loaded_ || hDev_ == INVALID_HANDLE_VALUE) {
    SetError(errOut, "驱动未加载，请先调用 LoadDriver()");
    return false;
  }
  if (launched_) return true;

  // vmdisk.img 必须存在（DBVM 镜像，dbvm 工程构建产物）
  const std::wstring imgPath =
      cfg_.vmdiskPath.empty() ? ReplaceFilename(cfg_.driverPath, L"vmdisk.img")
                              : cfg_.vmdiskPath;
  if (!FileExistsW(imgPath)) {
    SetError(errOut, "缺少 DBVM 镜像: " + WideToAnsi(imgPath) +
                     "\n请从 Cheat Engine 安装目录复制 vmdisk.img（DBVM 的磁盘镜像）");
    return false;
  }

  // 输入结构与 CE 完全一致：dbvmimgpath 指向「NT 路径串」（\??\C:\...\vmdisk.img）
  //（CE: temp := '\??\'+apppath+'vmdisk.img'; input.dbvmimgpath := qword(@temp[1])）
  const std::wstring ntPath = L"\\??\\" + imgPath;
  struct LaunchInput {
    ULONG64 dbvmimgpath;
    ULONG   cpuid;
  } input{};
  input.dbvmimgpath = reinterpret_cast<ULONG64>(ntPath.c_str());
  input.cpuid = 0xFFFFFFFF;  // 所有 CPU（CE 传 -1）

  DWORD bytesReturned = 0;
  if (!::DeviceIoControl(hDev_, kIoctlCeLaunchDbvm, &input, sizeof(input),
                         nullptr, 0, &bytesReturned, nullptr)) {
    char buf[200];
    std::snprintf(buf, sizeof(buf),
                  "IOCTL_CE_LAUNCHDBVM 失败 GLE=%lu\n设备已打开但驱动拒绝启动 DBVM"
                  "（检查 vmdisk.img 是否有效、CPU 是否支持 VMX/SVM）",
                  ::GetLastError());
    SetError(errOut, buf);
    return false;
  }

  launched_ = true;
  return true;
}

// ---------------------------------------------------------------------------
//  Unload —— 停止并删除驱动服务
// ---------------------------------------------------------------------------
bool DbvmLoader::Unload(std::string* errOut) {
  if (hDev_ != INVALID_HANDLE_VALUE) {
    ::CloseHandle(hDev_);
    hDev_ = INVALID_HANDLE_VALUE;
  }

  SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
  if (scm) {
    SC_HANDLE svc = ::OpenServiceW(scm, cfg_.serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (svc) {
      SERVICE_STATUS st{};
      ::ControlService(svc, SERVICE_CONTROL_STOP, &st);
      ::DeleteService(svc);
      ::CloseServiceHandle(svc);
    }
    ::CloseServiceHandle(scm);
  }

  loaded_ = false;
  launched_ = false;
  SetError(errOut, "");
  return true;
}

}  // namespace ce
