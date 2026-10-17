#pragma once
// ============================================================================
//  DbvmLoader.h —— DBVM 加载器（用户态，对应 CE 侧 dbk32/DBK32functions.pas）
//
//  CE 在 Windows 上加载 DBVM 的机制（移植结论）：
//    1. dbk 内核驱动（dbk64.sys）内嵌 DBVM offload 代码（DBKKernel/vmxoffload.c
//       + dbvm/vmm 源码）。驱动本身不含 hypervisor，它负责把「DBVM 镜像
//       vmdisk.img」读进物理内存并把 CPU 切进 VMX/SVM root。
//    2. 加载流程 = 纯用户态 SCM 服务加载驱动 → 打开设备 → 发 IOCTL。
//       本类就是这一层的 C++ 移植：
//         LoadDriver()   = 端口 CE 的 LoadDBK32（CreateService/StartService/
//                          注册表 A/B/C/D 配置/CreateFile 设备）
//         Launch()       = 端口 CE 的 internal_LaunchDBVM（DeviceIoControl
//                          IOCTL_CE_LAUNCHDBVM，参数 { vmdisk.img 的 NT 路径,
//                          cpuid }）
//         Unload()       = 停服务 + 删服务（DeleteService 同时删注册表键）
//    3. 成功后 vmcall/vmmcall 指令才会被 DBVM 捕获 —— 之后才轮到
//       Dbvm 类（include/DBVM.h）的通道与命令封装起作用。
//
//  依赖的外部文件（用户提供，通常从 Cheat Engine 安装目录复制）：
//    · dbk64.sys    —— dbk 内核驱动（内嵌 DBVM offload）
//    · vmdisk.img   —— DBVM 镜像（dbvm 工程构建产物，imagemaker 生成）
//
//  注意：加载内核驱动需要管理员权限，且驱动必须有有效签名（或系统
//  处于测试签名/F8 禁用签名状态）。驱动签名失败时 StartService 返回
//  错误 577（ERROR_INVALID_IMAGE_HASH），这里会给出明确提示。
// ============================================================================
#include <windows.h>

#include <cstdint>
#include <string>

namespace ce {

// IOCTL_CE_LAUNCHDBVM —— 与 CE 的 dbk32/DBK32functions.pas 完全一致：
//   (FILE_DEVICE_UNKNOWN(0x22) << 16) | (FILE_RW_ACCESS(3) << 14)
//   | (0x083A << 2) | METHOD_BUFFERED(0)   →   0x22E0E8
constexpr ULONG kIoctlCeLaunchDbvm = (0x22u << 16) | (3u << 14) | (0x083Au << 2);

class DbvmLoader {
 public:
  // 加载配置（默认值对齐 CE：服务名 CEDRIVER73 / 设备 \\.\CEDRIVER73 / 默认密码）
  struct Config {
    std::wstring driverPath;   // dbk64.sys 完整路径（必填）
    std::wstring vmdiskPath;   // vmdisk.img 完整路径；空 = 与 driverPath 同目录
    std::wstring serviceName;  // 默认 L"CEDRIVER73"
    std::wstring deviceName;   // 默认 L"\\\\.\\CEDRIVER73"
    std::wstring processEvent; // 注册表 C 值（驱动读事件名）
    std::wstring threadEvent;  // 注册表 D 值
    uint64_t p1 = 0x76543210;  // 与 dbvm/vmm/main.c 默认密码一致
    uint32_t p2 = 0xfedcba98;
    uint64_t p3 = 0x90909090;
  };

  Config& cfg() { return cfg_; }

  // 驱动是否已加载并打开设备
  bool IsDriverLoaded() const { return loaded_; }
  bool IsLaunched() const { return launched_; }

  // SCM 加载内核驱动（服务注册 + 注册表配置 + StartService + CreateFile）。
  // 已加载时幂等返回 true。失败时 errOut 写入中文原因。
  bool LoadDriver(std::string* errOut = nullptr);

  // 触发 DBVM 启动：DeviceIoControl(IOCTL_CE_LAUNCHDBVM)。
  // 成功后建议调用 ce::Dbvm::Instance().ChangePassword(p1, p2, p3)
  // 以对齐密码（对应 CE 的 configure_vmx）。
  bool Launch(std::string* errOut = nullptr);

  // 停驱动服务并删除服务（DeleteService 会一并删掉注册表键）。
  bool Unload(std::string* errOut = nullptr);

  // 底层设备句柄（Launch 前拿到，便于扩展直接发其他 IOCTL）
  HANDLE Device() const { return hDev_; }

  DbvmLoader() {
    cfg_.serviceName = L"CEDRIVER73";
    cfg_.deviceName = L"\\\\.\\CEDRIVER73";
    cfg_.processEvent = L"DBKProcList60";
    cfg_.threadEvent = L"DBKThreadList60";
  }

 private:
  Config cfg_;
  HANDLE hDev_ = INVALID_HANDLE_VALUE;
  bool loaded_ = false;
  bool launched_ = false;

  std::string ResolveVmdiskPath() const;
  void SetError(std::string* errOut, const std::string& msg) const;
};

}  // namespace ce
