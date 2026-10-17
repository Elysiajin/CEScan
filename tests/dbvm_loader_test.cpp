// ============================================================================
//  dbvm_loader_test.cpp —— DBVM 加载器自测
//
//  本机没有 dbk64.sys / vmdisk.img（它们是 CE 的驱动产物，用户自备），
//  所以这里验证的是「加载器的正确性与失败分支」：
//    1. IOCTL_CE_LAUNCHDBVM 常量 = 0x22E0E8（与 CE 逐位一致）
//    2. 驱动文件缺失 → LoadDriver 返回 false + 明确中文错误
//    3. 未加载就 Launch → 明确错误
//    4. Unload 幂等
//  若把 dbk64.sys 和 vmdisk.img 放到程序目录（以管理员 + 可签名环境运行），
//  同一套代码会走真实加载路径 —— 本测试不会真的加载驱动。
// ============================================================================
#include "DbvmLoader.h"

#include <cstdio>
#include <string>

int main() {
  printf("==== DBVM 加载器测试 ====\n");

  printf("[常量] IOCTL_CE_LAUNCHDBVM = 0x%08X (期望 0x22E0E8)\n",
         static_cast<unsigned>(ce::kIoctlCeLaunchDbvm));
  if (ce::kIoctlCeLaunchDbvm != 0x22E0E8u) {
    printf("[常量] MISMATCH!\n");
    return 1;
  }
  printf("[常量] OK\n");

  ce::DbvmLoader loader;
  std::string err;

  // 1) 驱动文件缺失
  loader.cfg().driverPath = L"Z:\\nonexist\\dbk64.sys";
  bool ok = loader.LoadDriver(&err);
  printf("[1] LoadDriver(缺文件)   = %s\n", ok ? "OK(不应)" : "FAIL(预期)");
  printf("    err = %s\n", err.c_str());
  if (ok) return 1;

  // 2) 未加载就 Launch
  err.clear();
  ok = loader.Launch(&err);
  printf("[2] Launch(未加载)       = %s\n", ok ? "OK(不应)" : "FAIL(预期)");
  printf("    err = %s\n", err.c_str());
  if (ok) return 1;

  // 3) 空配置加载
  err.clear();
  ce::DbvmLoader loader2;
  ok = loader2.LoadDriver(&err);
  printf("[3] LoadDriver(空配置)   = %s\n", ok ? "OK(不应)" : "FAIL(预期)");
  printf("    err = %s\n", err.c_str());
  if (ok) return 1;

  // 4) Unload 幂等
  err.clear();
  ok = loader2.Unload(&err);
  printf("[4] Unload(未加载)       = %s\n", ok ? "OK" : "FAIL");
  if (!ok) return 1;

  // 5) 驱动文件存在但未加载过 → 到这里若驱动目录真放了文件会尝试加载；
  //    正常测试环境下这里不应被执行到（上面缺文件分支已覆盖）。
  printf("==== TEST_DONE ====\n");
  return 0;
}
