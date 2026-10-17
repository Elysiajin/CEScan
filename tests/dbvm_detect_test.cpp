//=============================================================================
//  dbvm_detect_test.cpp —— DBVM 功能检测自测程序
//
//  验证目标：
//    1. CPUID 厂商识别（Intel / AMD）
//    2. CPU 是否支持 vmcall/vmmcall（VMX / SVM 标志）
//    3. DBVM 通道 Detect()：GETVERSION vmcall，不在场时应安全地触发 #UD
//       并被 SEH 接住（不崩溃），返回 false + LastError 说明
//
//  注意：本程序不要求 DBVM 真的在跑 —— 本机没加载 hypervisor 时，
//  vmcall 指令会触发 #UD（EXCEPTION_ILLEGAL_INSTRUCTION），这正是
//  DBVM.cpp 里 __try/__except 捕获的路径，等价 CE 的 vmcallexceptiontest。
//=============================================================================
#include "DBVM.h"

#include <windows.h>
#include <intrin.h>

#include <cstdio>
#include <cstring>
#include <cstdint>

namespace {

void CpuId(uint32_t leaf, uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
  int regs[4] = {0, 0, 0, 0};
  __cpuidex(regs, static_cast<int>(leaf), 0);
  *a = static_cast<uint32_t>(regs[0]);
  *b = static_cast<uint32_t>(regs[1]);
  *c = static_cast<uint32_t>(regs[2]);
  *d = static_cast<uint32_t>(regs[3]);
}

}  // namespace

int main() {
  printf("==== DBVM 功能检测测试 ====\n");

  uint32_t a = 0, b = 0, c = 0, d = 0;
  CpuId(0, &a, &b, &c, &d);
  char vendor[13];
  std::memcpy(vendor, &b, 4);
  std::memcpy(vendor + 4, &d, 4);
  std::memcpy(vendor + 8, &c, 4);
  vendor[12] = '\0';
  printf("[CPU] vendor              = %s\n", vendor);

  CpuId(1, &a, &b, &c, &d);
  printf("[CPU] CPUID.1:ECX.VMX[5]  = %u\n", (c >> 5) & 1u);
  CpuId(0x80000001, &a, &b, &c, &d);
  printf("[CPU] CPUID.80000001:ECX.SVM[2] = %u\n", (c >> 2) & 1u);

  const bool vmcall = ce::Dbvm::CpuSupportsVmcall();
  printf("[CPU] CpuSupportsVmcall() = %s\n", vmcall ? "YES" : "NO");
  printf("[CPU] DbvmCapable()       = %s\n", ce::DbvmCapable() ? "YES" : "NO");

  ce::Dbvm& dbvm = ce::Dbvm::Instance();
  const bool detected = dbvm.Detect();
  printf("[DBVM] Detect()           = %s\n", detected ? "YES" : "NO");
  if (detected) {
    printf("[DBVM] Version            = 0x%08X\n", dbvm.Version());
    printf("[DBVM] Available()        = %s\n", dbvm.Available() ? "YES" : "NO");
  } else {
    printf("[DBVM] Version            = 0 (不在场)\n");
  }
  printf("[DBVM] LastError          = %s\n", dbvm.LastError().c_str());

  // 期望结论（本机通常无 DBVM）：CPU 支持 vmcall（YES），DBVM 不在场（NO），
  // 全程无崩溃 —— 说明 SEH 捕获 #UD 的路径工作正常。
  printf("==== TEST_DONE ====\n");
  return detected ? 0 : 2;
}
