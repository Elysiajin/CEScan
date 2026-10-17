// forcetest.c - 强制附加测试工具
// 用法: forcetest.exe <PID>
// 流程: 驱动内核构造 PROCESS_ALL_ACCESS 句柄 -> NtCreateDebugObject -> NtDebugActiveProcess
#include <windows.h>
#include <stdio.h>

#define IOCTL_TEST_FORCEOPEN  0x222000
#define IOCTL_TEST_GETMASK    0x222004
#define IOCTL_TEST_FORCEATTACH 0x222008

#pragma pack(push, 8)
typedef struct _MY_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PWSTR           ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} MY_OBJECT_ATTRIBUTES;
#pragma pack(pop)

typedef LONG (NTAPI *PFN_NtCreateDebugObject)(PHANDLE, ACCESS_MASK, MY_OBJECT_ATTRIBUTES*, ULONG);
typedef LONG (NTAPI *PFN_NtDebugActiveProcess)(HANDLE, HANDLE);
typedef LONG (NTAPI *PFN_NtRemoveProcessDebug)(HANDLE, HANDLE);
typedef LONG (NTAPI *PFN_NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// 从 ntdll 的 NtDebugActiveProcess 桩读取 SSDT 服务号。
// x64 ntdll 系统调用桩机器码: 4C 8B D1 B8 xx xx xx xx 0F 05 C3
//   (mov r10, rcx; mov eax, <syscall#>; syscall; ret)
static ULONG GetSyscallNumber(PVOID pfn)
{
    UCHAR* p = (UCHAR*)pfn;
    for (int i = 0; i < 16; i++) {
        // 找 "B8 xx xx xx xx" (mov eax, imm32)
        if (p[i] == 0xB8) {
            return *(ULONG*)(p + i + 1);
        }
    }
    return 0;
}

// ObjectBasicInformation: GrantedAccess 在 +4 处
typedef struct _MY_OBJ_BASIC {
    ULONG Attributes;
    ULONG GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
    ULONG Reserved[3];
    ULONG NameInformationLength;
} MY_OBJ_BASIC;

static void PrintGrantedAccess(const char* tag, HANDLE h, PFN_NtQueryObject pQuery)
{
    // OBJECT_BASIC_INFORMATION 实际长度随系统有差异，给大缓冲区，
    // GrantedAccess 固定在 +4（Attributes 之后）
    static UCHAR buf[256] = { 0 };
    ULONG ret = 0;
    LONG st = pQuery ? pQuery(h, 0, buf, sizeof(buf), &ret) : 0xC0000001;
    if (st >= 0)
        printf("[*] %s GrantedAccess = 0x%08X\n", tag, *(ULONG*)(buf + 4));
    else
        printf("[*] %s GrantedAccess = <query failed: 0x%08lX>\n", tag, st);
}

int main(int argc, char** argv)
{
    SetConsoleOutputCP(65001);	// 控制台切 UTF-8，避免中文乱码

    DWORD pid = 0;
    if (argc < 2) {
        printf("usage: forcetest.exe <pid>\n");
        printf("input pid: ");
        if (scanf("%lu", &pid) != 1) { printf("[-] invalid pid\n"); getchar(); getchar(); return 1; }
    } else {
        pid = (DWORD)strtoul(argv[1], NULL, 0);
    }

    // 1. 打开驱动设备
    HANDLE hDev = CreateFileA("\\\\.\\JfDebug", GENERIC_READ | GENERIC_WRITE,
                              0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDev == INVALID_HANDLE_VALUE) {
        printf("[-] 打开设备失败, GLE=%lu (驱动加载了吗? 需管理员运行)\n", GetLastError());
        getchar(); getchar();
        return 1;
    }

    // 2. 内核强制打开目标进程, 拿全权限句柄
    HANDLE hProc = NULL;
    DWORD  dwRet = 0;
    if (!DeviceIoControl(hDev, IOCTL_TEST_FORCEOPEN, &pid, sizeof(pid),
                         &hProc, sizeof(hProc), &dwRet, NULL)) {
        printf("[-] DeviceIoControl 失败, GLE=%lu\n", GetLastError());
        getchar(); getchar();
        CloseHandle(hDev);
        return 1;
    }
    if (!hProc) {
        printf("[-] 内核构造句柄失败 (看驱动日志)\n");
        getchar(); getchar();
        CloseHandle(hDev);
        return 1;
    }
    // 诊断0: 驱动回读动态定位结果 + 当前 ValidAccessMask (期望 0x001F000F)
    {
        ULONGLONG diag[6] = { 0 };
        if (DeviceIoControl(hDev, IOCTL_TEST_GETMASK, NULL, 0,
                            diag, sizeof(diag), &dwRet, NULL)) {
            printf("[*] 内核基址/大小              = 0x%016llX / 0x%016llX %s\n", diag[4], diag[5],
                   diag[5] ? "" : "(!!! 未获取, 扫描无法进行)");
            printf("[*] 驱动定位 OBJECT_TYPE      = 0x%016llX %s\n", diag[2], diag[2] ? "" : "(!!! 未找到)");
            printf("[*] 驱动定位 ValidAccessMask  = 0x%016llX %s\n", diag[3], diag[3] ? "" : "(!!! 未找到)");
            if (diag[1])
                printf("[*] 当前 ValidAccessMask 值   = 0x%08llX %s\n", diag[0],
                       diag[0] == 0x1F000F ? "(已恢复)" : "(!!! 被削状态，恢复定时器应马上改回)");
            else
                printf("[*] 当前 ValidAccessMask 值   = <无效地址>\n");
        } else {
            printf("[*] GETMASK 查询失败 GLE=%lu (驱动版本旧?)\n", GetLastError());
        }
    }

    printf("[+] PID:%lu 全权限句柄 = 0x%p\n", pid, hProc);

    // 获取 ntdll 导出函数（提前，后续 FORCEATTACH 与用户态对照都要用）
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PFN_NtCreateDebugObject    pCreate = (PFN_NtCreateDebugObject)GetProcAddress(hNtdll, "NtCreateDebugObject");
    PFN_NtDebugActiveProcess   pActive = (PFN_NtDebugActiveProcess)GetProcAddress(hNtdll, "NtDebugActiveProcess");
    PFN_NtRemoveProcessDebug   pRemove = (PFN_NtRemoveProcessDebug)GetProcAddress(hNtdll, "NtRemoveProcessDebug");
    PFN_NtQueryObject          pQuery  = (PFN_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
    if (!pCreate || !pActive || !pRemove || !pQuery) {
        printf("[-] ntdll 导出缺失\n");
        getchar(); getchar();
        CloseHandle(hDev);
        return 1;
    }

    // ---- 内核态强制附加 (IOCTL_TEST_FORCEATTACH) ----
    // 通过 SSDT 解析 NtDebugActiveProcess，以内核态直接附加，绕开
    // 反作弊进程(DNF/ACE)的 ObCallback 对用户态句柄引用的权限剥离。
    {
        // 先创建调试对象（内核态附加需要调试对象句柄）
        MY_OBJECT_ATTRIBUTES oa = { sizeof(MY_OBJECT_ATTRIBUTES) };
        HANDLE hDbg = NULL;
        LONG stCreate = pCreate(&hDbg, 0x1F000F, &oa, 0);
        printf("[*] NtCreateDebugObject = 0x%08lX, 对象 = 0x%p\n", stCreate, hDbg);
        if (stCreate < 0) {
            printf("[-] 创建调试对象失败\n");
            getchar(); getchar();
            CloseHandle(hProc);
            CloseHandle(hDev);
            return 1;
        }

        // 读 NtDebugActiveProcess 的 syscall 号
        ULONG syscallNum = GetSyscallNumber((PVOID)pActive);
        printf("[*] NtDebugActiveProcess syscall 号 = 0x%lX (%lu)\n", syscallNum, syscallNum);

        // 构造 FORCEATTACH 输入: { pid, syscallNum, hProcess, hDebug }
        ULONGLONG faIn[4] = { 0 };
        faIn[0] = pid;
        faIn[1] = syscallNum;
        faIn[2] = (ULONGLONG)(ULONG_PTR)hProc;
        faIn[3] = (ULONGLONG)(ULONG_PTR)hDbg;
        ULONGLONG faOut[2] = { 0 };
        DWORD dwFA = 0;

        if (DeviceIoControl(hDev, IOCTL_TEST_FORCEATTACH, faIn, sizeof(faIn),
                            faOut, sizeof(faOut), &dwFA, NULL)) {
            LONG stAttach = (LONG)faOut[0];
            printf("[*] 内核态 NtDebugActiveProcess = 0x%08lX\n", stAttach);
            if (stAttach >= 0) {
                printf("[+] 内核态强制附加成功! 调试对象 0x%p 保持打开\n", hDbg);
                printf("    按 Enter 分离并退出...");
                getchar(); getchar();
                pRemove(hProc, hDbg);
                printf("[*] 已分离\n");
                getchar();
                CloseHandle(hDbg);
                CloseHandle(hProc);
                CloseHandle(hDev);
                return 0;
            } else if (stAttach == 0xC00000B0) {
                printf("[-] STATUS_PORT_ALREADY_SET: 目标已被其他调试器附加\n");
            } else if (stAttach == 0xC0000022) {
                printf("[-] STATUS_ACCESS_DENIED: 内核态附加仍被拒(可能 PPL 保护或服务号错误)\n");
            } else if (stAttach == 0xC000000D) {
                printf("[-] STATUS_INVALID_PARAMETER: 服务号无效或 SSDT 定位失败\n");
            } else if (stAttach == 0xC0000002) {
                printf("[-] STATUS_NOT_IMPLEMENTED: SSDT 定位失败\n");
            } else {
                printf("[-] 内核态附加失败, 状态码见上\n");
            }
        } else {
            printf("[-] FORCEATTACH IOCTL 失败 GLE=%lu\n", GetLastError());
        }
        CloseHandle(hDbg);
    }

    // 3. 手动走调试附加流程（作为对照，验证用户态路径仍被拒）
    // 诊断1: 确认内核句柄权限是否完整 (期望 0x001FFFFF = PROCESS_ALL_ACCESS)
    PrintGrantedAccess("ProcessHandle", hProc, pQuery);

    MY_OBJECT_ATTRIBUTES oa = { sizeof(MY_OBJECT_ATTRIBUTES) };
    HANDLE hDbg = NULL;
    LONG st = pCreate(&hDbg, 0x1F000F, &oa, 0);
    printf("[*] NtCreateDebugObject = 0x%08lX, 对象 = 0x%p\n", st, hDbg);
    if (st < 0) { getchar(); getchar(); CloseHandle(hDev); return 1; }

    // 诊断2: 调试对象实际拿到的权限 (期望 0x001F000F)
    // 若低位缺少 0x0000000F (READ|WRITE|OPERATION)，说明 DbgkDebugObjectType 的
    // ValidAccessMask 仍是"被削"状态，驱动的恢复没生效
    PrintGrantedAccess("DebugObject", hDbg, pQuery);

    st = pActive(hProc, hDbg);
    printf("[*] NtDebugActiveProcess = 0x%08lX\n", st);

    if (st >= 0) {
        printf("[+] 强制附加成功! 调试对象 0x%p 保持打开(本进程存活期间有效)\n", hDbg);
        printf("    按 Enter 恢复(分离并退出)...");
        getchar(); getchar();
        pRemove(hProc, hDbg);
        printf("[*] 已分离\n");
        getchar();
    } else {
        if (st == 0xC00000B0)      printf("[-] STATUS_PORT_ALREADY_SET: 目标已被其他调试器附加\n");
        else if (st == 0xC0000022) printf("[-] STATUS_ACCESS_DENIED: 权限仍被拒(看驱动日志确认句柄权限)\n");
        else if (st == 0xC000000B) printf("[-] STATUS_INVALID_CID: 进程已退出或 PID 无效\n");
        else                       printf("[-] 附加失败, 状态码见上\n");
        getchar(); getchar();
    }

    CloseHandle(hProc);
    CloseHandle(hDev);
    return 0;
}
