#include <ntddk.h>


// 查找内核模块
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;



typedef struct _OB_CALLBACK
{
	LIST_ENTRY	ListEntry;
	ULONG64		Unknown;
	ULONG64		ObHandle;
	ULONG64		ObjTypeAddr;
	ULONG64		PreCall;
	ULONG64		PostCall;
} OB_CALLBACK, *POB_CALLBACK;
//////////////////////////////////////////////////////////////////////////
// 函数声明
//////////////////////////////////////////////////////////////////////////
void DriverUnload(
	PDRIVER_OBJECT pDriverObject
	);

VOID TimerRoutine(
	_In_      struct _KDPC *Dpc,
	_In_opt_  PVOID DeferredContext,
	_In_opt_  PVOID SystemArgument1,
	_In_opt_  PVOID SystemArgument2
	);

PLDR_DATA_TABLE_ENTRY SearchDriver(PDRIVER_OBJECT pDriverObject, wchar_t *strDriverName);



ULONG_PTR GetDbgkDebugobjectAddr();


NTKERNELAPI CHAR* PsGetProcessImageFileName(PEPROCESS Process);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(HANDLE Id, PETHREAD *Thread);
NTKERNELAPI PEPROCESS IoThreadToProcess(PETHREAD Thread);
NTKERNELAPI PVOID PsGetProcessDebugPort(PEPROCESS Process);

// 内核内强制附加兜底：同步恢复 ValidAccessMask + 构造全权限句柄
NTSTATUS KernelForceAttach(ULONG ulPid);

// 绕过 PPL：清零目标进程 EPROCESS 的 Protection / SignatureLevel /
// SectionSignatureLevel 字段（Win10 1909=18363 偏移为 0x6fa/0x6f8/0x6f9，
// 由 NtBuildNumber 动态决定），使 PPL 不再裁剪 PROCESS_SET_PORT 等权限位，
// 从而 NtDebugActiveProcess 内部的 ObReferenceObjectByHandle 能拿到完整权限。
VOID DisableProcessProtection(PEPROCESS pProcess);

//////////////////////////////////////////////////////////////////////////
// SSDT 解析 —— 内核态直接调用 NtDebugActiveProcess（绕开 ObCallback）
//////////////////////////////////////////////////////////////////////////

// KeServiceDescriptorTable 结构（Win10 x64 未导出，需特征码定位）
//   [0] ServiceTableBase  = KiServiceTable 地址（服务表，4字节偏移数组）
//   [1] ServiceCounterTableBase = 0（x64 未用）
//   [2] NumberOfServices  = 服务总数
//   [3] ParamTableBase    = KiArgumentTable 地址
typedef struct _SERVICE_DESCRIPTOR_TABLE {
	ULONG_PTR  ServiceTableBase;
	ULONG_PTR  ServiceCounterTableBase;
	ULONGLONG  NumberOfServices;
	ULONG_PTR  ParamTableBase;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

// 定位 KiServiceTable（服务函数表基址），失败返回 0
// 注意：x64 的 SSDT 表项是 4 字节相对偏移（offset<<4 | argInfo），
//       真实函数地址 = KiServiceTable + (entry >> 4)
ULONG_PTR FindSSDTServiceTableBase(VOID);

// 通过 SSDT 以 KernelMode 调用 NtDebugActiveProcess(ProcessHandle, DebugObjectHandle)
//  syscallNum: NtDebugActiveProcess 的 SSDT 服务号（由用户态从 ntdll 桩读取传入）
//  返回:     NtDebugActiveProcess 的 NTSTATUS（>=0 表示附加成功）
NTSTATUS SsdtDebugActiveProcess(ULONG ulSyscallNum, HANDLE hProcess, HANDLE hDebugObject);

// 读取 MSR（0xC0000082 = IA32_LSTAR）
ULONG64 ReadMsrLstar(VOID);
//////////////////////////////////////////////////////////////////////////


VOID SetDPCTimerByDbgAccess();				// 此DPC计时器用来500ms恢复一次全局调试对象权限

VOID SetDPCTimerByNotifys();				// 此DPC计时器用来检查以及恢复TP设置的一些回调和OBJ HOOK

VOID SetDPCTimerByFxxkThread();				// 此DPC计时器用来干掉TP关键线程

ULONG64 FindPspCreateProcessNotifyRoutine();
void FuckTPProcessNotify();

ULONG64 FindPspCreateThreadNotifyRoutine();
void FuckTPThreadNotify();

ULONG64 FindPspLoadImageNotifyRoutine();
void FuckTPLoadImageNotify();


BOOLEAN GetVersionAndHardCode();
ULONG FuckTPObCallbacks();

PEPROCESS FindGameProcess();
PEPROCESS LookupProcess(HANDLE Pid);
PETHREAD LookupThread(HANDLE Tid);
VOID EnumThread(PEPROCESS Process);



typedef NTSTATUS(__fastcall *PSPTERMINATETHREADBYPOINTER)
(
IN PETHREAD Thread,
IN NTSTATUS ExitStatus,
IN BOOLEAN DirectTerminate
);

typedef unsigned char       BYTE;

ULONG64 Get64bitValue(PVOID p);
ULONG32 Get32bitValue(PVOID p);
VOID Set64bitValue(PVOID p, ULONG64 v);
VOID Set32bitValue(PVOID p, ULONG32 v);
PVOID GetFunctionAddr(PCWSTR FunctionName);
VOID InitKillThread();
//////////////////////////////////////////////////////////////////////////