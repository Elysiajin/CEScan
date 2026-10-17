#include <ntddk.h>
#include <intrin.h>
#include "main.h"
#include "commonfunc.h"

//////////////////////////////////////////////////////////////////////////
// 相关全局变量

ULONG_PTR ul_TPBaseAddr = 0;
ULONG_PTR ul_TPSize = 0;

ULONG_PTR ul_KernelBase = 0; // 内核基址
ULONG_PTR ul_KernelSize = 0; // 内核映像大小（用于动态扫描）

ULONG_PTR ul_ValidAccessMask_Addr = 0; // 调试对象权限地址
ULONG_PTR ul_DebugObjectType_Addr = 0; // 调试对象地址


KTIMER Timer = { 0 };			// 用于全局调试对象权限的计时器
KDPC myDpc = { 0 };				// 用于全局调试对象权限的计时器


KTIMER Timer2 = { 0 };			// 用于清除回调以及OBJ HOOK的计时器
KDPC myDpc2 = { 0 };			// 用于清除回调以及OBJ HOOK的计时器

KTIMER Timer3 = { 0 };			// 用于清除病毒关键线程的计时器
KDPC myDpc3 = { 0 };			// 用于清除病毒关键线程的计时器

ULONG NtBuildNumber = 0;
ULONG ObjectCallbackListOffset = 0;

PDRIVER_OBJECT pMyDriverObject = NULL;

PSPTERMINATETHREADBYPOINTER PspTerminateThreadByPointer = NULL;

//////////////////////////////////////////////////////////////////////////
// 强制附加：设备与 IOCTL
//////////////////////////////////////////////////////////////////////////
#define DEVICE_NAME		L"\\Device\\JfDebug"
#define SYMLINK_NAME	L"\\??\\JfDebug"
// CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x800+, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TEST_FORCEOPEN	0x222000	// 内核构造目标进程全权限句柄并复制给调用者
#define IOCTL_TEST_GETMASK		0x222004	// 回读当前 DbgkDebugObjectType.ValidAccessMask 值
#define IOCTL_TEST_FORCEATTACH	0x222008	// 内核内一次性完成 构造句柄+创建调试对象+ZwDebugActiveProcess 附加

PDEVICE_OBJECT g_pDevObj = NULL;

// ValidAccessMask 的可写别名映射（DriverEntry 建立，DPC 直接写它，避免清 CR0）
PULONG g_pMaskWriteAddr = NULL;
PMDL   g_pMaskMdl = NULL;
//////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////
// 以下全是win7 64 硬编码 相对于内核基址
// 虚拟机：DbgkDebugObjectType 0x45de1c   本机：DbgkDebugObjectType 0x45a5fc
ULONG_PTR ul_DebugObjectType_offset = 0x45a5fc;

// NtCreateDebugObject 相对于内核基址的偏移
// 虚拟机：0x45dda0   本机：0x45a580 （GetDbgkDebugobjectAddr 实际使用此变量）
ULONG_PTR ul_NtCreateDebugObject_offset = 0x45a580;

// ETHREAD.Win32StartAddress 偏移
// 虚拟机：0x410   本机：0x418 （EnumThread 实际使用此变量）
ULONG_PTR ul_Win32StartAddress_offset = 0x418;

// ValidAccessMask +0x040+0x01c
ULONG_PTR ul_ValidAccessMask_offset = 0x5c;

/********************************************************************/
/*	函数名: 	获取 ntoskrnl 基址与大小（不依赖加载模块链表）
/*	原理:   取本驱动导入表中任一 ntoskrnl 例程的真实地址，
/*			按页向下翻找 MZ/PE 头得基址，再从 OptionalHeader 取 SizeOfImage
/*	返回:   成功 TRUE
/*********************************************************************/
BOOLEAN GetNtosBaseAndSize(PULONG_PTR pOutBase, PULONG_PTR pOutSize)
{
	ULONG_PTR p;
	ULONG_PTR ulBase = 0;
	ULONG ulNtOffs = 0;
	ULONG ulSize = 0;
	ULONG_PTR pStart;

	// 引用任意 ntoskrnl 导入函数 -> 其真实地址必在 ntoskrnl 内
	pStart = (ULONG_PTR)MmIsAddressValid;
	pStart &= ~0xFFFULL;				// 页对齐

	// 从函数所在页向上限 64MB 向下翻找 PE 头
	// （用裸偏移: e_magic@0, e_lfanew@0x3c, PE签名@e_lfanew,
	//   OptionalHeader@e_lfanew+0x18, SizeOfImage@+0x38）
	for (p = pStart; p > 0xFFFF800000000000ULL; p -= 0x1000)
	{
		if ((pStart - p) > 0x4000000ULL)	// 最多回退 64MB
			break;

		if (!MmIsAddressValid((PVOID)p) || !MmIsAddressValid((PVOID)(p + 0x3F)))
			continue;
		if (*(PUSHORT)p != 0x5A4D)		// 'MZ'
			continue;

		ulNtOffs = *(PULONG)(p + 0x3c);
		if (ulNtOffs < 0x40 || ulNtOffs > 0x1000)
			continue;
		if (!MmIsAddressValid((PVOID)(p + ulNtOffs)) ||
			!MmIsAddressValid((PVOID)(p + ulNtOffs + 0x58)))
			continue;
		if (*(PULONG)(p + ulNtOffs) != 0x00004550)	// 'PE\0\0'
			continue;

		ulSize = *(PULONG)(p + ulNtOffs + 0x18 + 0x38);	// PE32+ SizeOfImage
		if (ulSize < 0x100000 || ulSize > 0x8000000)	// 合理性：1MB~128MB
			continue;

		ulBase = p;
		break;
	}

	if (ulBase == 0 || ulSize == 0)
		return FALSE;

	*pOutBase = ulBase;
	*pOutSize = (ULONG_PTR)ulSize;
	return TRUE;
}


/********************************************************************/
/*	函数名: 	动态查找 DbgkDebugObjectType
/*	原理:   扫描 ntoskrnl 映像内的全局指针，验证其指向的
/*			OBJECT_TYPE.Name（+0x10）是否为 L"Debug"(Win7)
/*			或 L"DebugObject"(Win10/11)
/*	返回:   OBJECT_TYPE 本体地址，失败返回 0
/*********************************************************************/
ULONG_PTR FindDbgkDebugObjectType()
{
	ULONG_PTR pScan;
	ULONG_PTR pEnd;
	ULONG_PTR v;
	PWSTR pszName;
	USHORT usNameLen;
	ULONG ulCount = 0;

	if (ul_KernelBase == 0 || ul_KernelSize == 0)
		return 0;

	pEnd = (ul_KernelBase + ul_KernelSize) - 8;

	// 逐 8 字节扫描映像内的全局指针
	for (pScan = ul_KernelBase; pScan < pEnd; pScan += 8)
	{
		// 映像本身在非分页内存，但仍逐段验址，防止 pEnd 推算异常
		if (!MmIsAddressValid((PVOID)pScan) || !MmIsAddressValid((PVOID)(pScan + 7)))
			continue;

		v = *(PULONG_PTR)pScan;

		// 粗筛：必须是内核系统空间指针(Win7 池在 FFFFF8xx，Win10/11 池在 FFFFB0xx~D0xx，
		// 统一用 0xFFFF800000000000 作为内核空间下限)，且不指向映像自身
		if (v < 0xFFFF800000000000ULL || (v >= ul_KernelBase && v < ul_KernelBase + ul_KernelSize))
			continue;

		// 必须 8 字节对齐的池对象
		if (v & 7)
			continue;

		ulCount++;

		if (!MmIsAddressValid((PVOID)v))
			continue;

		// OBJECT_TYPE.Name 位于 +0x10（Vista~Win10/11 布局稳定）：UNICODE_STRING
		// { USHORT Length; USHORT MaximumLength; PWSTR Buffer; }
		// 【必须逐个字段验址】MmIsAddressValid 只保证它被调用的那个字节可读，
		// 不覆盖后续字节/跨页情况，直接读 +0x10 会 0x50 蓝屏
		if (!MmIsAddressValid((PVOID)(v + 0x10)) || !MmIsAddressValid((PVOID)(v + 0x1F)))
			continue;

		// 调试对象类型名：Win7 为 L"Debug"(5字符=10字节)，
		// Win10/11 为 L"DebugObject"(11字符=22字节) —— 两种都要认！
		usNameLen = *(PUSHORT)(v + 0x10);
		if (usNameLen != 10 && usNameLen != 22)
			continue;

		if (!MmIsAddressValid((PVOID)(v + 0x18)) || !MmIsAddressValid((PVOID)(v + 0x1F)))
			continue;

		pszName = *(PWSTR *)(v + 0x18);
		if (!MmIsAddressValid((PVOID)pszName))
			continue;

		// 字符串读取同样要逐字符验址，避免 Buffer 尾部跨页
		if (!MmIsAddressValid((PVOID)((ULONG_PTR)pszName + usNameLen + 1)))
			continue;

		// 前 5 个字符必须是 "Debug"，且结尾形态匹配（"Debug\0" 或 "DebugO..."）
		if (pszName[0] == L'D' && pszName[1] == L'e' && pszName[2] == L'b' &&
			pszName[3] == L'u' && pszName[4] == L'g' &&
			(pszName[5] == L'\0' || pszName[5] == L'O'))
		{
			// 额外校验：TypeInfo.Length（OBJECT_TYPE+0x40，USHORT）应在合理范围，
			// 排除"字符串恰好叫 Debug"的假命中
			if (MmIsAddressValid((PVOID)(v + 0x40)) && MmIsAddressValid((PVOID)(v + 0x41)))
			{
				USHORT usInitLen = *(PUSHORT)(v + 0x40);
				if (usInitLen < 0x10 || usInitLen > 0x200)
					continue;
			}

			DbgPrint("[动态定位] 扫描指针数:%lu 命中 OBJECT_TYPE:%p 名字节数:%u\n",
				ulCount, v, usNameLen);
			return (ULONG_PTR)v;
		}
	}

	DbgPrint("[动态定位] 扫描指针数:%lu 未命中 Debug/DebugObject\n", ulCount);
	return 0;
}


/********************************************************************/
/*	函数名: 	在 OBJECT_TYPE 内定位 ValidAccessMask 的地址
/*	原理:   Debug 类型的 ValidAccessMask 在 Win7 上固定为 0x1F000F，
/*			在结构前 0x100 字节内按值搜索，无需硬编码结构体偏移
/*	返回:   ValidAccessMask 的地址，失败返回 0
/*********************************************************************/
	ULONG_PTR FindValidAccessMaskAddr(ULONG_PTR pType)
{
	ULONG ulOff;
	ULONG_PTR ulAddr;

	if (pType == 0 || !MmIsAddressValid((PVOID)pType))
		return 0;

	// 方案1：按值 0x1F000F 搜索（mask 尚未被削的干净系统上最可靠）
	for (ulOff = 0x30; ulOff < 0x100; ulOff += 4)
	{
		if (MmIsAddressValid((PVOID)(pType + ulOff)) &&
			*(PULONG)(pType + ulOff) == 0x1F000F)
		{
			return pType + ulOff;
		}
	}

	// 方案2：mask 已被反调试改掉时按值搜不到——回退到结构偏移
	// Win7 x64/Win10 x64: OBJECT_TYPE.TypeInfo 在 +0x40，ValidAccessMask 在 TypeInfo+0x1c，
	// 即 OBJECT_TYPE+0x5c（与原版硬编码一致，Vista~Win10 布局稳定）
	ulAddr = pType + 0x5c;
	if (MmIsAddressValid((PVOID)(pType + 0x40)) &&
		MmIsAddressValid((PVOID)(pType + 0x40 + 1)))
	{
		USHORT usInitLen = *(PUSHORT)(pType + 0x40);	// TypeInfo.Length
		if (usInitLen >= 0x18 && usInitLen <= 0x100 &&
			MmIsAddressValid((PVOID)ulAddr) &&
			MmIsAddressValid((PVOID)(ulAddr + 3)))
		{
			ULONG ulCur = *(PULONG)ulAddr;
			// 值合理性：access mask 低位必须含权限位，且不能是全 0/全 FF
			if ((ulCur & 0x0000000F) != 0 && ulCur != 0xFFFFFFFF)
			{
				DbgPrint("[动态定位] 按值搜索失败，回退结构偏移+0x5c，当前值:%08x\n", ulCur);
				return ulAddr;
			}
			DbgPrint("[动态定位] +0x5c 处值异常(%08x)，放弃\n", ulCur);
		}
	}

	return 0;
}


/********************************************************************/
/*	函数名: 	IRP 分发 - CREATE / CLOSE
/*********************************************************************/
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


/********************************************************************/
/*	函数名: 	KernelForceAttach
/*	功能:   "权限被拒时强行完成附加"的内核兜底。
/*			Hook 掉 Dbgk 权限校验的源头 —— DbgkDebugObjectType 的
/*			ValidAccessMask（这正是 NtDebugActiveProcess 返回
/*			STATUS_ACCESS_DENIED 的根本原因）：
/*			1) 【同步】把 ValidAccessMask 强制恢复为 0x1F000F（不等
/*			   500ms 的 DPC，消除"mask 在两次 DPC 间被削"的竞态窗口）
/*			2) 校验目标进程存在
/*			—— 至此用户态 NtDebugActiveProcess 必然通过权限校验。
/*	说明:   内核态驱动【无法】直接调用 NtDebugActiveProcess /
/*			NtCreateDebugObject（二者是 ntdll 的 SSDT 系统调用桩，
/*			ntoskrnl 并不导出，Win10 上 SSDT 也受 PatchGuard 保护），
/*			所以"附加"这一动作仍由用户态发起；驱动负责把"权限"这
/*			道闸门彻底打开（本 IOCTL 即事件驱动的即时恢复，配合
/*			DriverEntry 里 500ms 周期的 DPC 持续恢复双保险）。
/*	返回:   STATUS_SUCCESS 表示权限闸门已全开；否则为目标进程无效
/*********************************************************************/
NTSTATUS KernelForceAttach(ULONG ulPid)
{
	NTSTATUS state;
	PEPROCESS pProcess = NULL;

	// 0) 【同步】强制恢复 Debug 对象 ValidAccessMask，立即消除权限拒绝根因。
	//    优先写 MDL 可写别名（无需清 CR0，PatchGuard 安全），
	//    否则退回直接写原始地址（该地址已在 DriverEntry 严格校验过）。
	if (g_pMaskWriteAddr)
	{
		*g_pMaskWriteAddr = 0x1F000F;
		DbgPrint("[强制附加] 同步恢复 ValidAccessMask=0x1F000F (别名:%p)\n", g_pMaskWriteAddr);
	}
	else if (ul_ValidAccessMask_Addr && MmIsAddressValid((PVOID)ul_ValidAccessMask_Addr))
	{
		*(PULONG)ul_ValidAccessMask_Addr = 0x1F000F;
		DbgPrint("[强制附加] 同步恢复 ValidAccessMask=0x1F000F (原始:%p)\n",
			(PVOID)ul_ValidAccessMask_Addr);
	}
	else
	{
		DbgPrint("[强制附加] 警告: 无可用 mask 写入口(动态定位失败?)\n");
	}

	// 1) 校验目标进程存在，并绕过其 PPL 保护
	state = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ulPid, &pProcess);
	if (!NT_SUCCESS(state))
	{
		DbgPrint("[强制附加] FORCEATTACH 找不到进程 PID:%lu, status:%08x\n", ulPid, state);
		return state;
	}

	// 2) 清零 Protection/SignatureLevel/SectionSignatureLevel，解除 PPL 保护。
	//    这一步必须在内核重新构造句柄之前完成，否则 PPL 会裁剪 PROCESS_SET_PORT
	//    等位（NtDebugActiveProcess 内部 ObReferenceObjectByHandle 需要它）。
	DisableProcessProtection(pProcess);
	ObDereferenceObject(pProcess);

	DbgPrint("[强制附加] FORCEATTACH 权限闸门已全开(含 PPL 绕过): PID:%lu\n", ulPid);
	return STATUS_SUCCESS;
}


/********************************************************************/
/*	函数名: 	DisableProcessProtection
/*	功能:   绕过 PPL（Protected Process Light）保护。DNF.exe 等腾讯
/*			ACE 反作弊进程以 PPL 运行，其 EPROCESS 的 Protection 字段
/*			非零时，内核 Psp 保护机制会在 ObOpenObjectByPointer /
/*			ObReferenceObjectByHandle 里裁剪 PROCESS_SET_PORT、
/*			PROCESS_SUSPEND_RESUME 等敏感权限位，导致内核态
/*			NtDebugActiveProcess 内部 ObReferenceObjectByHandle 失败、
/*			返回 STATUS_ACCESS_DENIED。
/*			—— 本函数直接清零 Protection + SignatureLevel +
/*			SectionSignatureLevel，解除 PPL，使后续句柄构造能拿到
/*			完整权限。偏移按 NtBuildNumber 动态决定：
/*			  18362/18363(1909/19H2): Protection=0x6fa, SigLevel=0x6f8, SecSig=0x6f9
/*			  19041+(20H1 及更新)   : Protection=0x87a, SigLevel=0x878, SecSig=0x879
/*			  17763(1809)           : Protection=0x6ca, SigLevel=0x6c8, SecSig=0x6c9
/*			  17134/16299/15063     : Protection=0x6ca, SigLevel=0x6c8, SecSig=0x6c9
/*	说明:   仅清零 Protection 一个字节即可让 PPL 失效；SignatureLevel /
/*			SectionSignatureLevel 一并清零更彻底（有些保护会检测这两者）。
/*********************************************************************/
VOID DisableProcessProtection(PEPROCESS pProcess)
{
	ULONG offProtection = 0;
	ULONG offSigLevel = 0;
	ULONG offSecSigLevel = 0;
	UCHAR ucOldProt = 0;
	UCHAR ucOldSig = 0;

	if (!pProcess)
		return;

	// 按 build 号确定偏移（参考 vergilius / eprocess_offsets 权威数据）
	switch (NtBuildNumber)
	{
	case 10240: offProtection = 0x6aa; offSigLevel = 0x6a8; offSecSigLevel = 0x6a9; break;
	case 10586: offProtection = 0x6b2; offSigLevel = 0x6b0; offSecSigLevel = 0x6b1; break;
	case 14393: offProtection = 0x6c2; offSigLevel = 0x6c0; offSecSigLevel = 0x6c1; break;
	case 15063:
	case 16299:
	case 17134: offProtection = 0x6ca; offSigLevel = 0x6c8; offSecSigLevel = 0x6c9; break;
	case 17763: offProtection = 0x6ca; offSigLevel = 0x6c8; offSecSigLevel = 0x6c9; break;
	case 18362:
	case 18363: offProtection = 0x6fa; offSigLevel = 0x6f8; offSecSigLevel = 0x6f9; break;
	default:
		// 19041(20H1)+ 及未知新版，默认用 0x87a（Win10 21H2/22H2、Win11 早期）
		if (NtBuildNumber >= 19041)
		{
			offProtection = 0x87a; offSigLevel = 0x878; offSecSigLevel = 0x879;
		}
		break;
	}

	if (offProtection == 0)
	{
		DbgPrint("[PPL] 未识别的 build 号(%lu)，无法确定 Protection 偏移，跳过 PPL 绕过\n", NtBuildNumber);
		return;
	}

	PUCHAR pProt = (PUCHAR)((ULONG_PTR)pProcess + offProtection);
	PUCHAR pSig = (PUCHAR)((ULONG_PTR)pProcess + offSigLevel);
	PUCHAR pSecSig = (PUCHAR)((ULONG_PTR)pProcess + offSecSigLevel);

	if (!MmIsAddressValid(pProt))
	{
		DbgPrint("[PPL] Protection 地址 %p 无效，跳过\n", pProt);
		return;
	}

	ucOldProt = *pProt;
	ucOldSig = *pSig;

	DbgPrint("[PPL] 目标 EPROCESS=%p Protection=0x%02x SignatureLevel=0x%02x SectionSignatureLevel=0x%02x\n",
		pProcess, ucOldProt, *pSig, *pSecSig);

	// 清零三项，彻底解除 PPL
	*pProt = 0;
	*pSig = 0;
	*pSecSig = 0;

	DbgPrint("[PPL] 已清零 Protection/SignatureLevel/SectionSignatureLevel (原 Protection=0x%02x Sig=0x%02x)\n",
		ucOldProt, ucOldSig);
}
/*	功能:   读 MSR IA32_LSTAR(0xC0000082)，即系统调用入口 KiSystemCall64
/*********************************************************************/
ULONG64 ReadMsrLstar(VOID)
{
	return __readmsr(0xC0000082);
}


/********************************************************************/
/*	函数名: 	FindSSDTServiceTableBase
/*	原理:   Win10 x64 上 SSDT 不导出。做法：
/*			1) 读 MSR LSTAR(0xC0000082) 得 KiSystemCall64 入口；
/*			2) 从入口向下扫描 "lea r10,[rip+disp32]"(4C 8D 15 imm32)；
/*			3) 命中的目标地址可能是：
/*			   a) KiServiceTable —— 4 字节偏移数组（表项高 16 位通常是
/*			      0xFFFF 的负偏移或小正偏移，连续排列）；
/*			   b) KeServiceDescriptorTable —— 结构，[0]=KiServiceTable、
/*			      [1]=0、[2]=服务数(小整数)、[3]=KiArgumentTable。
/*			4) 用"结构特征"([1]==0 且 [2] 是几百的小整数)识别结构，
/*			   取 [0] 作为 KiServiceTable；用"数组特征"(前几个 4 字节
/*			   都是偏移、且按 >>>4+基址 落在 ntoskrnl 内)识别数组。
/*	返回:   KiServiceTable 基址，失败返回 0
/*********************************************************************/
ULONG_PTR FindSSDTServiceTableBase(VOID)
{
	ULONG64 ulLstar = ReadMsrLstar();
	ULONG64 pScan;
	ULONG i;

	if (ulLstar < 0xFFFF800000000000ULL || ul_KernelBase == 0 || ul_KernelSize == 0)
		return 0;

	for (i = 0; i < 0x2000; i++)
	{
		pScan = ulLstar + i;
		if (!MmIsAddressValid((PVOID)pScan) || !MmIsAddressValid((PVOID)(pScan + 6)))
			continue;

		if (*(PUCHAR)(pScan + 0) == 0x4C &&
			*(PUCHAR)(pScan + 1) == 0x8D &&
			*(PUCHAR)(pScan + 2) == 0x15)
		{
			LONG lDisp = *(PLONG)(pScan + 3);
			ULONG64 ulTarget = pScan + 7 + lDisp;

			if (ulTarget < 0xFFFF800000000000ULL || (ulTarget & 7))
				continue;

			if (!MmIsAddressValid((PVOID)ulTarget) || !MmIsAddressValid((PVOID)(ulTarget + 0x17)))
				continue;

			ULONG64 f0 = *(PULONG64)(ulTarget + 0x00);
			ULONG64 f1 = *(PULONG64)(ulTarget + 0x08);
			ULONG64 f2 = *(PULONG64)(ulTarget + 0x10);
			ULONG64 f3 = *(PULONG64)(ulTarget + 0x18);

			// ---- 情况B：KeServiceDescriptorTable 结构 ----
			// 特征：f1==0 且 f2 是服务数(几十~一千多的小整数) 且 f0/f3 是内核地址
			if (f1 == 0 && f2 >= 50 && f2 <= 2000 &&
				f0 >= ul_KernelBase && f0 < ul_KernelBase + ul_KernelSize &&
				f3 >= ul_KernelBase && f3 < ul_KernelBase + ul_KernelSize)
			{
				// f0 即 KiServiceTable；再验证其前两个表项经 >>>4+基址 落在内核内
				if (MmIsAddressValid((PVOID)f0) && MmIsAddressValid((PVOID)(f0 + 7)))
				{
					ULONG e0 = *(PULONG)(f0 + 0);
					ULONG e1 = *(PULONG)(f0 + 4);
					ULONG64 a0 = f0 + ((ULONG64)(LONG)e0 >> 4);
					ULONG64 a1 = f0 + ((ULONG64)(LONG)e1 >> 4);
					DbgPrint("[SSDT] 结构命中 KeServiceDescriptorTable=%p KiServiceTable=%p 服务数=%llu (表项0->%p 1->%p)\n",
						(PVOID)ulTarget, (PVOID)f0, f2, (PVOID)a0, (PVOID)a1);
					return (ULONG_PTR)f0;
				}
			}

			// ---- 情况A：KiServiceTable 数组 ----
			// 特征：前两个 4 字节表项经 >>>4+基址 后落在 ntoskrnl 映像内
			{
				ULONG e0 = *(PULONG)(ulTarget + 0);
				ULONG e1 = *(PULONG)(ulTarget + 4);
				ULONG e2 = *(PULONG)(ulTarget + 8);
				ULONG64 a0 = ulTarget + ((ULONG64)(LONG)e0 >> 4);
				ULONG64 a1 = ulTarget + ((ULONG64)(LONG)e1 >> 4);
				ULONG64 a2 = ulTarget + ((ULONG64)(LONG)e2 >> 4);
				BOOLEAN b0 = (a0 >= ul_KernelBase && a0 < ul_KernelBase + ul_KernelSize);
				BOOLEAN b1 = (a1 >= ul_KernelBase && a1 < ul_KernelBase + ul_KernelSize);
				BOOLEAN b2 = (a2 >= ul_KernelBase && a2 < ul_KernelBase + ul_KernelSize);

				DbgPrint("[SSDT] 数组候选 pScan=%p target=%p e0=%08x e1=%08x e2=%08x (a0/1/2在内核:%d/%d/%d)\n",
					(PVOID)pScan, (PVOID)ulTarget, e0, e1, e2, b0, b1, b2);

				if (b0 && b1 && b2 && a0 != a1)
				{
					DbgPrint("[SSDT] 数组命中 KiServiceTable=%p (服务0=%p 1=%p 2=%p)\n",
						(PVOID)ulTarget, (PVOID)a0, (PVOID)a1, (PVOID)a2);
					return (ULONG_PTR)ulTarget;
				}
			}
		}
	}

	DbgPrint("[SSDT] 未定位到 KiServiceTable (扫描 %lu 字节)\n", i);
	return 0;
}


/********************************************************************/
/*	函数名: 	SsdtDebugActiveProcess
/*	功能:   通过 SSDT 以 KernelMode 直接调用 NtDebugActiveProcess。
/*			绕开用户态 NtDebugActiveProcess 内部的 UserMode Ob 引用
/*			（后者会触发反作弊进程的 ObCallback 剥离 PROCESS_* 权限位，
/*			 导致 STATUS_ACCESS_DENIED）。内核态调用 PreviousMode 为
/*			 KernelMode，Ob 回调不触发，附加可成功。
/*	参数:   ulSyscallNum   NtDebugActiveProcess 的 SSDT 服务号
/*			hProcess       目标进程全权限句柄（内核构造）
/*			hDebugObject   调试对象句柄
/*	返回:   NtDebugActiveProcess 的 NTSTATUS
/*********************************************************************/
NTSTATUS SsdtDebugActiveProcess(ULONG ulSyscallNum, HANDLE hProcess, HANDLE hDebugObject)
{
	ULONG_PTR ulKiServiceTable = 0;
	ULONG_PTR ulFuncAddr = 0;
	NTSTATUS st = STATUS_NOT_IMPLEMENTED;

	ulKiServiceTable = FindSSDTServiceTableBase();
	if (ulKiServiceTable == 0)
	{
		DbgPrint("[SSDT] KiServiceTable 定位失败，无法内核附加\n");
		return STATUS_NOT_IMPLEMENTED;
	}

	// 关键：x64 的 SSDT 表项是 4 字节相对偏移（offset<<4 | argInfo），
	// 真实函数地址 = KiServiceTable + (entry >> 4)（entry 按有符号 32 位取）
	if (!MmIsAddressValid((PVOID)(ulKiServiceTable + (ULONG_PTR)ulSyscallNum * 4)))
	{
		DbgPrint("[SSDT] 服务号 %lu 越界\n", ulSyscallNum);
		return STATUS_INVALID_PARAMETER;
	}

	LONG lEntry = *(PLONG)(ulKiServiceTable + (ULONG_PTR)ulSyscallNum * 4);
	ulFuncAddr = ulKiServiceTable + ((ULONG64)lEntry >> 4);

	if (ulFuncAddr < ul_KernelBase || ulFuncAddr >= ul_KernelBase + ul_KernelSize)
	{
		DbgPrint("[SSDT] 服务号 %lu 解算地址异常(%p)，表项=%08x\n",
			ulSyscallNum, (PVOID)ulFuncAddr, (ULONG)lEntry);
		return STATUS_INVALID_PARAMETER;
	}

	DbgPrint("[SSDT] NtDebugActiveProcess 服务号=%lu 表项=%08x -> 地址=%p\n",
		ulSyscallNum, (ULONG)lEntry, (PVOID)ulFuncAddr);

	// 内核态直接调用：NtDebugActiveProcess(ProcessHandle, DebugObjectHandle)
	// x64 fastcall：rcx=ProcessHandle, rdx=DebugObjectHandle
	typedef NTSTATUS(__fastcall *PFN_DEBUG_ACTIVE)(HANDLE, HANDLE);
	PFN_DEBUG_ACTIVE pfn = (PFN_DEBUG_ACTIVE)ulFuncAddr;

	// 【关键】临时把当前线程的 PreviousMode 改成 KernelMode(0)。
	// 原因：FORCEATTACH 的 IOCTL 是在用户态 DeviceIoControl 的 IRP 上下文里处理的，
	//       当前线程 KTHREAD->PreviousMode = UserMode(1)。即使通过 SSDT 直接 call
	//       NtDebugActiveProcess，其内部 KeGetPreviousMode() 仍读到 UserMode，
	//       于是 ObReferenceObjectByHandle(..., UserMode, ...) 依然走用户态权限检查
	//       （Ob 回调、PPL 裁剪），导致 STATUS_ACCESS_DENIED。
	//       只有把 PreviousMode 改成 KernelMode，才能让 Ob 引用不触发这些拦截。
	// KTHREAD->PreviousMode 偏移：Win10 1909(18363) = 0x232（1 字节，1=User,0=Kernel）。
	PUCHAR pPrevMode = (PUCHAR)((ULONG_PTR)KeGetCurrentThread() + 0x232);
	UCHAR  ucOldPrevMode = *pPrevMode;

	DbgPrint("[SSDT] 原 PreviousMode=%u (KTHREAD=%p)，临时切换为 KernelMode\n",
		ucOldPrevMode, KeGetCurrentThread());

	*pPrevMode = 0;   // KernelMode

	__try
	{
		st = pfn(hProcess, hDebugObject);
	}
	__finally
	{
		// 无论成败或异常，务必恢复 PreviousMode，避免污染后续系统调用
		*pPrevMode = ucOldPrevMode;
	}

	DbgPrint("[SSDT] NtDebugActiveProcess(内核态,PreviousMode=Kernel) = %08x\n", st);
	return st;
}


/********************************************************************/
/*	函数名: 	IRP 分发 - DEVICE_CONTROL
/*	功能:   IOCTL_TEST_FORCEOPEN：内核直接构造目标进程的
/*			PROCESS_ALL_ACCESS 用户态句柄，绕过 OpenProcess 权限检查
/*********************************************************************/
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);

	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	NTSTATUS state = STATUS_INVALID_DEVICE_REQUEST;
	ULONG ulInfo = 0;

	if (pStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_TEST_GETMASK)
	{
		// 返回 48 字节: [0]=mask值(未知则0) [1]=mask地址有效标志
		//              [2]=OBJECT_TYPE地址 [3]=ValidAccessMask地址
		//              [4]=内核基址 [5]=内核大小
		PULONG64 pOut = (PULONG64)pIrp->AssociatedIrp.SystemBuffer;
		pOut[0] = 0;
		pOut[1] = 0;
		pOut[2] = (ULONG64)ul_DebugObjectType_Addr;
		pOut[3] = (ULONG64)ul_ValidAccessMask_Addr;
		pOut[4] = (ULONG64)ul_KernelBase;
		pOut[5] = (ULONG64)ul_KernelSize;
		if (ul_ValidAccessMask_Addr && MmIsAddressValid((PVOID)ul_ValidAccessMask_Addr))
		{
			pOut[0] = *(PULONG)ul_ValidAccessMask_Addr;
			pOut[1] = 1;
		}
		ulInfo = 48;
		state = STATUS_SUCCESS;
	}

	if (pStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_TEST_FORCEOPEN)
	{
		ULONG ulPid = *(PULONG)pIrp->AssociatedIrp.SystemBuffer;
		PEPROCESS pProcess = NULL;

		do
		{
			if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ulPid, &pProcess)))
			{
				DbgPrint("[强制附加] 找不到进程 PID:%lu\n", ulPid);
				state = STATUS_INVALID_PARAMETER;
				break;
			}

			// 内核直接构造全权限句柄（不经过 ObCallback/常规权限检查链）
			HANDLE hKernel = NULL;
			state = ObOpenObjectByPointer(pProcess, 0, NULL, PROCESS_ALL_ACCESS,
				*PsProcessType, KernelMode, &hKernel);
			if (!NT_SUCCESS(state))
			{
				DbgPrint("[强制附加] ObOpenObjectByPointer 失败:%08x\n", state);
				break;
			}

			// 诊断：读内核句柄真实 GrantedAccess（Obp 句柄表项 +0x28 GrantedAccessBits）
			{
				ACCESS_MASK am = 0;
				// OB_HEADER 在句柄表项之前 0x30；GrantedAccessBits 在 OB_HEADER 内偏移因版本而异，
				// 用 ObGetObjectType + ObReferenceObjectByHandle 重新引用兜底打印更稳，但这里
				// 直接取句柄表项里紧邻 OBJECT 头的 GrantedAccess（Win10 OB_HEADER 布局）。
				// 采用可靠方式：ObReferenceObjectByHandle 以 PROCESS_ALL_ACCESS 重新引用，
				// 若成功说明该句柄确实持全权限。
				PVOID pTmp = NULL;
				NTSTATUS stRef = ObReferenceObjectByHandle(hKernel, PROCESS_ALL_ACCESS,
					*PsProcessType, KernelMode, &pTmp, NULL);
				DbgPrint("[诊断] 内核句柄重新引用(全权限) status=%08x %s\n",
					stRef, NT_SUCCESS(stRef) ? "(权限完整)" : "(权限被削!)");
				if (NT_SUCCESS(stRef))
					ObDereferenceObject(pTmp);
			}

			// 诊断：目标进程保护级别（EPROCESS.SignatureLevel/SectionSignatureLevel）
			// Win10 x64: Protection 位在 +0x6A8 附近（版本相关，仅作参考打印，不依赖布局）
			{
				// 通过 PsGetProcessProtection 不存在；这里直接读 FLAGS 里 PPL 相关位不可靠，
				// 改为打印 EPROCESS 里 DebugPort 是否已占用（决定是否 STATUS_PORT_ALREADY_SET）
				PVOID pDebugPort = NULL;
				if (PsGetProcessDebugPort)
					pDebugPort = PsGetProcessDebugPort(pProcess);
				DbgPrint("[诊断] 目标进程 DebugPort=%p %s\n",
					pDebugPort, pDebugPort ? "(已被附加!)" : "(空,可附加)");
			}

			// 复制为当前调用进程的用户态句柄
			HANDLE hUser = NULL;
			state = ZwDuplicateObject(ZwCurrentProcess(), hKernel, ZwCurrentProcess(),
				&hUser, 0, 0, DUPLICATE_SAME_ACCESS);
			ZwClose(hKernel);
			if (!NT_SUCCESS(state))
			{
				DbgPrint("[强制附加] ZwDuplicateObject 失败:%08x\n", state);
				break;
			}

			*(PULONG64)pIrp->AssociatedIrp.SystemBuffer = (ULONG64)(ULONG_PTR)hUser;
			ulInfo = sizeof(ULONG64);
			DbgPrint("[强制附加] PID:%lu 全权限句柄:%p\n", ulPid, hUser);

		} while (0);

		if (pProcess)
			ObDereferenceObject(pProcess);
	}

	if (pStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_TEST_FORCEATTACH)
	{
		// 输入（结构化，8 字节对齐）:
		//   [0] ULONG pid          目标进程 PID
		//   [1] ULONG syscallNum   NtDebugActiveProcess 的 SSDT 服务号（用户态从 ntdll 桩读取）
		//   [2] HANDLE hProcess   目标进程句柄（旧，PPL 状态构造，权限可能被裁剪，仅作参考）
		//   [3] HANDLE hDebug     调试对象句柄（用户态 NtCreateDebugObject 取得）
		// 输出（16 字节）:
		//   [0] = 内核态 NtDebugActiveProcess 的最终 NTSTATUS（>=0 即附加成功）
		//   [1] = 附加路径: 1=SSDT内核态成功 0=失败
		PULONG64 pBuf = (PULONG64)pIrp->AssociatedIrp.SystemBuffer;
		ULONG   ulPid        = (ULONG)pBuf[0];
		ULONG   ulSyscallNum = (ULONG)(pBuf[1] & 0xFFFFFFFF);
		HANDLE  hProcess     = (HANDLE)(ULONG_PTR)pBuf[2];
		HANDLE  hDebug       = (HANDLE)(ULONG_PTR)pBuf[3];

		DbgPrint("[强制附加] FORCEATTACH PID:%lu syscall:%lu hProc:%p hDbg:%p\n",
			ulPid, ulSyscallNum, hProcess, hDebug);

		// 1) 同步恢复 ValidAccessMask + 清零 PPL 保护（DisableProcessProtection）
		KernelForceAttach(ulPid);

		// 2) PPL 已解除，重新解析目标进程并【重新】构造全权限句柄。
		//    之前的句柄( FORCEOPEN )是在 PPL 仍生效时构造的，其 GrantedAccess
		//    被裁剪掉了 PROCESS_SET_PORT 等位；PPL 清零后必须重建句柄才能拿到
		//    完整权限，供内核态 NtDebugActiveProcess 内部 ObReferenceObjectByHandle 使用。
		NTSTATUS stAttach = STATUS_INVALID_PARAMETER;
		PEPROCESS pProc2 = NULL;
		HANDLE hProcKernel = NULL;

		do
		{
			if (!hDebug || !ulSyscallNum)
			{
				DbgPrint("[强制附加] FORCEATTACH 缺少调试对象句柄或 syscall 号\n");
				break;
			}

			if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ulPid, &pProc2)))
			{
				DbgPrint("[强制附加] FORCEATTACH 重新解析进程失败 PID:%lu\n", ulPid);
				stAttach = STATUS_INVALID_PARAMETER;
				break;
			}

			// 重新构造全权限句柄（此时 PPL 已解除，能拿到 PROCESS_SET_PORT 等完整权限）
			NTSTATUS stOpen = ObOpenObjectByPointer(pProc2, 0, NULL, PROCESS_ALL_ACCESS,
				*PsProcessType, KernelMode, &hProcKernel);
			if (!NT_SUCCESS(stOpen))
			{
				DbgPrint("[强制附加] FORCEATTACH 重建全权限句柄失败:%08x\n", stOpen);
				stAttach = stOpen;
				break;
			}

			// 诊断：确认重建句柄持全权限（PROCESS_SET_PORT=0x0800 等关键位）
			{
				PVOID pTmp = NULL;
				NTSTATUS stRef = ObReferenceObjectByHandle(hProcKernel, PROCESS_ALL_ACCESS,
					*PsProcessType, KernelMode, &pTmp, NULL);
				DbgPrint("[诊断] 重建句柄重新引用(全权限) status=%08x %s\n",
					stRef, NT_SUCCESS(stRef) ? "(权限完整!)" : "(权限仍被削)");
				if (NT_SUCCESS(stRef))
					ObDereferenceObject(pTmp);
			}

			// 3) 通过 SSDT 内核态直接附加（用重建的完整权限句柄）
			stAttach = SsdtDebugActiveProcess(ulSyscallNum, hProcKernel, hDebug);

		} while (0);

		if (hProcKernel)
			ZwClose(hProcKernel);
		if (pProc2)
			ObDereferenceObject(pProc2);

		pBuf[0] = (ULONG64)(ULONG)stAttach;
		pBuf[1] = (stAttach >= 0) ? 1 : 0;
		ulInfo = 16;

		DbgPrint("[强制附加] FORCEATTACH 内核态附加结果 = %08x\n", stAttach);
		state = STATUS_SUCCESS;
	}

	pIrp->IoStatus.Status = state;
	pIrp->IoStatus.Information = ulInfo;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return state;
}


/********************************************************************/
/*	创建:	2015/03/11
/*	函数名: 	驱动开始例程
/*	参数1:
/*	参数2:
/*
/*	返回值:
/*********************************************************************/
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pReg)
{
	NTSTATUS state = STATUS_SUCCESS;
	LDR_DATA_TABLE_ENTRY	*pLdrDataTableEntry;


	UNREFERENCED_PARAMETER(pReg);

	pDriverObject->DriverUnload = DriverUnload;

	// InitKillThread 是 2015 年对抗 病毒 的特征码扫描（依赖 Win7 专属导出
	// PsTerminateSystemThread），与强制附加研究无关，Win10/11 上必然失败，
	// 且含未验址的字节读取，直接停用。
	//InitKillThread();

	DbgPrint("驱动加载成功\n");

	// 获取内核模块基址：优先 PE 翻页法（不依赖模块链表），失败再用 SearchDriver
	if (!GetNtosBaseAndSize(&ul_KernelBase, &ul_KernelSize))
	{
		pLdrDataTableEntry = SearchDriver(pDriverObject, L"ntoskrnl.exe");
		if (pLdrDataTableEntry)
		{
			ul_KernelBase = (ULONG_PTR)pLdrDataTableEntry->DllBase;
			ul_KernelSize = (ULONG_PTR)pLdrDataTableEntry->SizeOfImage;
		}
	}
	DbgPrint("内核基址:%p 大小:%p %s\n", ul_KernelBase, ul_KernelSize,
		ul_KernelSize ? "" : "(!!! 获取失败, 扫描无法进行)");

	pMyDriverObject = pDriverObject;

	// 动态查找 DbgkDebugObjectType（不依赖硬编码偏移，适配任意 Win7 x64 内核）
	ULONG_PTR ul_DebugObjectType = FindDbgkDebugObjectType();
	if (ul_DebugObjectType)
	{
		ul_DebugObjectType_Addr = ul_DebugObjectType;
		ul_ValidAccessMask_Addr = FindValidAccessMaskAddr(ul_DebugObjectType);
		DbgPrint("调试对象类型地址:%p\n", ul_DebugObjectType_Addr);
		DbgPrint("调试对象权限地址:%p\n", ul_ValidAccessMask_Addr);
	}
	else
	{
		DbgPrint("[警告] 未能动态定位 Debug 对象类型\n");
	}

	// 【关键防护】在 PASSIVE_LEVEL 一次性严格校验将要被 DPC 写入的地址：
	// 必须是内核池地址 + 目标 4 字节所在整页可读 + 当前值像 access mask（低 24 位为权限位）。
	// 校验不过就置 0，DPC 里直接不写——这是唯一能避免 DPC 写坏内存的方式。
	if (ul_ValidAccessMask_Addr)
	{
		BOOLEAN bOk = FALSE;
		if (ul_ValidAccessMask_Addr >= 0xFFFF800000000000ULL &&
			MmIsAddressValid((PVOID)ul_ValidAccessMask_Addr) &&
			MmIsAddressValid((PVOID)(ul_ValidAccessMask_Addr + 3)))
		{
			ULONG ulCur = *(PULONG)ul_ValidAccessMask_Addr;
			// access mask 低位必为 1（含 READ/WRITE 等），且不应是全 0/全 FF
			if ((ulCur & 0x0000000F) != 0 && ulCur != 0xFFFFFFFF)
				bOk = TRUE;
			DbgPrint("[校验] mask地址:%p 当前值:%08x -> %s\n",
				(PVOID)ul_ValidAccessMask_Addr, ulCur, bOk ? "通过" : "拒绝(值可疑)");
		}
		if (!bOk)
		{
			ul_ValidAccessMask_Addr = 0;
			DbgPrint("[校验] ValidAccessMask 地址校验未通过，已置0，DPC 不会写入\n");
		}
	}

	// 【Win10/11 关键】在 PASSIVE_LEVEL 用 MDL 建立一份"可写别名"映射。
	// 这样 DPC 里只写别名地址，无需清 CR0.WP（清 CR0 会被 PatchGuard 判定并蓝屏）。
	if (ul_ValidAccessMask_Addr)
	{
		g_pMaskMdl = IoAllocateMdl((PVOID)ul_ValidAccessMask_Addr, sizeof(ULONG), FALSE, FALSE, NULL);
		if (g_pMaskMdl)
		{
			__try
			{
				MmProbeAndLockPages(g_pMaskMdl, KernelMode, IoReadAccess);
				g_pMaskWriteAddr = (PULONG)MmMapLockedPagesSpecifyCache(g_pMaskMdl,
					KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				g_pMaskWriteAddr = NULL;
			}

			if (g_pMaskWriteAddr)
				DbgPrint("[映射] ValidAccessMask 可写别名:%p (DPC 将写此地址)\n", g_pMaskWriteAddr);
			else
				DbgPrint("[映射] 可写别名建立失败，DPC 不会写入\n");
		}
	}


	SetDPCTimerByDbgAccess();

	// 以下两个是 2015 年对抗 病毒 的特征码扫描逻辑，与强制附加研究无关，
	// 且在非原作 build 上会因未防护的特征码地址解引用导致蓝屏，保持关闭！
	//SetDPCTimerByNotifys();

	//SetDPCTimerByFxxkThread();

	// 创建强制附加设备
	{
		UNICODE_STRING usDev, usLink;
		RtlInitUnicodeString(&usDev, DEVICE_NAME);
		state = IoCreateDevice(pDriverObject, 0, &usDev, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_pDevObj);
		if (!NT_SUCCESS(state))
		{
			DbgPrint("IoCreateDevice 失败:%08x\n", state);
			return state;
		}

		RtlInitUnicodeString(&usLink, SYMLINK_NAME);
		state = IoCreateSymbolicLink(&usLink, &usDev);
		if (!NT_SUCCESS(state))
		{
			DbgPrint("IoCreateSymbolicLink 失败:%08x\n", state);
			IoDeleteDevice(g_pDevObj);
			g_pDevObj = NULL;
			return state;
		}

		pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
		pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
		pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
		DbgPrint("强制附加设备就绪: \\\\.\\JfDebug\n");
	}

	return state;
}


/********************************************************************/
/*	创建:	2015/03/11
/*	函数名: 驱动卸载例程
/*	参数1:
/*	参数2:
/*
/*	返回值:
/*********************************************************************/
void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	BOOLEAN bTimer = FALSE;
	bTimer = KeCancelTimer(&Timer);
	if (bTimer)
	{
		DbgPrint("DPC定时器卸载成功\n");
	}
	KeCancelTimer(&Timer2);
	KeCancelTimer(&Timer3);

	// 【顺序很重要】KeCancelTimer 只是"请求取消"，正在别的 CPU 上执行的 DPC
	// 可能仍在写别名地址。正确顺序：
	//   1) 先置空 DPC 使用的写指针（即使有在途 tick 也不会再写）
	//   2) 小睡让在途 DPC 跑完（PASSIVE_LEVEL 可用忙等）
	//   3) 解映射 -> 解锁 -> 释放 MDL
	if (g_pMaskWriteAddr)
	{
		PULONG pAlias = g_pMaskWriteAddr;
		g_pMaskWriteAddr = NULL;
		KeStallExecutionProcessor(1000);	// 1ms 忙等，等在途 DPC 退出
		MmUnmapLockedPages(pAlias, g_pMaskMdl);
	}
	if (g_pMaskMdl)
	{
		MmUnlockPages(g_pMaskMdl);
		IoFreeMdl(g_pMaskMdl);
		g_pMaskMdl = NULL;
	}

	// 清理强制附加设备
	if (g_pDevObj)
	{
		UNICODE_STRING usLink;
		RtlInitUnicodeString(&usLink, SYMLINK_NAME);
		IoDeleteSymbolicLink(&usLink);
		IoDeleteDevice(g_pDevObj);
		g_pDevObj = NULL;
	}

	DbgPrint("驱动卸载完成\n");
}


// 用于全局调试对象权限的计时器   500ms写一次
VOID TimerRoutine(
	_In_      struct _KDPC *Dpc,
	_In_opt_  PVOID DeferredContext,
	_In_opt_  PVOID SystemArgument1,
	_In_opt_  PVOID SystemArgument2
	)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	LARGE_INTEGER lTime = { 0 };
	ULONG ulMicroSecond = 0;

	//将定时器的时间设置为50us（自续周期相同）
	ulMicroSecond = 50;
	//将32位整数转化成64位整数
	lTime = RtlConvertLongToLargeInteger(-10 * ulMicroSecond);

	// 【重要】DPC 运行在 DISPATCH_LEVEL，此级别下 MmIsAddressValid 不可靠
	// （它只看页表存在位，不判 IRQL 合法性），绝不能在 DPC 里靠它兜底。
	// 地址有效性已在 DriverEntry(PASSIVE_LEVEL) 一次性校验完毕，
	// 写入走预映射的 g_pMaskWriteAddr，全程不需要任何地址校验。
	{
		static ULONG ulTick = 0;
		if ((ulTick++ % 20000) == 0 && g_pMaskWriteAddr)
		{
			DbgPrint("ValidAccessMask 当前值:%08x (别名:%p)\n",
				*g_pMaskWriteAddr, g_pMaskWriteAddr);
		}
	}

	if (g_pMaskWriteAddr)
	{
		// 【Win10/11 关键】不能 WPOFF/WPON 清 CR0.WP 直写——会触发 PatchGuard 蓝屏。
		// 也不能在 DPC(DISPATCH_LEVEL) 调 MmProbeAndLockPages（要求 <= APC_LEVEL）。
		// 正确做法：g_pMaskWriteAddr 已在 DriverEntry(PASSIVE_LEVEL) 用 MDL 预映射好，
		// DPC 里只写这个"可写别名"地址即可，不需要任何地址校验或 CR0 操作。
		*g_pMaskWriteAddr = 0x1f000f;
	}

	KeSetTimer(&Timer, lTime, &myDpc);
}


// 用于清除回调以及OBJ HOOK的计时器   30秒检查一次
VOID TimerRoutine2(
	_In_      struct _KDPC *Dpc,
	_In_opt_  PVOID DeferredContext,
	_In_opt_  PVOID SystemArgument1,
	_In_opt_  PVOID SystemArgument2
	)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	LDR_DATA_TABLE_ENTRY	*pLdrTPDataTableEntry;
	LARGE_INTEGER lTime = { 0 };
	ULONG ulMicroSecond = 0;

	//将定时器的时间设置为30S
	ulMicroSecond = 30000000;
	//将32位整数转化成64位整数
	lTime = RtlConvertLongToLargeInteger(-10 * ulMicroSecond);


	// 获取病毒模块基址和大小
	pLdrTPDataTableEntry = SearchDriver(pMyDriverObject, L"TesSafe.sys");
	if (pLdrTPDataTableEntry)
	{
		ul_TPBaseAddr = (ULONG_PTR)pLdrTPDataTableEntry->DllBase;
		ul_TPSize = (ULONG_PTR)pLdrTPDataTableEntry->SizeOfImage;
		DbgPrint("病毒驱动加载基址:%p，大小:%p\n", ul_TPBaseAddr, ul_TPSize);
	}

	FuckTPProcessNotify();
	FuckTPThreadNotify();
	FuckTPLoadImageNotify();
	if (!GetVersionAndHardCode())
	{
		DbgPrint("GetVersionAndHardCode failed!\n");
	}
	else
	{
		FuckTPObCallbacks();
	}

	KeSetTimer(&Timer2, lTime, &myDpc2);
}



// 用于清除病毒关键线程的计时器回调函数   30秒检查一次
VOID TimerRoutine3(
	_In_      struct _KDPC *Dpc,
	_In_opt_  PVOID DeferredContext,
	_In_opt_  PVOID SystemArgument1,
	_In_opt_  PVOID SystemArgument2
	)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	PEPROCESS pGameProcess = NULL;
	LARGE_INTEGER lTime = { 0 };
	ULONG ulMicroSecond = 0;

	//将定时器的时间设置为30S
	ulMicroSecond = 30000000;
	//将32位整数转化成64位整数
	lTime = RtlConvertLongToLargeInteger(-10 * ulMicroSecond);

	pGameProcess = FindGameProcess();
	EnumThread(pGameProcess);

	KeSetTimer(&Timer3, lTime, &myDpc3);
}


// 查找内核模块
PLDR_DATA_TABLE_ENTRY SearchDriver(PDRIVER_OBJECT pDriverObject, wchar_t *strDriverName)
{
	LDR_DATA_TABLE_ENTRY	*pDataTableEntry = NULL, *pTempDataTableEntry = NULL;
	PLIST_ENTRY				pList;
	UNICODE_STRING			usModuleName;

	RtlInitUnicodeString(&usModuleName, strDriverName);

	pDataTableEntry = (LDR_DATA_TABLE_ENTRY*)pDriverObject->DriverSection;
	if (!pDataTableEntry)
	{
		return 0;
	}

	pList = pDataTableEntry->InLoadOrderLinks.Blink;

	while (pList != &pDataTableEntry->InLoadOrderLinks)
	{
		pTempDataTableEntry = (LDR_DATA_TABLE_ENTRY *)pList;

		if (&pTempDataTableEntry->BaseDllName != NULL)
		{
			if (0 == RtlCompareUnicodeString(&pTempDataTableEntry->BaseDllName, &usModuleName, FALSE))
			{
				return pTempDataTableEntry;
			}
		}

		pList = pList->Blink;
	}

	return 0;
}


ULONG_PTR GetDbgkDebugobjectAddr()
{
	ULONG_PTR ul_NtCreateDebugObject_addr = 0;
	ULONG_PTR ul_retn = 0;
	ULONG ul_temp = 0;

	// 虚拟机NtCreateDebugObject的偏移是0x45dda0    本机的偏移：0x45a580
	ul_NtCreateDebugObject_addr = ul_KernelBase + ul_NtCreateDebugObject_offset;

	// 防蓝屏：先确认该内核地址可读，再解引用
	if (!MmIsAddressValid((PVOID)(ul_NtCreateDebugObject_addr + 0x7c + 0x3)))
	{
		return 0;
	}

	ul_temp = *(PULONG)(ul_NtCreateDebugObject_addr + 0x7c + 0x3);

	ul_retn = ((ul_NtCreateDebugObject_addr + 0x7c + ul_temp) & 0xfffffff0ffffffff) + 0x7;

	return ul_retn;
}



VOID SetDPCTimerByDbgAccess()
{
	BOOLEAN bTimerStart = FALSE;  // DPC定时器是否开启标志
	LARGE_INTEGER lTime = { 0 };
	ULONG ulMicroSecond = 0;

	// 初始化定时器
	KeInitializeTimer(&Timer);

	// 初始化DPC
	KeInitializeDpc(&myDpc, TimerRoutine, NULL);

	// 开始定时器
	//将定时器的时间设置为500ms
	ulMicroSecond = 100;
	//将32位整数转化成64位整数
	lTime = RtlConvertLongToLargeInteger(-10 * ulMicroSecond);
	bTimerStart = KeSetTimer(&Timer, lTime, &myDpc);
	if (bTimerStart)
	{
		DbgPrint("定时器开启成功\n");
	}
}



VOID SetDPCTimerByNotifys()
{
	BOOLEAN bTimerStart = FALSE;  // DPC定时器是否开启标志
	LARGE_INTEGER lTime = { 0 };
	ULONG ulMicroSecond = 0;

	// 初始化定时器
	KeInitializeTimer(&Timer2);

	// 初始化DPC
	KeInitializeDpc(&myDpc2, TimerRoutine2, NULL);

	// 开始定时器
	//将定时器的时间设置为500ms
	ulMicroSecond = 500000;
	//将32位整数转化成64位整数
	lTime = RtlConvertLongToLargeInteger(-10 * ulMicroSecond);
	bTimerStart = KeSetTimer(&Timer2, lTime, &myDpc2);
	if (bTimerStart)
	{
		DbgPrint("定时器开启成功\n");
	}
}



VOID SetDPCTimerByFxxkThread()
{
	BOOLEAN bTimerStart = FALSE;  // DPC定时器是否开启标志
	LARGE_INTEGER lTime = { 0 };
	ULONG ulMicroSecond = 0;

	// 初始化定时器
	KeInitializeTimer(&Timer3);

	// 初始化DPC
	KeInitializeDpc(&myDpc3, TimerRoutine3, NULL);

	// 开始定时器
	//将定时器的时间设置为500ms
	ulMicroSecond = 500000;
	//将32位整数转化成64位整数
	lTime = RtlConvertLongToLargeInteger(-10 * ulMicroSecond);
	bTimerStart = KeSetTimer(&Timer3, lTime, &myDpc3);
	if (bTimerStart)
	{
		DbgPrint("定时器开启成功\n");
	}
}


ULONG64 FindPspCreateProcessNotifyRoutine()
{
	LONG			OffsetAddr = 0;
	ULONG64			i = 0, pCheckArea = 0;
	UNICODE_STRING	unstrFunc;
	//获得PsSetCreateProcessNotifyRoutine的地址
	RtlInitUnicodeString(&unstrFunc, L"PsSetCreateProcessNotifyRoutine");
	pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);
	//获得PspSetCreateProcessNotifyRoutine的地址
	memcpy(&OffsetAddr, (PUCHAR)pCheckArea + 4, 4);
	pCheckArea = (pCheckArea + 3) + 5 + OffsetAddr;
	DbgPrint("PspSetCreateProcessNotifyRoutine: %llx", pCheckArea);
	//获得PspCreateProcessNotifyRoutine的地址
	for (i = pCheckArea; i < pCheckArea + 0xff; i++)
	{
		if (*(PUCHAR)i == 0x4c && *(PUCHAR)(i + 1) == 0x8d && *(PUCHAR)(i + 2) == 0x35)	//lea r14,xxxx
		{
			LONG OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 3), 4);
			return OffsetAddr + 7 + i;
		}
	}
	return 0;
}


void FuckTPProcessNotify()
{
	int i = 0;
	BOOLEAN b;
	ULONG64	NotifyAddr = 0, MagicPtr = 0;
	ULONG64	PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();
	DbgPrint("PspCreateProcessNotifyRoutine: %llx", PspCreateProcessNotifyRoutine);
	if (!PspCreateProcessNotifyRoutine)
		return;
	for (i = 0; i < 64; i++)
	{
		MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
		// 防蓝屏：读数组项之前先确认地址可读
		if (!MmIsAddressValid((PVOID)MagicPtr))
			continue;
		NotifyAddr = *(PULONG64)(MagicPtr);
		if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
		{
			NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
			if (NotifyAddr >= ul_TPBaseAddr&&NotifyAddr <= ul_TPBaseAddr + ul_TPSize)
			{
				DbgPrint("[CreateProcess]%llx", NotifyAddr);
				PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)NotifyAddr, TRUE);
			}
		}
	}
}



ULONG64 FindPspCreateThreadNotifyRoutine()
{
	ULONG64			i = 0, pCheckArea = 0;
	UNICODE_STRING	unstrFunc;
	RtlInitUnicodeString(&unstrFunc, L"PsSetCreateThreadNotifyRoutine");
	pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);
	DbgPrint("PsSetCreateThreadNotifyRoutine: %llx", pCheckArea);
	for (i = pCheckArea; i < pCheckArea + 0xff; i++)
	{
		if (*(PUCHAR)i == 0x48 && *(PUCHAR)(i + 1) == 0x8d && *(PUCHAR)(i + 2) == 0x0d)	//lea rcx,xxxx
		{
			LONG OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 3), 4);
			return OffsetAddr + 7 + i;
		}
	}
	return 0;
}

void FuckTPThreadNotify()
{
	int i = 0;
	BOOLEAN b;
	ULONG64	NotifyAddr = 0, MagicPtr = 0;
	ULONG64	PspCreateThreadNotifyRoutine = FindPspCreateThreadNotifyRoutine();
	DbgPrint("PspCreateThreadNotifyRoutine: %llx", PspCreateThreadNotifyRoutine);
	if (!PspCreateThreadNotifyRoutine)
		return;
	for (i = 0; i < 64; i++)
	{
		MagicPtr = PspCreateThreadNotifyRoutine + i * 8;
		// 防蓝屏：读数组项之前先确认地址可读
		if (!MmIsAddressValid((PVOID)MagicPtr))
			continue;
		NotifyAddr = *(PULONG64)(MagicPtr);
		if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
		{
			NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
			if (NotifyAddr >= ul_TPBaseAddr&&NotifyAddr <= ul_TPBaseAddr + ul_TPSize)
			{
				DbgPrint("[CreateThread]%llx", NotifyAddr);
				PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)NotifyAddr);
			}
		}
	}
}



ULONG64 FindPspLoadImageNotifyRoutine()
{
	ULONG64			i = 0, pCheckArea = 0;
	UNICODE_STRING	unstrFunc;
	RtlInitUnicodeString(&unstrFunc, L"PsSetLoadImageNotifyRoutine");
	pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);
	DbgPrint("PsSetLoadImageNotifyRoutine: %llx", pCheckArea);
	for (i = pCheckArea; i < pCheckArea + 0xff; i++)
	{
		if (*(PUCHAR)i == 0x48 && *(PUCHAR)(i + 1) == 0x8d && *(PUCHAR)(i + 2) == 0x0d)	//lea rcx,xxxx
		{
			LONG OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 3), 4);
			return OffsetAddr + 7 + i;
		}
	}
	return 0;
}

void FuckTPLoadImageNotify()
{
	int i = 0;
	BOOLEAN b;
	ULONG64	NotifyAddr = 0, MagicPtr = 0;
	ULONG64	PspLoadImageNotifyRoutine = FindPspLoadImageNotifyRoutine();
	DbgPrint("PspLoadImageNotifyRoutine: %llx", PspLoadImageNotifyRoutine);
	if (!PspLoadImageNotifyRoutine)
		return;
	for (i = 0; i < 8; i++)
	{
		MagicPtr = PspLoadImageNotifyRoutine + i * 8;
		// 防蓝屏：读数组项之前先确认地址可读
		if (!MmIsAddressValid((PVOID)MagicPtr))
			continue;
		NotifyAddr = *(PULONG64)(MagicPtr);
		if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
		{
			NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
			if (NotifyAddr >= ul_TPBaseAddr&&NotifyAddr <= ul_TPBaseAddr + ul_TPSize)
			{
				DbgPrint("[LoadImage]%llx", NotifyAddr);
				PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)NotifyAddr);
			}
		}
	}
}



BOOLEAN GetVersionAndHardCode()
{
	BOOLEAN b = FALSE;
	RTL_OSVERSIONINFOW	osi;
	osi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	RtlFillMemory(&osi, sizeof(RTL_OSVERSIONINFOW), 0);
	RtlGetVersion(&osi);
	NtBuildNumber = osi.dwBuildNumber;
	DbgPrint("NtBuildNumber: %ld\n", NtBuildNumber);
	switch (NtBuildNumber)
	{
	case 7600:
	case 7601:
	{
				 ObjectCallbackListOffset = 0xC0;
				 b = TRUE;
				 break;
	}
	case 9200:
	{
				 ObjectCallbackListOffset = 0xC8;	//OBJECT_TYPE.CallbackList
				 b = TRUE;
				 break;
	}
	case 9600:
	{
				 ObjectCallbackListOffset = 0xC8;	//OBJECT_TYPE.CallbackList
				 b = TRUE;
				 break;
	}
	default:
		break;
	}
	return b;
}



//VOID DisableObcallbacks(PVOID Address)
//{
//	KIRQL irql;
//	CHAR patchCode[] = "\x33\xC0\xC3";	//xor eax,eax + ret
//	if (!Address)
//		return;
//	if (MmIsAddressValid(Address))
//	{
//		irql = WPOFF();
//		memcpy(Address, patchCode, 3);
//		WPON(irql);
//	}
//}

ULONG FuckTPObCallbacks()
{
	ULONG c = 0;
	PLIST_ENTRY CurrEntry = NULL;
	POB_CALLBACK pObCallback;
	BOOLEAN IsTxCallback;
	ULONG64 ObProcessCallbackListHead = *(ULONG64*)PsProcessType + ObjectCallbackListOffset;
	ULONG64 ObThreadCallbackListHead = *(ULONG64*)PsThreadType + ObjectCallbackListOffset;
	//
	DbgPrint("ObProcessCallbackListHead: %p\n", ObProcessCallbackListHead);
	CurrEntry = ((PLIST_ENTRY)ObProcessCallbackListHead)->Flink;	//list_head的数据是垃圾数据，忽略
	do
	{
		pObCallback = (POB_CALLBACK)CurrEntry;
		if (pObCallback->ObHandle != 0)
		{
			if (pObCallback->PreCall >= ul_TPBaseAddr&&pObCallback->PreCall <= ul_TPBaseAddr + ul_TPSize)
			{
				DbgPrint("ObHandle: %p\n", pObCallback->ObHandle);
				DbgPrint("PreCall: %p\n", pObCallback->PreCall);
				DbgPrint("PostCall: %p\n", pObCallback->PostCall);
				ObUnRegisterCallbacks(pObCallback->ObHandle);
			}
			c++;
		}
		CurrEntry = CurrEntry->Flink;
	} while (CurrEntry != (PLIST_ENTRY)ObProcessCallbackListHead);
	//
	DbgPrint("ObThreadCallbackListHead: %p\n", ObThreadCallbackListHead);
	CurrEntry = ((PLIST_ENTRY)ObThreadCallbackListHead)->Flink;	//list_head的数据是垃圾数据，忽略
	do
	{
		pObCallback = (POB_CALLBACK)CurrEntry;
		if (pObCallback->ObHandle != 0)
		{
			if (pObCallback->PreCall >= ul_TPBaseAddr&&pObCallback->PreCall <= ul_TPBaseAddr + ul_TPSize)
			{
				DbgPrint("ObHandle: %p\n", pObCallback->ObHandle);
				DbgPrint("PreCall: %p\n", pObCallback->PreCall);
				DbgPrint("PostCall: %p\n", pObCallback->PostCall);
				ObUnRegisterCallbacks(pObCallback->ObHandle);
			}
			c++;
		}
		CurrEntry = CurrEntry->Flink;
	} while (CurrEntry != (PLIST_ENTRY)ObThreadCallbackListHead);
	DbgPrint("ObCallback count: %ld\n", c);
	return c;
}



//枚举进程
PEPROCESS FindGameProcess()
{
	ULONG i = 0;
	PEPROCESS eproc = NULL;
	for (i = 4; i < 262144; i = i + 4) //262144是一个随便的数字，一般来说没有超过100000的PID和TID
	{
		eproc = LookupProcess((HANDLE)i);
		if (eproc != NULL)
		{
			ObDereferenceObject(eproc);
			if (!strcmp((char*)PsGetProcessImageFileName(eproc), "eeeeeeeeeeeeeeee.exe"))
			{
				//DbgPrint("EPROCESS=%p PID=%ld PPID=%ld Name=%s\n",
				//	eproc,
				//	(DWORD)PsGetProcessId(eproc),
				//	(DWORD)PsGetProcessInheritedFromUniqueProcessId(eproc),
				//	PsGetProcessImageFileName(eproc));
				DbgPrint("EPROCESS:%p\n",eproc);
				return eproc;
			}
		}
	}
	return 0;
}


//根据进程ID返回进程EPROCESS，失败返回NULL
PEPROCESS LookupProcess(HANDLE Pid)
{
	PEPROCESS eprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &eprocess)))
		return eprocess;
	else
		return NULL;
}


//根据线程ID返回线程ETHREAD，失败返回NULL
PETHREAD LookupThread(HANDLE Tid)
{
	PETHREAD ethread;
	if (NT_SUCCESS(PsLookupThreadByThreadId(Tid, &ethread)))
		return ethread;
	else
		return NULL;
}


//枚举指定进程的线程
VOID EnumThread(PEPROCESS Process)
{
	ULONG i = 0, c = 0;
	PETHREAD ethrd = NULL;
	PEPROCESS eproc = NULL;

	// 防蓝屏：PspTerminateThreadByPointer 解析失败（NULL）时绝不能调用
	if (PspTerminateThreadByPointer == NULL)
		return;

	for (i = 4; i < 262144; i = i + 4) //262144是一个随便的数字，一般来说没有超过100000的PID和TID
	{
		ethrd = LookupThread((HANDLE)i);
		if (ethrd != NULL)
		{
			//获得线程所属进程
			eproc = IoThreadToProcess(ethrd);
			if (eproc == Process)
			{
				//    虚拟机：+0x388 StartAddress     : Ptr64 Void
				//			+0x410 Win32StartAddress : Ptr64 Void
				//    本机： +0x390 StartAddress     : Ptr64 Void
				//			+0x418 Win32StartAddress : Ptr64 Void

				if ((*(PULONG64)((ULONG64)ethrd + ul_Win32StartAddress_offset) & 0xffff) == 0x233B)
				{
					DbgPrint("病毒入口地址:%p,HANDLE:%d\n",
						*(PULONG64)((ULONG64)ethrd + ul_Win32StartAddress_offset), i);
					PspTerminateThreadByPointer(ethrd, 0, 1);
				}
			}
			ObDereferenceObject(ethrd);
		}
	}
}




VOID InitKillThread()
{
	//get pspterminatethreadbypointer
	ULONG32 callcode = 0;
	ULONG64 AddressOfPspTTBP = 0, AddressOfPsTST = 0, i = 0;
	PETHREAD Thread = NULL;
	PEPROCESS tProcess = NULL;
	NTSTATUS status = 0;
	if (PspTerminateThreadByPointer == NULL)
	{
		AddressOfPsTST = (ULONG64)GetFunctionAddr(L"PsTerminateSystemThread");
		if (AddressOfPsTST == 0)
			return STATUS_UNSUCCESSFUL;
		for (i = 1; i < 0xff; i++)
		{
			if (MmIsAddressValid((PVOID)(AddressOfPsTST + i)) != FALSE &&
				MmIsAddressValid((PVOID)(AddressOfPsTST + i + 5)) != FALSE)
			{
				if (*(BYTE *)(AddressOfPsTST + i) == 0x01 && *(BYTE *)(AddressOfPsTST + i + 1) == 0xe8) //目标地址-原始地址-5=机器码 ==> 目标地址=机器码+5+原始地址
				{
					RtlMoveMemory(&callcode, (PVOID)(AddressOfPsTST + i + 2), 4);
					AddressOfPspTTBP = (ULONG64)callcode + 5 + AddressOfPsTST + i + 1;
				}
			}
		}
		PspTerminateThreadByPointer = (PSPTERMINATETHREADBYPOINTER)AddressOfPspTTBP;
		DbgPrint("PspTerminateThreadByPointer:%p\n", PspTerminateThreadByPointer);
	}
}

ULONG64 Get64bitValue(PVOID p)
{
	if (MmIsAddressValid(p) == FALSE)
		return 0;
	return *(PULONG64)p;
}

ULONG32 Get32bitValue(PVOID p)
{
	if (MmIsAddressValid(p) == FALSE)
		return 0;
	return *(PULONG32)p;
}

VOID Set64bitValue(PVOID p, ULONG64 v)
{
	if (MmIsAddressValid(p) == FALSE)
		return;
	*(PULONG64)p = v;
}

VOID Set32bitValue(PVOID p, ULONG32 v)
{
	if (MmIsAddressValid(p) == FALSE)
		return;
	*(PULONG32)p = v;
}

PVOID GetFunctionAddr(PCWSTR FunctionName)
{
	UNICODE_STRING UniCodeFunctionName;
	RtlInitUnicodeString(&UniCodeFunctionName, FunctionName);
	return MmGetSystemRoutineAddress(&UniCodeFunctionName);
}