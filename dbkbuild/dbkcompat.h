// dbkcompat.h -- compat for legacy DBKKernel with WDK8.1's stub windef.h.
// The stub windef.h only defines base scalars (DWORD/WORD/BYTE/BOOL/UINT)
// and is missing the pointer typedef PDWORD. However, WDK's ntdef.h/wdm.h
// ALREADY typedef PCHAR/PWCHAR/PBYTE/PULONG/etc with multi-var declarations,
// so we must NOT #define those here (would corrupt the system headers).
// We only supply PDWORD, which neither stub nor ntdef defines as a plain name.
// Injected via cl /FI. ASCII-only for codepage safety.
#ifndef _DBKCOMPAT_H_
#define _DBKCOMPAT_H_

#ifndef PDWORD
# define PDWORD DWORD*
#endif

#ifndef PBOOL
# define PBOOL BOOL*
#endif

#ifndef UNREFERENCED_PARAMETER
# define UNREFERENCED_PARAMETER(P) (P)
#endif

#endif // _DBKCOMPAT_H_