#ifndef DEFS_H
#define DEFS_H

#include "Hash.hpp"

#ifdef HASH_API

#ifdef LOCAL_THREAD
typedef LPVOID ( WINAPI * fnVirtualAlloc ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
);

typedef BOOL ( WINAPI * fnVirtualProtect ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flNewProtect,
    PDWORD  lpflOldProtect
);

typedef HANDLE ( WINAPI * fnCreateThread ) (
    LPSECURITY_ATTRIBUTES   lpThreadAttribute,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
);

typedef DWORD ( WINAPI * fnWaitForSingleObject ) (
    HANDLE  hHandle,
    DWORD   dwMilliseconds
);

typedef BOOL ( WINAPI * fnHeapFree ) (
    HANDLE  hHeap,
    DWORD   dwFlags,
    LPVOID  lpMem
);

typedef HANDLE ( WINAPI * fnGetProcessHeap ) ();

CTIME_HASHA(VirtualAlloc)
CTIME_HASHA(VirtualProtect)
CTIME_HASHA(CreateThread)
CTIME_HASHA(WaitForSingleObject)
CTIME_HASHA(HeapFree)
CTIME_HASHA(GetProcessHeap)
#endif // !LOCAL_THREAD

#ifdef LOCAL_THREAD_HIJACK
typedef HANDLE ( WINAPI * fnCreateThread ) (
    LPSECURITY_ATTRIBUTES   lpThreadAttribute,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
);

typedef LPVOID ( WINAPI * fnVirtualAlloc ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
);

typedef BOOL ( WINAPI * fnVirtualProtect ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flNewProtect,
    PDWORD  lpflOldProtect
);

typedef BOOL ( WINAPI * fnGetThreadContext ) (
    HANDLE      hThread,
    LPCONTEXT   lpContext
);

typedef BOOL ( WINAPI * fnSetThreadContext ) (
    HANDLE              hThread,
    const CONTEXT       *lpContext
);

typedef DWORD ( WINAPI * fnResumeThread ) (
    HANDLE  hThread
);

typedef DWORD ( WINAPI * fnWaitForSingleObject ) (
    HANDLE  hHandle,
    DWORD   dwMilliseconds
);

CTIME_HASHA(CreateThread)
CTIME_HASHA(VirtualAlloc)
CTIME_HASHA(VirtualProtect)
CTIME_HASHA(GetThreadContext)
CTIME_HASHA(SetThreadContext)
CTIME_HASHA(ResumeThread)
CTIME_HASHA(WaitForSingleObject)
#endif // !LOCAL_THREAD_HIJACK

#ifdef LOCAL_THREAD_HIJACK_ENUM
typedef DWORD ( WINAPI * fnGetCurrentProcessId ) ();

typedef DWORD ( WINAPI * fnGetCurrentThreadId ) ();

typedef HANDLE ( WINAPI * fnCreateToolhelp32Snapshot) (
    DWORD   dwFlags,
    DWORD   th32ProcessId
);

typedef BOOL ( WINAPI * fnThread32First ) (
    HANDLE          hSnapshot,
    LPTHREADENTRY32 lpte
);

typedef BOOL ( WINAPI * fnCloseHandle ) (
    HANDLE  hObject
);

typedef HANDLE ( WINAPI * fnOpenThread ) (
    DWORD   dwDesiredAccess,
    BOOL    bInheritHandle,
    DWORD   dwThreadId
);

typedef BOOL ( WINAPI * fnThread32Next ) (
    HANDLE          hSnapshot,
    LPTHREADENTRY32 lpte
);

typedef LPVOID ( WINAPI * fnVirtualAlloc ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
);

typedef BOOL ( WINAPI * fnVirtualProtect ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flNewProtect,
    PDWORD  lpflOldProtect
);

typedef DWORD ( WINAPI * fnSuspendThread ) (
    HANDLE  hThread
);

typedef BOOL ( WINAPI * fnGetThreadContext ) (
    HANDLE      hThread,
    LPCONTEXT   lpContext
);

typedef BOOL ( WINAPI * fnSetThreadContext ) (
    HANDLE              hThread,
    const CONTEXT       *lpContext
);

typedef DWORD ( WINAPI * fnResumeThread ) (
    HANDLE  hThread
);

typedef DWORD ( WINAPI * fnWaitForSingleObject ) (
    HANDLE  hHandle,
    DWORD   dwMilliseconds
);

CTIME_HASHA(GetCurrentProcessId)
CTIME_HASHA(GetCurrentThreadId)
CTIME_HASHA(CreateToolhelp32Snapshot)
CTIME_HASHA(Thread32First)
CTIME_HASHA(CloseHandle)
CTIME_HASHA(OpenThread)
CTIME_HASHA(Thread32Next)
CTIME_HASHA(VirtualAlloc)
CTIME_HASHA(VirtualProtect)
CTIME_HASHA(SuspendThread)
CTIME_HASHA(GetThreadContext)
CTIME_HASHA(SetThreadContext)
CTIME_HASHA(ResumeThread)
CTIME_HASHA(WaitForSingleObject)
#endif // !LOCAL_THREAD_HIJACK_ENUM

#ifdef APC_INJECT
typedef HANDLE ( WINAPI * fnCreateEventA ) (
    LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL                  bManualReset,
    BOOL                  bInitialState,
    LPCSTR                lpName
);

typedef DWORD ( WINAPI * fnWaitForSingleObjectEx ) (
    HANDLE  hHandle,
    DWORD   dwMilliseconds,
    BOOL    bAlterable
);

typedef BOOL ( WINAPI * fnCloseHandle ) (
    HANDLE  hObject
);

typedef HANDLE ( WINAPI * fnCreateThread ) (
    LPSECURITY_ATTRIBUTES   lpThreadAttribute,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
);

typedef LPVOID ( WINAPI * fnVirtualAlloc ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
);

typedef BOOL ( WINAPI * fnVirtualProtect ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flNewProtect,
    PDWORD  lpflOldProtect
);

typedef DWORD ( WINAPI * fnQueueUserAPC ) (
    PAPCFUNC    pfnAPC,
    HANDLE      hThread,
    ULONG_PTR   dwData
);

typedef DWORD ( WINAPI * fnWaitForSingleObject ) (
    HANDLE  hHandle,
    DWORD   dwMilliseconds
);

CTIME_HASHA(CreateEventA)
CTIME_HASHA(WaitForSingleObjectEx)
CTIME_HASHA(CloseHandle)
CTIME_HASHA(CreateThread)
CTIME_HASHA(VirtualAlloc)
CTIME_HASHA(VirtualProtect)
CTIME_HASHA(QueueUserAPC)
CTIME_HASHA(WaitForSingleObject)
#endif // !APC_INJECT

#ifdef THREADPOOLWAIT
typedef HANDLE ( WINAPI * fnCreateEventA ) (
    LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL                  bManualReset,
    BOOL                  bInitialState,
    LPCSTR                lpName
);

typedef LPVOID ( WINAPI * fnVirtualAlloc ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
);

typedef BOOL ( WINAPI * fnVirtualProtect ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flNewProtect,
    PDWORD  lpflOldProtect
);

typedef PTP_WAIT ( WINAPI * fnCreateThreadpoolWait ) (
    PTP_WAIT_CALLBACK       pfnwa,
    PVOID                   pv,
    PTP_CALLBACK_ENVIRON    pcbe
);

// typedef void ( WINAPI * fnSetThreadpoolWait ) (
//     PTP_WAIT  pwa,
//     HANDLE    h,
//     PFILETIME pftTimeout
// );

typedef DWORD ( WINAPI * fnWaitForSingleObject ) (
    HANDLE  hHandle,
    DWORD   dwMilliseconds
);

// ---

CTIME_HASHA(CreateEventA)
CTIME_HASHA(VirtualAlloc)
CTIME_HASHA(VirtualProtect)
CTIME_HASHA(CreateThreadpoolWait)
// CTIME_HASHA(SetThreadpoolWait)
CTIME_HASHA(WaitForSingleObject)
#endif // !THREADPOOLWAIT

#ifdef FIBERS
typedef LPVOID ( WINAPI * fnConvertThreadToFiber ) (
    LPVOID  lpParameter
);

typedef LPVOID ( WINAPI * fnVirtualAlloc ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flAllocationType,
    DWORD   flProtect
);

typedef void ( WINAPI * fnDeleteFiber ) (
    LPVOID  lpFiber
);

typedef BOOL ( WINAPI * fnConvertFiberToThread ) ();

typedef BOOL ( WINAPI * fnVirtualProtect ) (
    LPVOID  lpAddress,
    SIZE_T  dwSize,
    DWORD   flNewProtect,
    PDWORD  lpflOldProtect
);

typedef LPVOID ( WINAPI * fnCreateFiber ) (
    SIZE_T                  dwStackSize,
    LPFIBER_START_ROUTINE   lpStartAddress,
    LPVOID                  lpParameter
);

typedef void ( WINAPI * fnSwitchToFiber ) (
    LPVOID  lpFiber
);

CTIME_HASHA(ConvertThreadToFiber)
CTIME_HASHA(VirtualAlloc)
CTIME_HASHA(DeleteFiber)
CTIME_HASHA(ConvertFiberToThread)
CTIME_HASHA(VirtualProtect)
CTIME_HASHA(CreateFiber)
CTIME_HASHA(SwitchToFiber)
#endif // !FIBERS

#endif // !HASH_API

#endif // !DEFS_H