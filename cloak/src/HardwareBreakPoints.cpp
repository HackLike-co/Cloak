#include <Windows.h>
#include <tlhelp32.h>

#include "Structs.h"
#include "HardwareBreakPoints.h"

//---------------------------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------------------------------
// "Ret" Shellcode - Used to terminate original function execution

#pragma section(".text")
__declspec(allocate(".text")) const unsigned char ucRet[] = { 0xC3 };

// Called in the detour function to block the execution of the original function
VOID BLOCK_REAL(IN PCONTEXT pThreadCtx) {
	pThreadCtx->Rip = (ULONG_PTR)&ucRet;
}


//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//										ARGUMENT MANAGEMENT FUNCTIONS


PBYTE GetFunctionArgument(IN PCONTEXT pThreadCtx, IN DWORD dwParmIndex) {

	// The first 4 arguments in x64 are in the "RCX - RDX - R8 - R9" registers
	switch (dwParmIndex) {
	case 0x01:
		return (ULONG_PTR)pThreadCtx->Rcx;
	case 0x02:
		return (ULONG_PTR)pThreadCtx->Rdx;
	case 0x03:
		return (ULONG_PTR)pThreadCtx->R8;
	case 0x04:
		return (ULONG_PTR)pThreadCtx->R9;
	default:
		break;
	}

	// Else more arguments are pushed to the stack
	return *(ULONG_PTR*)(pThreadCtx->Rsp + (dwParmIndex * sizeof(PVOID)));
}

VOID SetFunctionArgument(IN PCONTEXT pThreadCtx, IN ULONG_PTR uValue, IN DWORD dwParmIndex) {

	// The first 4 arguments in x64 are in the "RCX - RDX - R8 - R9" registers
	switch (dwParmIndex) {
	case 0x01:
		(ULONG_PTR)pThreadCtx->Rcx = uValue; return;
	case 0x02:
		(ULONG_PTR)pThreadCtx->Rdx = uValue; return;
	case 0x03:
		(ULONG_PTR)pThreadCtx->R8 = uValue; return;
	case 0x04:
		(ULONG_PTR)pThreadCtx->R9 = uValue; return;
	default:
		break;
	}

	// Else more arguments are pushed to the stack
	*(ULONG_PTR*)(pThreadCtx->Rsp + (dwParmIndex * sizeof(PVOID))) = uValue;
}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//													HELPER FUNCTIONS

DWORD _GetCurrentProcessId() {
	return (DWORD)(__readgsdword(0x40));
}

DWORD _GetCurrentThreadId() {
	return (DWORD)(__readgsdword(0x48));
}

HANDLE _GetProcessHeap() {
	PPEB pPeb = (PPEB)(__readgsqword(0x60));
	return (HANDLE)pPeb->ProcessHeap;
}


unsigned long long SetDr7Bits(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue) {
	unsigned long long mask = (1UL << NmbrOfBitsToModify) - 1UL;
	unsigned long long NewDr7Register = (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);

	return NewDr7Register;
}


//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//												GLOBAL VARIABLES


CRITICAL_SECTION						g_CriticalSection = { 0 };
HARDWARE_ENGINE_INIT_SETTINGS_GLOBAL	GlobalHardwareBreakpointObject = { 0 };
DESCRIPTOR_ENTRY* g_Head = NULL;


//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//												PRIVATE FUNCTIONS PROTOTYPES


// Sets or Removes a hardware breakpoint							\
	* ThreadId	= Thread Identifier to hook								\
	* Address	= Harware breakpoint address (where to install)		\
	* Position	= Can be 0 -> 3, represnting Dr0-Dr3 registers			\
	* Init		= Set(TRUE)/Remove(FALSE) a hardware breakpoint	
BOOL SetHardwareBreakpoint(IN DWORD ThreadId, IN PUINT_VAR_T Address, IN DRX Drx, IN BOOL bInitializeHWBP);


// VEH function that handles the hardware breakpoints exception
LONG ExceptionHandlerCallbackRoutine(IN PEXCEPTION_POINTERS ExceptionInfo);


// Used to set/remove hardware breakpoints among all running threads					\
	* Address			= Harware breakpoint address (where to install)					\
	* Position			= Can be 0 -> 3, represnting Dr0-Dr3 registers						\
	* Init				= Set(TRUE)/Remove(FALSE) a hardware breakpoint					\
	* Tid				= Thread Identifier to hook	| 0 to hook all threads					
BOOL SnapshotInsertHardwareBreakpointHookIntoTargetThread(IN PUINT_VAR_T Address, IN DRX Drx, IN BOOL bInitializeHWBP, IN DWORD ThreadId);


//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//			InitHardwareBreakpointHooking & CleapUpHardwareBreakpointHooking : PUBLIC

BOOL InitHardwareBreakpointHooking() {

	// If already initialized
	if (GlobalHardwareBreakpointObject.IsInit)
		return TRUE;

	RtlSecureZeroMemory(&GlobalHardwareBreakpointObject, sizeof(HARDWARE_ENGINE_INIT_SETTINGS_GLOBAL));
	RtlSecureZeroMemory(&g_CriticalSection, sizeof(CRITICAL_SECTION));

	// Add 'ExceptionHandlerCallbackRoutine' as the VEH handler function
	GlobalHardwareBreakpointObject.HandlerObject = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandlerCallbackRoutine);
	if (!GlobalHardwareBreakpointObject.HandlerObject)
		return FALSE;

	// Initialize critical section
	InitializeCriticalSection(&g_CriticalSection);

	GlobalHardwareBreakpointObject.IsInit = TRUE;

	return TRUE;
}


BOOL CleapUpHardwareBreakpointHooking() {

	DESCRIPTOR_ENTRY* TempObject = NULL;

	if (!GlobalHardwareBreakpointObject.IsInit)
		return TRUE;

	EnterCriticalSection(&g_CriticalSection);

	TempObject = g_Head;

	// Remove all installed breakpoints
	while (TempObject != NULL) {
		RemoveHardwareBreakingPntHook(TempObject->Address, TempObject->ThreadId);
		TempObject = TempObject->Next;
	}

	LeaveCriticalSection(&g_CriticalSection);

	// Uregister the VEH handler function
	if (GlobalHardwareBreakpointObject.HandlerObject)
		RemoveVectoredExceptionHandler(GlobalHardwareBreakpointObject.HandlerObject);

	// Delete the critical section object
	DeleteCriticalSection(&g_CriticalSection);

	GlobalHardwareBreakpointObject.IsInit = FALSE;

	return TRUE;
}


//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//				ExceptionHandlerCallbackRoutine : PRIVATE
//
// Veh handler function that handles the hardware breakpoints exception
LONG ExceptionHandlerCallbackRoutine(IN PEXCEPTION_POINTERS ExceptionInfo)
{
	DESCRIPTOR_ENTRY* TempObject = { 0 };
	BOOL				bResolved = FALSE;

	// Check exception code
	if (ExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
		goto EXIT_ROUTINE;

	EnterCriticalSection(&g_CriticalSection);

	TempObject = g_Head;

	while (TempObject != NULL) {

		// Search for the detour function pointer of the breakpoint triggered if the node is not processed yet
		if (TempObject->Address == ExceptionInfo->ContextRecord->Rip && !TempObject->Processed) {

			if (TempObject->ThreadId != 0 && TempObject->ThreadId != _GetCurrentThreadId()) {
				// Set the 'Processed' flag to avoid infinite loop: https://github.com/vxunderground/VX-API/blob/main/VX-API/ExceptHandlerCallbackRoutine.cpp#L19
				// If the 'Processed' is not added to the 'DESCRIPTOR_ENTRY' structure, the 'continue' statement can go back to the 'while' loop with the same 'TempObject' node, creating an infinte loop
				TempObject->Processed = TRUE;
				continue;
			}

			// 1. disable hw breakpoint 
			if (!SetHardwareBreakpoint(_GetCurrentThreadId(), TempObject->Address, TempObject->Drx, FALSE))
				goto EXIT_ROUTINE;

			// 2. execute the callback (detour function)
			VOID(*fnHookFunc)(PCONTEXT) = TempObject->CallbackFunction;
			fnHookFunc(ExceptionInfo->ContextRecord);

			// 3. enable the hw breakpoint again
			if (!SetHardwareBreakpoint(_GetCurrentThreadId(), TempObject->Address, TempObject->Drx, TRUE))
				goto EXIT_ROUTINE;

			// This node is processed
			TempObject->Processed = TRUE;
		}

		// Reset the 'Processed' flag after processing each node
		TempObject->Processed = FALSE;
		// Go to the next node in the linked list
		TempObject = TempObject->Next;
	}

	LeaveCriticalSection(&g_CriticalSection);

	bResolved = TRUE;

EXIT_ROUTINE:

	return (bResolved ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH);
}



//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//					SetHardwareBreakpoint : PRIVATE
// 
// Sets or Removes a hardware breakpoint							\
	* ThreadId	= Thread Identifier to hook								\
	* Address	= Harware breakpoint address (where to install)		\
	* Position	= Can be 0 -> 3, represnting Dr0-Dr3 registers			\
	* Init		= Set(TRUE)/Remove(FALSE) a hardware breakpoint	

BOOL SetHardwareBreakpoint(IN DWORD ThreadId, IN PUINT_VAR_T Address, IN DRX Drx, IN BOOL bInitializeHWBP)
{
	CONTEXT		Context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
	HANDLE		hThread = INVALID_HANDLE_VALUE;
	BOOL		bFlag = FALSE;

	// Open handle to the target thread if it is not the current thread  
	if (ThreadId != _GetCurrentThreadId()) {
		hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);
		if (hThread == NULL)
			goto EXIT_ROUTINE;
	}
	else
		hThread = ((HANDLE)(LONG_PTR)-2);

	// Get local thread context
	if (!GetThreadContext(hThread, &Context))
		goto EXIT_ROUTINE;

	// If install 
	if (bInitializeHWBP) {
		// Sets the value of the Dr0-3 registers 
		(&Context.Dr0)[Drx] = Address;
		// Enable the breakpoint: Populate the G0-3 flags depending on the saved breakpoint position in the Dr0-3 registers
		Context.Dr7 = SetDr7Bits(Context.Dr7, (Drx * 2), 1, 1);
	}
	// If remove
	else {
		// If breakpoint found in the thread context
		if ((&Context.Dr0)[Drx] == Address) {
			// Remove the address of the hooked function from the thread context
			(&Context.Dr0)[Drx] = 0ull;
			// Disabling the hardware breakpoint by setting the target G0-3 flag to zero
			Context.Dr7 = SetDr7Bits(Context.Dr7, (Drx * 2), 1, 0);
		}
	}

	// Set the thread context after editing it
	if (!SetThreadContext(hThread, &Context))
		goto EXIT_ROUTINE;

	bFlag = TRUE;

EXIT_ROUTINE:

	if (hThread)
		CloseHandle(hThread);

	return bFlag;
}


//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//				SnapshotInsertHardwareBreakpointHookIntoTargetThread : PRIVATE
// 
// Used to set/remove hardware breakpoints among all running threads					\
	* Address			= Harware breakpoint address (where to install)					\
	* Position			= Can be 0 -> 3, represnting Dr0-Dr3 registers						\
	* Init				= Set(TRUE)/Remove(FALSE) a hardware breakpoint					\
	* Tid				= Thread Identifier to hook	| 0 to hook all threads					


#define STATUS_SUCCESS              0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef NTSTATUS(WINAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);


BOOL SnapshotInsertHardwareBreakpointHookIntoTargetThread(IN PUINT_VAR_T Address, IN DRX Drx, IN BOOL bInitializeHWBP, IN DWORD ThreadId)
{

	fnNtQuerySystemInformation		pNtQuerySystemInformation = NULL;
	ULONG							uReturnLen1 = NULL,
		uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;
	BOOL							bFlag = FALSE;

	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL)
		goto _EndOfFunc;

	if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH)
		goto _EndOfFunc;

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(_GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL)
		goto _EndOfFunc;

	pValueToFree = SystemProcInfo;

	if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2)) != STATUS_SUCCESS)
		goto _EndOfFunc;

	while (TRUE) {


		if (SystemProcInfo->UniqueProcessId == _GetCurrentProcessId()) {

			PSYSTEM_THREAD_INFORMATION      SystemThreadInfo = (PSYSTEM_THREAD_INFORMATION)SystemProcInfo->Threads;

			for (DWORD i = 0; i < SystemProcInfo->NumberOfThreads; i++) {

				if (ThreadId != ALL_THREADS && ThreadId != SystemThreadInfo[i].ClientId.UniqueThread)
					continue;

				if (!SetHardwareBreakpoint(SystemThreadInfo[i].ClientId.UniqueThread, Address, Drx, bInitializeHWBP))
					goto _EndOfFunc;
			}

			break;
		}

		if (!SystemProcInfo->NextEntryOffset)
			break;

		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	bFlag = TRUE;

_EndOfFunc:
	if (pValueToFree)
		HeapFree(_GetProcessHeap(), 0, pValueToFree);
	return bFlag;
}


//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//				InstallHardwareBreakingPntHook & RemoveHardwareBreakingPntHook : PUBLIC
//
// Install hook on a specified address														\
	* Address			= Harware breakpoint address (where to install)					\
	* Drx				= Can be Dr0 -> Dr3													\
	* CallbackRoutine	= Pointer to the detour function 									\
	* ThreadId			= Thread identifier to hook	| 'ALL_THREADS' to hook all threads

BOOL InstallHardwareBreakingPntHook(IN PUINT_VAR_T Address, IN DRX Drx, IN PVOID CallbackRoutine, IN DWORD ThreadId)
{
	DESCRIPTOR_ENTRY* NewEntry = NULL;

	NewEntry = (DESCRIPTOR_ENTRY*)HeapAlloc(_GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DESCRIPTOR_ENTRY));
	if (NewEntry == NULL)
		return FALSE;

	EnterCriticalSection(&g_CriticalSection);

	NewEntry->Address = Address;
	NewEntry->Drx = Drx;
	NewEntry->ThreadId = ThreadId;
	NewEntry->CallbackFunction = CallbackRoutine;
	NewEntry->Next = g_Head;
	NewEntry->Previous = NULL;

	if (g_Head != NULL)
		g_Head->Previous = NewEntry;

	g_Head = NewEntry;

	LeaveCriticalSection(&g_CriticalSection);

	return SnapshotInsertHardwareBreakpointHookIntoTargetThread(Address, Drx, TRUE, ThreadId);
}


// Remove hook on a specified address														\
	* Address			= Harware breakpoint address (where to unhook)					\
	* ThreadId			= Thread identifier to unhook | 'ALL_THREADS' to remove hook from all threads
BOOL RemoveHardwareBreakingPntHook(IN PUINT_VAR_T Address, IN DWORD ThreadId)
{
	DESCRIPTOR_ENTRY* TempObject = NULL;
	enum DRX			Drx = -1;
	BOOL				bFlag = FALSE,
		Found = FALSE;

	EnterCriticalSection(&g_CriticalSection);

	TempObject = g_Head;

	while (TempObject != NULL)
	{
		if (TempObject->Address == Address && TempObject->ThreadId == ThreadId)
		{
			Found = TRUE;

			Drx = TempObject->Drx;

			if (g_Head == TempObject)
				g_Head = TempObject->Next;

			if (TempObject->Next != NULL)
				TempObject->Next->Previous = TempObject->Previous;

			if (TempObject->Previous != NULL)
				TempObject->Previous->Next = TempObject->Next;

			//if (TempObject)
			//	HeapFree(_GetProcessHeap(), HEAP_ZERO_MEMORY, TempObject);
		}

		if (TempObject)
			TempObject = TempObject->Next;
	}

	LeaveCriticalSection(&g_CriticalSection);

	if (Found)
		bFlag = SnapshotInsertHardwareBreakpointHookIntoTargetThread(Address, Drx, FALSE, ThreadId);

	return bFlag;
}



//------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------
//								IMPLEMENTATION TO HOOK NEW THREADS : PRIVATE


#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED	0x00000001

PVOID		g_pNtCreateThreadEx = NULL;


// https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms687066(v=vs.85)
VOID CALLBACK TimedHookCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired) {

	// 4. Wait for NtCreateThreadEx to return a HANDLE
	HANDLE hThread = (HANDLE)(*(HANDLE*)lpParameter);
	while (!hThread) {
	}

	EnterCriticalSection(&g_CriticalSection);

	// 5. Search for hooks that should be installed on all threads, and copy them to the new thread as well
	DESCRIPTOR_ENTRY* TempObject = g_Head;
	INT					i = 0;

	while (TempObject != NULL) {

		if (TempObject->Address && TempObject->CallbackFunction && TempObject->ThreadId == ALL_THREADS) {
			// 6. Install the hooks that should be set for all threads
			InstallHardwareBreakingPntHook(TempObject->Address, TempObject->Drx, TempObject->CallbackFunction, GetThreadId(hThread));
			i++;
		}

		// Used to get the first four 'ALL_THREADS' hooks 
		if (i == 4)
			break;

		TempObject = TempObject->Next;
	}

	LeaveCriticalSection(&g_CriticalSection);

	// 7. Resume thread
	ResumeThread(hThread);
}


VOID NtCreateThreadExDetour(PCONTEXT Ctx) {

	// 0. Get the pointer to the thread handle
	PHANDLE pThread = (PHANDLE)GETPARM_1(Ctx);

	// 1. Modify the 'Flags' parameter to create the thread suspended
	ULONG uNewFalg = GETPARM_7(Ctx);
	uNewFalg = uNewFalg | THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
	SETPARM_7(Ctx, uNewFalg);

	// 2. Execute the hook as a callback function
	HANDLE hTimer = INVALID_HANDLE_VALUE;
	CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)TimedHookCallback, pThread, 0, 0, 0);

	// 3. Execute the original thread
	CONTINUE_EXECUTION(Ctx);
}


//------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------
//								IMPLEMENTATION TO HOOK NEW THREADS : PUBLIC

BOOL InstallHooksOnNewThreads(IN DRX Drx) {

	// Install a hook on NtCreateThreadEx, executing the NtCreateThreadExCallback detour function
	g_pNtCreateThreadEx = (PVOID)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtCreateThreadEx");
	if (!g_pNtCreateThreadEx)
		return FALSE;

	return InstallHardwareBreakingPntHook(g_pNtCreateThreadEx, Drx, NtCreateThreadExDetour, ALL_THREADS);
}


BOOL RemoveHooksOnNewThreads() {
	// Remove the NtCreateThreadEx hook from all the threads
	return RemoveHardwareBreakingPntHook(g_pNtCreateThreadEx, ALL_THREADS);
}


//------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------

