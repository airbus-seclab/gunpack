#include "win_kernl.h"
#include "utils.h"
#include "exceptions_list.h"
#include "exceptions_hook.h"
#include "memory_state.h"
#include "syscall_hook.h"

#define MAX_ACCESS_ARRAY_SIZE 512
#define SLOT_USED 1
#define SLOT_FREE 0 

typedef struct{
	HANDLE OwningThread;
	PVOID AccessedAddress;
	ULONG State;
} KernelSingleStepAccess;

typedef struct{
	HANDLE OwningThread;
	ULONG State;
} UserSingleStepAccess;

KernelSingleStepAccess	KernelAccessArray[MAX_ACCESS_ARRAY_SIZE];
UserSingleStepAccess	UserAccessArray[MAX_ACCESS_ARRAY_SIZE];


unsigned int first_exception_in_process;
void ** ServiceTable;
extern int do_log;
extern unsigned int TargetPid;
extern HANDLE TargetProcessHandle;
extern proto_MiCopyOnWrite MiCopyOnWrite;
extern PLDR_DATA_TABLE_ENTRY * LdrpCurrentDllInitializer;
extern PRTL_CRITICAL_SECTION LdrpLoaderLock;
extern HANDLE hUserlandPipe;
extern HANDLE hPipeEvent;
extern ULONG_PTR * MmUserProbeAddress;
extern ULONG MmProtectValues[32];
extern proto_MiQueryAddressState MiQueryAddressState;
extern proto_MmAccessFault MmAccessFault;
extern ULONG_PTR ProgramOep;
extern int log_exceptions;
unsigned char * call_to_MmAccessFault = NULL;

proto_KeContextFromKframes KeContextFromKframes = NULL;
unsigned char * KiDispatchException_continue = NULL;
unsigned char * call_to_KeContextFromKframes = NULL;
unsigned char * KiDispatchException_end = NULL;

//extern MiProtectVirtualMemory_proto MiProtectVirtualMemory;
extern proto_NtProtectVirtualMemory NtProtectVirtualMemory;

void InitAccessArray()
{
	memset(KernelAccessArray,0,sizeof(KernelAccessArray));
	memset(UserAccessArray,0,sizeof(UserAccessArray));
}


int IsThreadSingleStepped(HANDLE OwningThread)
{
	ULONG i;
	for (i = 0; i < MAX_ACCESS_ARRAY_SIZE; i++)
	{
		if ( (UserAccessArray[i].State == SLOT_USED) && (UserAccessArray[i].OwningThread == OwningThread) )
		{
			UserAccessArray[i].OwningThread = NULL;
			UserAccessArray[i].State = SLOT_FREE;
			return 1;
		}
	}
	
	return 0;	
}

int AddSingleStepThread(HANDLE OwningThread)
{
	ULONG i;
	
	for (i = 0; i < MAX_ACCESS_ARRAY_SIZE; i++)
	{
		if ( UserAccessArray[i].State == SLOT_FREE )
		{
			UserAccessArray[i].State = SLOT_USED;
			UserAccessArray[i].OwningThread = OwningThread;
		
			return 1;
		}
	}
	
	return 0;
}

PVOID GetAccessAddressOfThread(HANDLE OwningThread)
{
	ULONG i;
	PVOID AccessedAddress;
	
	for (i = 0; i < MAX_ACCESS_ARRAY_SIZE; i++)
	{
		if ( (KernelAccessArray[i].State == SLOT_USED) && (KernelAccessArray[i].OwningThread == OwningThread) )
		{
			AccessedAddress = KernelAccessArray[i].AccessedAddress;
			KernelAccessArray[i].AccessedAddress = NULL;
			KernelAccessArray[i].State = SLOT_FREE;
			return AccessedAddress;
		}
	}
	
	return NULL;
}

int AddAccessAddress(HANDLE OwningThread, PVOID AccessedAddress)
{
	ULONG i;
	
	for (i = 0; i < MAX_ACCESS_ARRAY_SIZE; i++)
	{
		if ( KernelAccessArray[i].State == SLOT_FREE )
		{
			KernelAccessArray[i].State = SLOT_USED;
			KernelAccessArray[i].OwningThread = OwningThread;
			KernelAccessArray[i].AccessedAddress = AccessedAddress;
			
			return 1;
		}
	}
	
	return 0;
}

ULONG RetrieveEspTop(ULONG * pEsp)
{
	try
	{
		ProbeForRead(pEsp,sizeof(ULONG),1);
		
		return *pEsp;
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		return 0;
	}
}

void RetrieveExceptionInfo(PEXCEPTION_INFO pExceptionInfo, ULONG AccessViolationType,PVOID AccessedAddress, PKTRAP_FRAME pTrap)
{
	PLDR_DATA_TABLE_ENTRY pEntry;
	PTE * ppte_virtual = NULL;
	
	if( !LdrpLoaderLock )
	{
		pdebug(do_log,"[RetrieveExceptionInfo] LdrpLoaderLock is null\n");
		return;
	}
	
	if (! LdrpCurrentDllInitializer )
	{
		pdebug(do_log,"[RetrieveExceptionInfo] LdrpCurrentDllInitializer is null\n");
		return;
	}
	
	try
	{
		ProbeForRead(LdrpLoaderLock,sizeof(LdrpLoaderLock),4);
		ProbeForRead(LdrpCurrentDllInitializer,sizeof(LdrpCurrentDllInitializer),4);
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		return;
	}
	
	memset(pExceptionInfo,0,sizeof(EXCEPTION_INFO));
	
	//Retrieve the loader current entry from userland
	pEntry = *LdrpCurrentDllInitializer;
	//
	pExceptionInfo->AccessType = AccessViolationType;
	pExceptionInfo->AccessedAddress = AccessedAddress;
	pExceptionInfo->LockCount = LdrpLoaderLock->LockCount;
	pExceptionInfo->RecursionCount = LdrpLoaderLock->RecursionCount;
	pExceptionInfo->OwningThread = LdrpLoaderLock->OwningThread;
	pExceptionInfo->CurrentThread = PsGetCurrentThreadId();
	pExceptionInfo->Esp = pTrap->HardwareEsp;
	pExceptionInfo->Esp_top_value = RetrieveEspTop((ULONG *)pTrap->HardwareEsp);
		
	ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS((DWORD_PTR)AccessedAddress);
	if (ppte_virtual->pte.present)
	{
		pExceptionInfo->PhysicalAddress = (ppte_virtual->pte.address << 0xC) + ((DWORD_PTR)AccessedAddress & 0xFFF);
		pdebug(do_log,"[RetrieveExceptionInfo] Pte present, physical : 0x%x\n",ppte_virtual->pte.address);
	}
	else
	{
		pdebug(do_log,"[RetrieveExceptionInfo] Pte not present\n");
		pExceptionInfo->PhysicalAddress = 0xffffffffffffffff;
	}
	
	if (pEntry)
	{
		ULONG CopySize;
		
		pdebug(do_log,"[RetrieveExceptionInfo] DllBase : %p\n", pEntry->DllBase);
		pdebug(do_log,"[RetrieveExceptionInfo] BaseDllName : %S\n", pEntry->BaseDllName.Buffer);
		pdebug(do_log,"[RetrieveExceptionInfo] FullDllName : %S\n", pEntry->FullDllName.Buffer);
		
		pExceptionInfo->InDllLoad = 1;
		
		CopySize = min( MAX_PATH*sizeof(USHORT), pEntry->FullDllName.Length*sizeof(USHORT) );
		
		try
		{
			ProbeForRead(pEntry->FullDllName.Buffer,CopySize,1);
			memcpy(&pExceptionInfo->DllName,pEntry->FullDllName.Buffer ,CopySize);		
		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			return;
		}
		
	}
	else
	{
		pExceptionInfo->InDllLoad = 0;
	}
}

int TreatKernellandException(ULONG_PTR ExceptionCode,ULONG_PTR AccessViolationType,ULONG_PTR AccessedAddress, PKTRAP_FRAME pTrap)
{
	NTSTATUS r;
	PVOID LastAccessedAddress = NULL;
	
	//Handle single-step exceptions
	if ( ExceptionCode == STATUS_SINGLE_STEP )
	{
		LastAccessedAddress = GetAccessAddressOfThread(PsGetCurrentThreadId());
		if(!LastAccessedAddress)
		{
			pdebug(do_log,"[TreatKernellandException] Oops GetAccessAddressOfThread failed !\n");
		}
		
		//Set page !WRITE & EXEC
		r = SetMemoryProtectionPae2( (ULONG_PTR)LastAccessedAddress, 0, 1 );
		pTrap->EFlags &= 0xFEFF;
		return 1;
	}

	//If eip and accessed address are in the same page
	if ( (AccessViolationType == WRITE_ACCESS) )
	{
		if( !AddAccessAddress(PsGetCurrentThreadId(),(PVOID)AccessedAddress))
		{
			pdebug(do_log,"[TreatKernellandException] Oops AddAccessAddress failed !\n");
		}
		
		SetMemoryProtectionPae2( AccessedAddress, 1, 0 );
		pTrap->EFlags |= 0x0100;
		return 1;
	}
	
	return 0;
}

int __stdcall do_exception_filter(PEXCEPTION_RECORD pExp, void * pKexp, PKTRAP_FRAME pTrap, int PreviousMode, int FirstChance)
{
	//ULONG_PTR AccessedAddress;
	unsigned int current_pid;
	int i;
	unsigned int * p;
	int result = 0;
	PVOID LastAccessedAddress;

	//
	// We catch only first chance exceptions
	//
	if ( !FirstChance )
		return result;
		
	//
	// Ensure that pExp and pTrap are both not null
	//
	if ( !pExp )
		return result;
	
	if ( !pTrap )
		return result;
		
	//
	// Ensure we are on the right process
	//
	current_pid = (unsigned int)PsGetCurrentProcessId();
	if( current_pid != TargetPid )
		return result;
		
	
	//
	// We are only interested in STATUS_SINGLE_STEP exceptions caused by the
	//
	if ( pExp->ExceptionCode == STATUS_SINGLE_STEP )
	{

		if (  pTrap->Eip < *MmUserProbeAddress )
		{
			//Ensure the single-step was induced by our driver and not by the process itself
			if ( IsThreadSingleStepped(PsGetCurrentThreadId()) )
			{
				pdebug(do_log,"[do_exception_filter] SINGLE_STEP in userland, Eip = 0x%x\n",pTrap->Eip);
				//
				// Set page protection back to EXECUTE and not(WRITE)
				//
				if (SetMemoryProtectionPae2(pTrap->Eip, 0, 1))
				{
					pdebug(do_log,"[do_exception_filter] Unactivate single-step\n");
					pTrap->EFlags &= 0xFEFF;
					return 1;
				}
			}
			else
			{
				pdebug(do_log,"[do_exception_filter] Not our SINGLE_STEP in userland, Eip = 0x%x\n",pTrap->Eip);
			}
		}
		else
		{
			pdebug(do_log,"[do_exception_filter] SINGLE_STEP in kernelland, Eip = 0x%x\n",pTrap->Eip);
			
			result = TreatKernellandException(STATUS_SINGLE_STEP,0,0,pTrap);
		}
	}
	
	return result;
}

/*
	IsARealFault determines if the fault generated is a "real" fault in the monitored program
	or a fault induced by our PTE modifications.
*/
int IsARealFault(ULONG_PTR FaultStatus, ULONG_PTR FaultAddress)
{
	PMMVAD VadRoot, FaultingVad;
	ULONG Protect;
	int result = 1;	
	
	Protect = GetVadMemoryProtect(FaultAddress);
	if (Protect == 0)
	{
		pdebug(do_log,"[IsARealFault] GetVadMemoryProtect failed! Returning true.\n");
		return 1;
	}
	
	if ( ShouldItFault(FaultStatus, Protect) )
	{
		result = 1;
	}
	else
		result = 0;
		
	pdebug(do_log,"[IsARealFault] ShouldItFault returned %d\n",result);
	pdebug(do_log,"[IsARealFault] FaultStatus %d, Protect : 0x%x\n",FaultStatus,Protect);
	
	return result;
}

//
// Triggers copy on write at page level on a page that needs it.
// 
void HandleCopyOnWrite(ULONG BaseAddress)
{
	PMMVAD VadRoot, CurrentVad;
	ULONG Protect, ReturnedProtect;
	PTE * ppte_virtual = NULL;
	int r;
	PVOID NextVa;
	
	VadRoot = (PMMVAD)GetVadRoot(PsGetCurrentProcess());	

	pdebug(do_log,"[HandleCopyOnWrite] Vad root : 0x%x\n",VadRoot);	
	
	CurrentVad = LocateVadForPage(VadRoot, (ULONG)BaseAddress >> 0xC);
	if (!CurrentVad)
	{
		pdebug(do_log,"[HandleCopyOnWrite] No vad found !!\n");
		return;
	}
	
	Protect = MmProtectValues[CurrentVad->u.Protection];
	pdebug(do_log,"[HandleCopyOnWrite] Page 0x%x is at protect : 0x%x\n",BaseAddress,Protect);
	
	if ( (Protect & PAGE_WRITECOPY) || (Protect & PAGE_EXECUTE_WRITECOPY)  )
	{
		pdebug(do_log,"[HandleCopyOnWrite] Page 0x%x needs copy on write\n",BaseAddress);
			
		ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(BaseAddress);
		
		if ( ppte_virtual->raw.LowPart == 0 )
		{
			pdebug(do_log,"[HandleCopyOnWrite] PTE is NULL\n");
			MmAccessFault(FALSE, (PVOID)BaseAddress, UserMode, NULL);
		}
		
		if ( ppte_virtual->pte.present == 0 )
		{
			pdebug(do_log,"[HandleCopyOnWrite] PTE is not present\n");
			return;		
		}
		
		if ( (ppte_virtual->pte.d) || (ppte_virtual->pte.reserved) )
		{
			pdebug(do_log,"[HandleCopyOnWrite] PTE is already copy on write !\n");
			return;
		}
		
		if ( ppte_virtual->pte.present )
		{
			pdebug(do_log,"[HandleCopyOnWrite] chatte !\n");
			
			r = MiCopyOnWrite((PVOID)BaseAddress ,ppte_virtual);
			pdebug(do_log,"r = %d\n",r);

		}
		else
			pdebug(do_log,"[HandleCopyOnWrite] pas chatte !\n");		
	}
	
	return;
}

void DisplayPTE(ULONG_PTR Page)
{
	PTE * ppte_virtual = NULL;

	// We hope pte virtual address is mapped...
	// We're feeling lucky
	ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(Page);
	
	pdebug(do_log,"[DisplayPTE] PTE High = 0x%x, Low = 0x%x\n",ppte_virtual->raw.HighPart, ppte_virtual->raw.LowPart);
}


NTSTATUS NTAPI HookInMmAccessFault(ULONG_PTR FaultStatus,PVOID VirtualAddress,KPROCESSOR_MODE PreviousMode,PKTRAP_FRAME pTrap)
{
	unsigned int current_pid;
	NTSTATUS result;
	ULONG VadProtect;
	PTE * ppte_virtual;
	
	ULONG_PTR AccessedAddress = (ULONG_PTR)VirtualAddress;
	EXCEPTION_INFO CurrentException;
	
	PTE * pTrackedAddress;	
	
	if (!pTrap)
		goto regular_treatment;

	//
	// Ensure we are on the right process
	//
	current_pid = (unsigned int)PsGetCurrentProcessId();
	if( current_pid != TargetPid )
		goto regular_treatment;	

	//
	// TODO : try to do this somewhere else
	// We change the process protection to execute only on the very first exception of the process
	//
	if (first_exception_in_process)
	{
		PMMVAD VadRoot;
		
		first_exception_in_process = 0;
		ClearTrackedPages();
		VadRoot = (PMMVAD)GetVadRoot( PsGetCurrentProcess() );
		ParseProcessVad(VadRoot);		
	}
	
	pdebug(do_log,"[HookInMmAccessFault] VirtualAddress = 0x%x, FaultStatus : 0x%x\n",VirtualAddress, FaultStatus);
	
	// 
	// Access faults on read instructions are not handled, we pass it to MmAccessFault right away
	// 
	if ( (FaultStatus == READ_ACCESS) )
		goto regular_treatment;
	
	// 
	// Never modify kernel virtual address space
	// 
	if ( AccessedAddress >= *MmUserProbeAddress )
		goto regular_treatment;
	
	//Search for expected OEP
	if (pTrap->Eip == ProgramOep)
	{
		pdebug(do_log,"[HookInMmAccessFault] Program Oep reached, calling NtTerminateProcess\n");

		//Add exception info to the list to let the userland program know we reached the Oep
		RetrieveExceptionInfo(&CurrentException,FaultStatus,(PVOID)AccessedAddress, pTrap);
		
		AddExceptionToList(&CurrentException);			
		
		//our event will be raised and current thread will be suspended
		NtTerminateProcess_hook((HANDLE)-1,0);
	}
	
	ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS((ULONG_PTR)VirtualAddress);
	
	//If page not tracked we exit
	if ( IsTrackedPage((ULONG_PTR)VirtualAddress) == 0 )
	{
		pdebug(do_log,"[HookInMmAccessFault] Page not tracked, regular treatment\n");
		goto regular_treatment;
	}
	
	if ( IsARealFault(FaultStatus,AccessedAddress) )
	{
		pdebug(do_log,"real fault at 0x%x\n",AccessedAddress);
		pdebug(do_log,"returning STATUS_ACCESS_VIOLATION\n");
		return STATUS_ACCESS_VIOLATION;
	}
	
	pdebug(do_log,"[HookInMmAccessFault] Treating exception on tracked page\n");
	
	//Userland exception
	if ( pTrap->Eip <= *MmUserProbeAddress )
	{
		//
		// Retrieve information about the loader in the EXCEPTION_INFO structure and add it to the list
		//	
		RetrieveExceptionInfo(&CurrentException,FaultStatus,(PVOID)AccessedAddress, pTrap);
		
		if (log_exceptions)
			AddExceptionToList(&CurrentException);	
	
		//
		// If Eip and AccessedAddress are in the same page (TODO change variable name) then enable SINGLE STEP
		// and set page rights to EXECUTE and WRITE
		if (  (FaultStatus == WRITE_ACCESS) && ((pTrap->Eip & 0xFFFFF000) == (AccessedAddress & 0xFFFFF000)) )
		{
			//Set memory protection to both writable and executable
			SetMemoryProtectionPae2(AccessedAddress, 1, 1);
		
			pdebug(do_log,"[HookInMmAccessFault] Activate single-step\n");
			
			//Remember that there is a pending single-step on this userland thread
			AddSingleStepThread(PsGetCurrentThreadId());
			
			//Activate single-step of userland process
			pTrap->EFlags |= 0x100;
			
			//resume process execution
			return STATUS_SUCCESS;
		}

		//
		// If fault on write access on memory, change its PTE to make it writable but not executable
		// If fault on execute access do the opposite
		//
		if ( FaultStatus == WRITE_ACCESS )
		{
			SetMemoryProtectionPae2((ULONG)AccessedAddress,1,0 );
		}
		else if ( FaultStatus == EXECUTE_ACCESS )
		{
			SetMemoryProtectionPae2((ULONG)AccessedAddress,0,1 );		
		}
		else
			pdebug(do_log,"[HookInMmAccessFault] WTF ???!!\n");
	}
	else
	{
		pdebug(do_log,"[HookInMmAccessFault] kernelland exception, eip = 0x%x\n, AccessedAddress = 0x%x\n", pTrap->Eip, AccessedAddress );
		
		TreatKernellandException(0,FaultStatus,AccessedAddress,pTrap);
	}
	
	//
	// Resume thread's execution without going through exception handling 
	//
	return STATUS_SUCCESS;
	
regular_treatment:

	return MmAccessFault(FaultStatus, VirtualAddress, PreviousMode, pTrap);
}

//Low level hook of kernel exception dispatcher
void __declspec(naked) HookInKiDispatchException()
{
	__asm{
		push    dword ptr [ebp+18h] ; FirstChance
		push    dword ptr [ebp+14h] ; PreviousMode
		push    dword ptr [ebp+10h] ; PKTRAP_FRAME
		push    dword ptr [ebp+0Ch] ; pKexp
		push    dword ptr [ebp+8] ; PEXCEPTION_RECORD
		call do_exception_filter
		test eax,eax
		//if eax == 0 the exception was not catched by our driver
		//therefore exception handling flow must continue
		je Unhandled_exception
		//If we handled the exception, we jump directly to the end of the exception handler.
		//The kernel will then restore userland thread context using the KTRAP_FRAME structure
		//we have modified
		jmp dword ptr[KiDispatchException_end]
		
	Unhandled_exception:
		//Parameters of KeContextFromKframes are already on the stack at the beginning of HookInKiDispatchException.
		//No need to push them twice.
		call dword ptr[KeContextFromKframes]
		jmp dword ptr[KiDispatchException_continue]
	};
}

int UnHookExceptionDispatcher()
{
	disable_cr0();
	PatchBranch(CALL,call_to_KeContextFromKframes,(unsigned char *)KeContextFromKframes);
	enable_cr0();
	
	return 1;
}

int UnHookKiTrap0E()
{
	disable_cr0();
	PatchBranch(CALL,call_to_MmAccessFault,(unsigned char *)MmAccessFault);
	enable_cr0();
	
	return 1;
}

int HookKiTrap0E(PVOID KernelImageBase, ULONG KernelImageSize)
{
	unsigned char before_MmAccessFaultCall[] =   {0x55,0x8B,0x45,0x6C,0x83,0xE0,0x01,0x50,0x57,0x8B,0x00,0x64,0xD1,0x00,0x23,0x00};
	
	call_to_MmAccessFault = FindSignatureWithHoles(KernelImageBase,KernelImageSize,before_MmAccessFaultCall,sizeof(before_MmAccessFaultCall));
	if (!call_to_MmAccessFault)
	{
		pdebug(do_log,"[HookKiTrap0E] Error : unable to find before_MmAccessFaultCall\n");
		return 0;
	}
	
	//There's a delta because the kernel uses a global variable which my be relocated
	call_to_MmAccessFault += (5 + sizeof(before_MmAccessFaultCall));
	
	pdebug(do_log,"[HookKiTrap0E] call_to_MmAccessFault : 0x%x\n",call_to_MmAccessFault);
	
	//Compute the MmAccessFault address
	MmAccessFault = (proto_MmAccessFault)ComputeBranchAddress(call_to_MmAccessFault);
	if(!MmAccessFault)
	{
		return 0;
	}	

	pdebug(do_log,"[HookKiTrap0E] MmAccessFault : 0x%x\n",MmAccessFault);
		
	disable_cr0();
	PatchBranch(CALL,call_to_MmAccessFault,(unsigned char *)HookInMmAccessFault);
	enable_cr0();		
		
		
	return 1;
}

int HookExceptionDispatcher(PVOID KernelImageBase, ULONG KernelImageSize)
{
	unsigned char * r = NULL;
	unsigned char inside_KiDispatchException_signature[] = {0x89,0x65,0xE8,0x8B,0xFC,0x89,0x7D,0xBC,0x8D,0x45,0xD8,0x50};
	unsigned char endof_KiDispatchException_signature[] = {0x8D,0xA5,0xE8,0xFE,0xFF,0xFF};
	unsigned char before_KeContextFromKframes_call_signature[] = {0x57,0xFF,0x75,0x0C,0xFF,0x75,0x10};
		
	r = FindSignature(KernelImageBase,KernelImageSize,inside_KiDispatchException_signature,sizeof(inside_KiDispatchException_signature));
	if (!r)
	{
		pdebug(do_log,"[HookExceptionDispatcher] Error : unable to find inside_KiDispatchException_signature\n");		
		return 0;
	}
	
	KiDispatchException_end = FindSignature((void *)r,0x1000,endof_KiDispatchException_signature,sizeof(endof_KiDispatchException_signature));
	if(!KiDispatchException_end)
	{
		pdebug(do_log,"[HookExceptionDispatcher] Error : unable to find endof_KiDispatchException_signature\n");
		return 0;
	}
	
	call_to_KeContextFromKframes = FindSignature((void *)r,0x1000,before_KeContextFromKframes_call_signature,sizeof(before_KeContextFromKframes_call_signature));
	if(!call_to_KeContextFromKframes)
	{
		pdebug(do_log,"[HookExceptionDispatcher] Error : unable to find before_KeContextFromKframes_call_signature\n");
		return 0;
	}
	
	//switch to the call
	call_to_KeContextFromKframes += sizeof(before_KeContextFromKframes_call_signature);
	
	//The KiDispatchException_continue is located at the return of the call
	KiDispatchException_continue = call_to_KeContextFromKframes + 5;
	
	//Compute the KeContextFromKframes address
	KeContextFromKframes = (proto_KeContextFromKframes)ComputeBranchAddress(call_to_KeContextFromKframes);
	if(!KeContextFromKframes)
	{
		return 0;
	}
	
	pdebug(do_log,"[HookExceptionDispatcher] KeContextFromKframes =  0x%p\n",KeContextFromKframes);	
	pdebug(do_log,"[HookExceptionDispatcher] KiDispatchException_end =  0x%p\n",KiDispatchException_end);
	pdebug(do_log,"[HookExceptionDispatcher] KiDispatchException_continue =  0x%p\n",KiDispatchException_continue);
	
	disable_cr0();
	PatchBranch(JMP_FAR,call_to_KeContextFromKframes,(unsigned char *)HookInKiDispatchException);
	enable_cr0();
	
	return 1;
}