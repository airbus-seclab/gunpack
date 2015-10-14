#include "win_kernl.h"
#include "memory_state.h"
#include "utils.h"

extern unsigned int TargetPid;
extern proto_NtAllocateVirtualMemory NtAllocateVirtualMemory;
extern int do_log;

NTSTATUS NTAPI NtAllocateVirtualMemory_hook(HANDLE ProcessHandle, PVOID * BaseAddress, ULONG ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect)
{
	NTSTATUS result,r;
	HANDLE Pid = NULL;
	KAPC_STATE ApcState;
	PVOID LocalBaseAddress = NULL;
	ULONG LocalRegionSize = 0;
	PMYEPROCESS pProc = NULL;
	//int AttachedToPorcess = 0;
	int take_hook = 0;

	//first we do regular allocation
	result = NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	if (result != STATUS_SUCCESS)
		return result;
	
	//Reference target process kernel object
	r = ObReferenceObjectByHandle(ProcessHandle,PROCESS_ALL_ACCESS,*PsProcessType,UserMode,(PVOID)&pProc,NULL);
	if( r == STATUS_SUCCESS )
	{
		if (  ((HANDLE)pProc->UniqueProcessId == (HANDLE)TargetPid) && ( PsGetCurrentProcessId() == (HANDLE)TargetPid) )
			take_hook = 1;
		
		ObDereferenceObject(pProc);
		pProc = NULL;
	}
	
	if (take_hook)
	{
		//It is safe to dereference those userland pointers since we already called NtAllocateVirtualMemory
		LocalBaseAddress = *BaseAddress;
		LocalRegionSize = *RegionSize;
		
		pdebug(do_log,"[NtAllocateVirtualMemory_hook] BaseAddress :: 0x%x, RegionSize : 0x%x,  AllocationType : 0x%x, Protect 0x%x\n", LocalBaseAddress, LocalRegionSize, AllocationType, Protect);
		
		//Change memory protection on page that are commited and not page guards
		if ( (AllocationType & MEM_COMMIT) && ( !(Protect & PAGE_GUARD) ) )
		{
			ProtectExecutablePTEs((ULONG_PTR)LocalBaseAddress,LocalRegionSize);
		}
	}
	
	return result;
}