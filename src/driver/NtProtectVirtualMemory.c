#include "win_kernl.h"
#include "memory_state.h"
#include "utils.h"

extern unsigned int TargetPid;
extern proto_NtProtectVirtualMemory NtProtectVirtualMemory;
extern ULONG_PTR * MmUserProbeAddress;
extern int do_log;

NTSTATUS NTAPI NtProtectVirtualMemory_hook(HANDLE ProcessHandle, PVOID * BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
{
	NTSTATUS result = STATUS_UNSUCCESSFUL, r = STATUS_UNSUCCESSFUL;
	ULONG i = 0, NumberOfPages = 0;
	ULONG_PTR CurrentPage = 0;
	unsigned int Writable = 0, Executable = 0;
	PKTHREAD pCurrentThread = NULL;
	PTE * ppte_virtual = NULL;
	PEPROCESS pProc = NULL;	
	ULONG * PteArray = NULL;
	int take_hook = 0;
	PVOID InputBaseAddress;
	PMMVAD CurrentVad;
	
	//Try to sanitize input variables
	//If smething goes wrong, call the original syscall and exit
	try
	{
		ProbeForRead(BaseAddress,sizeof(BaseAddress),1);
		ProbeForRead(NumberOfBytesToProtect,sizeof(NumberOfBytesToProtect),1);
		
		InputBaseAddress = *BaseAddress;
		
		if ( (*NumberOfBytesToProtect % PAGE_SIZE) == 0 )
		{
			NumberOfPages = *NumberOfBytesToProtect >> 0xC;
		}
		else
		{
			NumberOfPages = (*NumberOfBytesToProtect >> 0xC) + 1;
		}		
		
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		pdebug(do_log,"NtProtectVirtualMemory error sanitizing inputs\n");
		goto error_normal_exec;
	}	
	
	//Don't try to mess with kernel memory
	if ( (ULONG_PTR)InputBaseAddress > (ULONG_PTR)*MmUserProbeAddress )
	{
		pdebug(do_log,"NtProtectVirtualMemory error sanitizing inputs\n");
		goto error_normal_exec;
	}
	
	//Reference target process kernel object
	r = ObReferenceObjectByHandle(ProcessHandle,PROCESS_ALL_ACCESS,*PsProcessType,UserMode,(PVOID)&pProc,NULL);
	if( r == STATUS_SUCCESS )
	{
		if (  ((HANDLE)pProc->UniqueProcessId == (HANDLE)TargetPid) && ( PsGetCurrentProcessId() == (HANDLE)TargetPid) )
			take_hook = 1;
		
		ObDereferenceObject(pProc);
		pProc = NULL;
	}

	if (!take_hook)
	{
		goto error_normal_exec;
	}
	else
	{
		pdebug(do_log,"[NtProtectVirtualMemory_hook] InputAddress : 0x%x, NumberOfPages : 0x%x, NewAccessProtection : 0x%x\n",InputBaseAddress,NumberOfPages,NewAccessProtection);
		
		CurrentVad = LocateVadForPage(GetVadRoot(PsGetCurrentProcess()), (ULONG)InputBaseAddress >> 0xC);
		if(!CurrentVad)
		{
			pdebug(do_log,"[NtProtectVirtualMemory_hook] Vad of starting address not found !");
			goto error_normal_exec;
		}
		
		if ( (((ULONG)InputBaseAddress >> 0xC) + NumberOfPages ) < NumberOfPages )
		{
			pdebug(do_log,"[NtProtectVirtualMemory_hook] overflow. A = 0x%x, Sum = 0x%x, N = 0x%x!",(ULONG)InputBaseAddress >> 0xC,((ULONG)InputBaseAddress >> 0xC) + NumberOfPages, NumberOfPages );
			goto error_normal_exec;
		}
		
		//Check that the protected memory range is contained within a single vad.
		//If it is not NtProtectVirtualMemory system call would fail anyway
		if ( (((ULONG)InputBaseAddress >> 0xC) + NumberOfPages ) > (CurrentVad->EndingVpn +1) )
		{
			pdebug(do_log,"[NtProtectVirtualMemory_hook] Memory range does not fit in a vad !");
			goto error_normal_exec;
		}
		
		//Allocate an array for PTEs
		PteArray = ExAllocatePoolWithTag(NonPagedPool, NumberOfPages*sizeof(ULONG), 0x31333337);
		if (!PteArray)
		{
			pdebug(do_log,"[NtProtectVirtualMemory_hook] not enough memory!\n");
			return 0xC0000001;
		}
		
		memset(PteArray,NumberOfPages*sizeof(ULONG),0);
		
		for (i = 0; i < NumberOfPages; i++ )
		{
			CurrentPage = (ULONG_PTR)InputBaseAddress+i*PAGE_SIZE;
			ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(CurrentPage);
			
			pdebug(do_log,"[NtProtectVirtualMemory_hook] page : 0x%x, before 0x%x 0x%x\n",CurrentPage,ppte_virtual->raw.HighPart,ppte_virtual->raw.LowPart);
			
			if (( ppte_virtual->pte.present ) && ( IsTrackedPage(CurrentPage)  ) )
			{
				pdebug(do_log,"[NtProtectVirtualMemory_hook] tracked\n");
				GetMemoryProtectionPae(CurrentPage,&Writable,&Executable);
				
				pdebug(do_log,"[NtProtectVirtualMemory_hook] Writable : %d, Executable %d\n",Writable,Executable);

				PteArray[i] = (Writable & 1) << 8 | Executable & 1;				
			}
			else
			{
				pdebug(do_log,"[NtProtectVirtualMemory_hook] not tracked\n");
				PteArray[i] = 0xFFFFFFFF;
			}
		}
		
		result = NtProtectVirtualMemory(ProcessHandle,BaseAddress,NumberOfBytesToProtect,NewAccessProtection,OldAccessProtection);
		if (result == STATUS_SUCCESS)
		{
			for (i = 0; i < NumberOfPages; i++ )
			{
				CurrentPage = (ULONG_PTR)InputBaseAddress+i*PAGE_SIZE;
				ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(CurrentPage);
				
				if ( (PteArray[i] != 0xFFFFFFFF) &&  ppte_virtual->pte.present)
				{
					pdebug(do_log,"[NtProtectVirtualMemory_hook] page : 0x%x, after 0x%x 0x%x\n",CurrentPage, ppte_virtual->raw.HighPart,ppte_virtual->raw.LowPart);
					
					Writable = (PteArray[i] >> 8) & 1;
					Executable = PteArray[i] & 1;
					
					pdebug(do_log,"[NtProtectVirtualMemory_hook] page : Writable : %d, Executable : %d\n",Writable,Executable);
					
					SetMemoryProtectionPae2(CurrentPage,Writable,Executable);
					
					pdebug(do_log,"[NtProtectVirtualMemory_hook] page : 0x%x, 0x%x 0x%x\n", ppte_virtual->raw.HighPart,ppte_virtual->raw.LowPart);
				}
			}
		}
		
		if(PteArray)
		{
			ExFreePool(PteArray);
			PteArray = NULL; 
		}		
	}

	return result;
	
error_normal_exec:
		return NtProtectVirtualMemory(ProcessHandle,BaseAddress,NumberOfBytesToProtect,NewAccessProtection,OldAccessProtection);

}	