/*
 * Copyright 2016 Julien Lenoir / Airbus Group Innovations
 * contact: julien.lenoir@airbus.com
 */

/*
 * This file is part of Gunpack.
 *
 * Gunpack is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Gunpack is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Gunpack.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

//extern unsigned int TargetPid;
extern proto_NtProtectVirtualMemory NtProtectVirtualMemory;
extern ULONG_PTR * MmUserProbeAddress;
extern ConfigStruct GlobalConfigStruct;

NTSTATUS CONVENTION NtProtectVirtualMemory_hook(HANDLE ProcessHandle, PVOID * BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
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
    virtualprotect_event evt = {0};
    HANDLE TargetProcessId;
	
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
		pdebug(GlobalConfigStruct.debug_log,"NtProtectVirtualMemory error sanitizing inputs\n");
		goto error_normal_exec;
	}	
	
	//Don't try to mess with kernel memory
	if ( (ULONG_PTR)InputBaseAddress > (ULONG_PTR)*MmUserProbeAddress )
	{
		pdebug(GlobalConfigStruct.debug_log,"NtProtectVirtualMemory error sanitizing inputs\n");
		goto error_normal_exec;
	}
	
	//Reference target process kernel object
	r = ObReferenceObjectByHandle(ProcessHandle,PROCESS_ALL_ACCESS,*PsProcessType,UserMode,(PVOID)&pProc,NULL);
	if( r == STATUS_SUCCESS )
	{
        TargetProcessId = pProc->UniqueProcessId;
        //TODO : check this condition
		if ( ( IsProcessTracked( TargetProcessId ) ) && ( IsProcessTracked(PsGetCurrentProcessId()) ) ) 
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
		pdebug(GlobalConfigStruct.debug_log,"[NtProtectVirtualMemory_hook] InputAddress : 0x%x, NumberOfPages : 0x%x, NewAccessProtection : 0x%x\n",InputBaseAddress,NumberOfPages,NewAccessProtection);
		
		CurrentVad = LocateVadForPage(GetVadRoot(PsGetCurrentProcess()), (ULONG)InputBaseAddress >> 0xC);
		if(!CurrentVad)
		{
			pdebug(GlobalConfigStruct.debug_log,"[NtProtectVirtualMemory_hook] Vad of starting address not found !");
			goto error_normal_exec;
		}
		
		if ( (((ULONG)InputBaseAddress >> 0xC) + NumberOfPages ) < NumberOfPages )
		{
			pdebug(GlobalConfigStruct.debug_log,"[NtProtectVirtualMemory_hook] overflow. A = 0x%x, Sum = 0x%x, N = 0x%x!",(ULONG)InputBaseAddress >> 0xC,((ULONG)InputBaseAddress >> 0xC) + NumberOfPages, NumberOfPages );
			goto error_normal_exec;
		}
		
		//Check that the protected memory range is contained within a single vad.
		//If it is not NtProtectVirtualMemory system call would fail anyway
		if ( (((ULONG)InputBaseAddress >> 0xC) + NumberOfPages ) > (CurrentVad->EndingVpn +1) )
		{
			pdebug(GlobalConfigStruct.debug_log,"[NtProtectVirtualMemory_hook] Memory range does not fit in a vad !");
			goto error_normal_exec;
		}
		
		//Allocate an array for PTEs
		PteArray = ExAllocatePoolWithTag(NonPagedPool, NumberOfPages*sizeof(ULONG), GPAK_TAG);
		if (!PteArray)
		{
			pdebug(GlobalConfigStruct.debug_log,"[NtProtectVirtualMemory_hook] not enough memory!\n");
			return 0xC0000001;
		}
		
		memset(PteArray,NumberOfPages*sizeof(ULONG),0);
		
		for (i = 0; i < NumberOfPages; i++ )
		{
			CurrentPage = (ULONG_PTR)InputBaseAddress+i*PAGE_SIZE;
			ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(CurrentPage);
			
			pdebug(GlobalConfigStruct.debug_log,"[NtProtectVirtualMemory_hook] page : 0x%x, before 0x%x 0x%x\n",CurrentPage,ppte_virtual->raw.HighPart,ppte_virtual->raw.LowPart);
			
			if (( ppte_virtual->pte.present ) && ( IsTrackedPage(CurrentPage)  ) )
			{
				pdebug(GlobalConfigStruct.debug_log,"[NtProtectVirtualMemory_hook] tracked\n");
				GetMemoryProtectionPae(CurrentPage,&Writable,&Executable);
				
				pdebug(GlobalConfigStruct.debug_log,"[NtProtectVirtualMemory_hook] Writable : %d, Executable %d\n",Writable,Executable);

				PteArray[i] = (Writable & 1) << 8 | Executable & 1;				
			}
			else
			{
				pdebug(GlobalConfigStruct.debug_log,"[NtProtectVirtualMemory_hook] not tracked\n");
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
					pdebug(GlobalConfigStruct.debug_log,"[NtProtectVirtualMemory_hook] page : 0x%x, after 0x%x 0x%x\n",CurrentPage, ppte_virtual->raw.HighPart,ppte_virtual->raw.LowPart);
					
					Writable = (PteArray[i] >> 8) & 1;
					Executable = PteArray[i] & 1;
					
					pdebug(GlobalConfigStruct.debug_log,"[NtProtectVirtualMemory_hook] page : Writable : %d, Executable : %d\n",Writable,Executable);
					
					SetMemoryProtectionPae2(CurrentPage,Writable,Executable);
					
					pdebug(GlobalConfigStruct.debug_log,"[NtProtectVirtualMemory_hook] page : 0x%x, 0x%x 0x%x\n", ppte_virtual->raw.HighPart,ppte_virtual->raw.LowPart);
				}
			}
		}
		
		if(PteArray)
		{
			ExFreePool(PteArray);
			PteArray = NULL; 
		}

        if ( ((PKTHREAD)PsGetCurrentThread())->PreviousMode == UserMode )
        {
            //Send event to userland
            evt.ProcessId = PsGetCurrentProcessId();
            evt.TargetProcessId = TargetProcessId;
            evt.BaseAddress = *BaseAddress;
            evt.RegionSize = *NumberOfBytesToProtect;
            evt.Protect = NewAccessProtection;
            evt.result = result;

            AddEventToBuffer( EVENT_VIRTUAL_PROTECT ,sizeof(evt), (PVOID)&evt);
        }
	}

	return result;
	
error_normal_exec:
		return NtProtectVirtualMemory(ProcessHandle,BaseAddress,NumberOfBytesToProtect,NewAccessProtection,OldAccessProtection);

}	