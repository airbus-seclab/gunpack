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

extern proto_NtAllocateVirtualMemory NtAllocateVirtualMemory;
extern ConfigStruct GlobalConfigStruct;

NTSTATUS NTAPI NtAllocateVirtualMemory_hook(HANDLE ProcessHandle, PVOID * BaseAddress, ULONG ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect)
{
	NTSTATUS result,r;
	HANDLE Pid = NULL;
	KAPC_STATE ApcState;
	PVOID LocalBaseAddress = NULL;
	ULONG LocalRegionSize = 0;
	PMYEPROCESS pProc = NULL;
    HANDLE TargetProcessId = NULL;
    virtualalloc_event evt = {0};
	
	int take_hook = 0;
    
	//first we do regular allocation
	result = NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	if (result != STATUS_SUCCESS)
		return result;
    
	//Reference target process kernel object
	r = ObReferenceObjectByHandle(ProcessHandle,PROCESS_ALL_ACCESS,*PsProcessType,UserMode,(PVOID)&pProc,NULL);
	if( r == STATUS_SUCCESS )
	{
        TargetProcessId = pProc->UniqueProcessId;
        
        //We may want to update this policy sometimes
		//if (  IsProcessTracked( TargetProcessId )  &&  IsProcessTracked( PsGetCurrentProcessId() ) && ( ((PKTHREAD)PsGetCurrentThread())->PreviousMode == UserMode ) )
        if (  IsProcessTracked( TargetProcessId )  &&  IsProcessTracked( PsGetCurrentProcessId() ) )
			take_hook = 1;
		
		ObDereferenceObject(pProc);
		pProc = NULL;
	}
	
	if (take_hook)
	{
		//It is safe to dereference those userland pointers since we already called NtAllocateVirtualMemory
		LocalBaseAddress = *BaseAddress;
		LocalRegionSize = *RegionSize;
		
		pdebug(GlobalConfigStruct.debug_log,"[NtAllocateVirtualMemory_hook] BaseAddress :: 0x%x, RegionSize : 0x%x,  AllocationType : 0x%x, Protect 0x%x\n", LocalBaseAddress, LocalRegionSize, AllocationType, Protect);
		
		//Change memory protection on page that are commited and not page guards
		if ( ( AllocationType & MEM_COMMIT ) && ( !(Protect & PAGE_GUARD) ) )
		{
			SetInitialPTEStates((ULONG_PTR)LocalBaseAddress,LocalRegionSize);
		}

        if ( ((PKTHREAD)PsGetCurrentThread())->PreviousMode == UserMode )
        {
            //Send event to userland
            evt.ProcessId = PsGetCurrentProcessId();
            evt.ThreadId = PsGetCurrentThreadId();
            evt.TargetProcessId = TargetProcessId;
            evt.BaseAddress = LocalBaseAddress;
            evt.RegionSize = LocalRegionSize;
            evt.AllocationType = AllocationType;
            evt.Protect = Protect;
            evt.result = result;

            AddEventToBuffer( EVENT_VIRTUAL_ALLOC ,sizeof(evt), (PVOID)&evt);
        }
	}
	
	return result;
}