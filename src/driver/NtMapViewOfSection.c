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

extern proto_NtMapViewOfSection NtMapViewOfSection;
extern ConfigStruct GlobalConfigStruct;

NTSTATUS NtMapViewOfSection_hook(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize,SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect)
{
	NTSTATUS result,r;
	ULONG OldProtect;
	HANDLE TargetPid;
	PMYEPROCESS pProc = NULL;
	int take_hook = 0;
    mapviewofsection_event evt = {0};
    
	//Performe the genuine syscall
	result = NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize , InheritDisposition, AllocationType, Protect);   
	if (result != STATUS_SUCCESS)
		return result;

	//Reference target process kernel object
	r = ObReferenceObjectByHandle(ProcessHandle,PROCESS_ALL_ACCESS,*PsProcessType,UserMode,(PVOID)&pProc,NULL);
	if( r == STATUS_SUCCESS )
	{
		if ( ( IsProcessTracked( pProc->UniqueProcessId ) ) && ( IsProcessTracked(PsGetCurrentProcessId()) ) ) 
			take_hook = 1;
		
        TargetPid = pProc->UniqueProcessId;
        
		ObDereferenceObject(pProc);
		pProc = NULL;
	}	
	
	if (take_hook)
	{
		pdebug(GlobalConfigStruct.debug_log,"[NtMapViewOfSection_hook] called : 0x%x, 0x%x",*BaseAddress,*ViewSize);
		SetInitialPTEStates((ULONG_PTR)*BaseAddress,*ViewSize);
        
        if ( ((PKTHREAD)PsGetCurrentThread())->PreviousMode == UserMode )
        {
            //Send event to userland
            evt.ProcessId = PsGetCurrentProcessId();
            evt.TargetPid = TargetPid;
            evt.BaseAddress = *BaseAddress;
            evt.ZeroBits = ZeroBits;
            evt.ViewSize = *ViewSize;
            evt.AllocationType = AllocationType;
            evt.Protect = Protect;
            evt.result = result;

            AddEventToBuffer( EVENT_MAP_VIEW_OF_SECTION ,sizeof(evt), (PVOID)&evt);
        }
	}
	
	return result;
}