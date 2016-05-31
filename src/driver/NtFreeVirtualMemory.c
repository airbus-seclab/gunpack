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

extern proto_NtFreeVirtualMemory NtFreeVirtualMemory;
extern ConfigStruct GlobalConfigStruct;

NTSTATUS NTAPI NtFreeVirtualMemory_hook(HANDLE ProcessHandle,PVOID *BaseAddress,PSIZE_T RegionSize,ULONG FreeType)
{
	NTSTATUS result;
	DWORD_PTR CurrentAddress;
	DWORD_PTR StartAddress, EndAddress;
    virtualfree_event evt = {0};    
	 
	if ( IsProcessTracked(PsGetCurrentProcessId()) )
	{
		result = NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
		if ( (result == STATUS_SUCCESS) && ( FreeType & MEM_RELEASE) )
		{
			pdebug(GlobalConfigStruct.debug_log,"[NtFreeVirtualMemory] Freeing 0x%x with size 0x%x, Type : 0x%x !\n",*BaseAddress,*RegionSize,FreeType);
			StartAddress = (DWORD_PTR)*BaseAddress;
			EndAddress = StartAddress + *RegionSize;
			
			pdebug(GlobalConfigStruct.debug_log,"[NtFreeVirtualMemory] StartAddress : 0x%x, EndAddress :  0x%x\n",StartAddress,EndAddress); 
			
			for ( CurrentAddress = StartAddress; CurrentAddress < EndAddress ; CurrentAddress += PAGE_SIZE )
			{
				pdebug(GlobalConfigStruct.debug_log,"[NtFreeVirtualMemory] Untracking page 0x%x\n",CurrentAddress);
				SetUntrackedPage(CurrentAddress);
			}
            
            if ( ((PKTHREAD)PsGetCurrentThread())->PreviousMode == UserMode )
            {
                //Send event to userland
                evt.ProcessId = PsGetCurrentProcessId();
                evt.BaseAddress = *BaseAddress;
                evt.RegionSize = *RegionSize;
                evt.FreeType = FreeType;
                evt.result = result;

                AddEventToBuffer( EVENT_VIRTUAL_FREE ,sizeof(evt), (PVOID)&evt);
            }
		}
	
		return result;
	}
    
	return NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
}
