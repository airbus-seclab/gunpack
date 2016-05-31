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

#include "single_step.h"

KernelSingleStepAccess	KernelAccessArray[MAX_ACCESS_ARRAY_SIZE];
UserSingleStepAccess	UserAccessArray[MAX_ACCESS_ARRAY_SIZE];


#ifdef _M_X64
    #pragma message ( "C Preprocessor got here!" )
#endif


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