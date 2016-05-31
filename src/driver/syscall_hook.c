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
#include "syscall_hook.h"
#include "utils.h"

extern void ** ServiceTable;
extern ConfigStruct GlobalConfigStruct;
SyscallNumbers SysN;

extern unsigned int number_of_hooked_syscalls;
extern HookSyscall HookedSyscallArray[];

int GetKernelBaseAndSize(PVOID *pImageBaseAddress, ULONG * pImageSize);

proto_NtProtectVirtualMemory NtProtectVirtualMemory = NULL;
proto_NtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
proto_NtFreeVirtualMemory NtFreeVirtualMemory = NULL;
proto_NtCreateThread NtCreateThread = NULL;
proto_NtQueryVirtualMemory NtQueryVirtualMemory = NULL;
proto_NtTerminateProcess NtTerminateProcess = NULL;
proto_NtTerminateThread NtTerminateThread = NULL;
proto_NtCreateProcessEx NtCreateProcessEx = NULL;
proto_NtDeleteFile NtDeleteFile = NULL;
proto_NtMapViewOfSection NtMapViewOfSection = NULL;
proto_NtCreateSection NtCreateSection = NULL;
proto_NtCreateThreadEx NtCreateThreadEx = NULL;
proto_NtSuspendThread NtSuspendThread = NULL;
proto_NtSetInformationThread NtSetInformationThread = NULL;
proto_NtCreateUserProcess NtCreateUserProcess = NULL;

ULONG_PTR SyscallHookResume = 0;
ULONG_PTR psyscall_path = 0;
ULONG KiServiceLimit = KI_SERVICE_LIMIT;

void InitHookedArray()
{
    LONG i;
    
    for (i=0 ; i < KI_SERVICE_LIMIT; i++)
    {
        HookedSyscallArray[i].Kernfunc = NULL;
        HookedSyscallArray[i].HookFunc = NULL;
        HookedSyscallArray[i].SyscallNumber = INVALID_SYSCALL_NUMBER;
    }
}

void AddHookedSyscall(USHORT SyscallNumber, PVOID HookFunc, PVOID * pToOriginal)
{
    if (SyscallNumber < KI_SERVICE_LIMIT)
    {
        HookedSyscallArray[SyscallNumber].HookFunc = HookFunc;
        HookedSyscallArray[SyscallNumber].SyscallNumber = SyscallNumber;
        HookedSyscallArray[SyscallNumber].PointerToOriginalFunc = pToOriginal;
    }
}

PVOID GetSyscallHookFunc(PVOID KernFunc)
{
    LONG i;
    
    for (i=0 ; i < KI_SERVICE_LIMIT; i++)
    {
        if ( KernFunc == HookedSyscallArray[i].Kernfunc)
            return HookedSyscallArray[i].HookFunc;
    }
    
    return NULL;
}

int HookSyscalls(PVOID KernelImageBase, ULONG KernelImageSize)
{
    LONG i;

    if (!ServiceTable)
    {
        pdebug(GlobalConfigStruct.debug_log,"[HookSyscalls] ServiceTable has not been resolved !\n");
        return 0;
    }
    
    InitHookedArray();

    //Here we can add all the system calls we want to hook
    AddHookedSyscall(WIN_NT_ALLOCATE_VIRTUAL_MEMORY,NtAllocateVirtualMemory_hook, (PVOID *)&NtAllocateVirtualMemory);    
    AddHookedSyscall(WIN_NT_PROTECT_VIRTUAL_MEMORY,NtProtectVirtualMemory_hook, (PVOID *)&NtProtectVirtualMemory);
    AddHookedSyscall(WIN_NT_QUERY_VIRTUAL_MEMORY,NtQueryVirtualMemory_hook, (PVOID *)&NtQueryVirtualMemory);
    AddHookedSyscall(WIN_NT_MAP_VIEW_OF_SECTION,NtMapViewOfSection_hook, (PVOID *)&NtMapViewOfSection);
    AddHookedSyscall(WIN_NT_FREE_VIRTUAL_MEMORY,NtFreeVirtualMemory_hook, (PVOID *)&NtFreeVirtualMemory);    
    AddHookedSyscall(WIN_NT_CREATE_USER_PROCESS,NtCreateUserProcess_hook, (PVOID *)&NtCreateUserProcess);
    AddHookedSyscall(WIN_NT_TERMINATE_PROCESS,NtTerminateProcess_hook, (PVOID *)&NtTerminateProcess);
    
    cr0_disable_write_protect();
    
    for (i = 0; i < KI_SERVICE_LIMIT; i++)
    {
        LONG SysN = HookedSyscallArray[i].SyscallNumber;

        if ( SysN != INVALID_SYSCALL_NUMBER  )
        {
            //On 32 bits systems we use regular pointers, it is easier
            HookedSyscallArray[i].Kernfunc = ServiceTable[SysN];
            *HookedSyscallArray[i].PointerToOriginalFunc = ServiceTable[SysN];
            ServiceTable[SysN] = HookedSyscallArray[i].HookFunc;
        }
    }
    
    cr0_enable_write_protect();
    
    return 1;
}

void UnhookSyscalls()
{
    LONG i;    
        
	cr0_disable_write_protect();
    
    for (i = 0; i < KI_SERVICE_LIMIT; i++)
    {
        if ( HookedSyscallArray[i].SyscallNumber != INVALID_SYSCALL_NUMBER  )
        { 
            //On 32 bits systems we use regular pointers, it is easier
            ServiceTable[i] = HookedSyscallArray[i].Kernfunc;
        }
    }
    
	cr0_enable_write_protect();
}

