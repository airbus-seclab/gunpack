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

#ifndef SYSCALL_HOOK_H
#define SYSCALL_HOOK_H

#include "DriverDefs.h"
#include <Wdm.h>
#include <ntddk.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <process.h>
#include "win_kernl.h"

#define INVALID_SYSCALL_NUMBER 0xFFFF

typedef struct HookSyscall{
    PVOID Kernfunc;
    PVOID HookFunc;
    PVOID * PointerToOriginalFunc;
    USHORT SyscallNumber;
}HookSyscall;

HookSyscall HookedSyscallArray[KI_SERVICE_LIMIT];


/*
//Xp syscall numbers
#define XP_NT_ALLOCATE_VIRTUAL_MEMORY 17
#define XP_NT_CREATE_PROCESS_EX 48
#define XP_NT_CREATE_SECTION 50
#define XP_NT_CREATE_THREAD 53
#define XP_NT_DELETE_FILE 62
#define XP_NT_FREE_VIRTUAL_MEMORY 83
#define XP_NT_MAP_VIEW_OF_SECTION 108
#define XP_NT_PROTECT_VIRTUAL_MEMORY 137
#define XP_NT_SUSPEND_THREAD 0xfe 
#define XP_NT_QUERY_VIRTUAL_MEMORY 178
#define XP_NT_TERMINATE_PROCESS 257
#define XP_NT_TERMINATE_THREAD 258
#define XP_NT_WRITE_VIRTUAL_MEMORY 277
*/

typedef struct _SyscallNumbers{
	USHORT NT_ALLOCATE_VIRTUAL_MEMORY;
	USHORT NT_CREATE_PROCESS_EX;
	USHORT NT_CREATE_SECTION;
	USHORT NT_CREATE_THREAD;
	USHORT NT_DELETE_FILE;
	USHORT NT_FREE_VIRTUAL_MEMORY;
	USHORT NT_MAP_VIEW_OF_SECTION;
	USHORT NT_PROTECT_VIRTUAL_MEMORY;
	USHORT NT_QUERY_VIRTUAL_MEMORY;
	USHORT NT_TERMINATE_PROCESS;
	USHORT NT_TERMINATE_THREAD;
	USHORT NT_WRITE_VIRTUAL_MEMORY;
	USHORT NT_CREATE_THREAD_EX;
	USHORT NT_SUSPEND_THREAD;
	USHORT NT_SET_INFORMATION_THREAD;
	USHORT NT_CREATE_USER_PROCESS;
} SyscallNumbers;

void SetSyscallNumbers();
int HookSyscalls(PVOID KernelImageBase, ULONG);
void UnhookSyscalls();
PVOID GetSyscallHookFunc(PVOID KernFunc);

// Hook functions
NTSTATUS NTAPI NtCreateUserProcess_hook(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters, PVOID CreateInfo, PVOID AttributeList);
NTSTATUS NTAPI NtProtectVirtualMemory_hook(HANDLE ProcessHandle, PVOID * BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
NTSTATUS NTAPI NtAllocateVirtualMemory_hook(HANDLE ProcessHandle, PVOID * BaseAddress, ULONG ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NTAPI NtFreeVirtualMemory_hook(HANDLE ProcessHandle,PVOID *BaseAddress,PSIZE_T RegionSize,ULONG FreeType);
NTSTATUS NTAPI NtTerminateProcess_hook(HANDLE ProcessHandle, ULONG ExitCode);
NTSTATUS NTAPI NtQueryVirtualMemory_hook(HANDLE ProcessHandle, PVOID BaseAddress, __int32 MemoryInformationClass,PVOID MemoryInformation, ULONG MemoryInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI NtCreateThreadEx_hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartAddress, PVOID Parameter, BOOLEAN CreateSuspended, ULONG StackZeroBits, ULONG SizeOfStackCommit, ULONG SizeOfStackReserve, PVOID BytesBuffer);
NTSTATUS NTAPI NtMapViewOfSection_hook(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize,SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);
NTSTATUS NTAPI NtSetInformationThread_hook(HANDLE ThreadHandle, ULONG ThreadInfoClass, PVOID ThreadInfo, ULONG ThreadInfoLength);
#endif