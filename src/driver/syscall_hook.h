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

//7 syscall numbers
#define WIN7_NT_ALLOCATE_VIRTUAL_MEMORY 0x13
#define WIN7_NT_CREATE_PROCESS_EX 0x50
#define WIN7_NT_CREATE_SECTION 0x54
#define WIN7_NT_CREATE_THREAD 0x57
#define WIN7_NT_CREATE_THREAD_EX 0x58	
#define WIN7_NT_DELETE_FILE 0x66
#define WIN7_NT_FREE_VIRTUAL_MEMORY 0x83
#define WIN7_NT_MAP_VIEW_OF_SECTION 0xa8
#define WIN7_NT_PROTECT_VIRTUAL_MEMORY 0xd7
#define WIN7_NT_QUERY_VIRTUAL_MEMORY 0x10b
#define WIN7_NT_SET_INFORMATION_THREAD 0x14f
#define WIN7_NT_SUSPEND_THREAD 0x16f
#define WIN7_NT_TERMINATE_PROCESS 0x172
#define WIN7_NT_TERMINATE_THREAD 0x173
#define WIN7_NT_WRITE_VIRTUAL_MEMORY 0x18f

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
} SyscallNumbers;

void SetSyscallNumbersXp();
void SetSyscallNumbersSeven();
void HookSyscalls();
void UnhookSyscalls();

// Hook functions
NTSTATUS NTAPI NtProtectVirtualMemory_hook(HANDLE ProcessHandle, PVOID * BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
NTSTATUS NTAPI NtAllocateVirtualMemory_hook(HANDLE ProcessHandle, PVOID * BaseAddress, ULONG ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NTAPI NtFreeVirtualMemory_hook(HANDLE ProcessHandle,PVOID *BaseAddress,PSIZE_T RegionSize,ULONG FreeType);
NTSTATUS NTAPI NtTerminateProcess_hook(HANDLE ProcessHandle, ULONG ExitCode);
NTSTATUS NTAPI NtQueryVirtualMemory_hook(HANDLE ProcessHandle, PVOID BaseAddress, __int32 MemoryInformationClass,PVOID MemoryInformation, ULONG MemoryInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI NtCreateThreadEx_hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartAddress, PVOID Parameter, BOOLEAN CreateSuspended, ULONG StackZeroBits, ULONG SizeOfStackCommit, ULONG SizeOfStackReserve, PVOID BytesBuffer);
NTSTATUS NTAPI NtMapViewOfSection_hook(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PULONG ViewSize,SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);
NTSTATUS NTAPI NtSetInformationThread_hook(HANDLE ThreadHandle, ULONG ThreadInfoClass, PVOID ThreadInfo, ULONG ThreadInfoLength);
#endif