#include "syscall_hook.h"
#include "utils.h"

extern void ** ServiceTable;

SyscallNumbers SysN;

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

void SetSyscallNumbersSeven()
{
	SyscallNumbers * pNSyscalls = &SysN;
	
	pNSyscalls->NT_ALLOCATE_VIRTUAL_MEMORY = WIN7_NT_ALLOCATE_VIRTUAL_MEMORY;
	pNSyscalls->NT_CREATE_PROCESS_EX = WIN7_NT_CREATE_PROCESS_EX;
	pNSyscalls->NT_CREATE_SECTION = WIN7_NT_CREATE_SECTION;
	pNSyscalls->NT_CREATE_THREAD = WIN7_NT_CREATE_THREAD;
	pNSyscalls->NT_CREATE_THREAD_EX = WIN7_NT_CREATE_THREAD_EX;	
	pNSyscalls->NT_DELETE_FILE = WIN7_NT_DELETE_FILE;
	pNSyscalls->NT_FREE_VIRTUAL_MEMORY = WIN7_NT_FREE_VIRTUAL_MEMORY;
	pNSyscalls->NT_MAP_VIEW_OF_SECTION = WIN7_NT_MAP_VIEW_OF_SECTION;
	pNSyscalls->NT_PROTECT_VIRTUAL_MEMORY = WIN7_NT_PROTECT_VIRTUAL_MEMORY;
	pNSyscalls->NT_QUERY_VIRTUAL_MEMORY = WIN7_NT_QUERY_VIRTUAL_MEMORY;
	pNSyscalls->NT_TERMINATE_PROCESS = WIN7_NT_TERMINATE_PROCESS;
	pNSyscalls->NT_TERMINATE_THREAD = WIN7_NT_TERMINATE_THREAD;
	pNSyscalls->NT_WRITE_VIRTUAL_MEMORY = WIN7_NT_WRITE_VIRTUAL_MEMORY;
	pNSyscalls->NT_SUSPEND_THREAD = WIN7_NT_SUSPEND_THREAD;
	pNSyscalls->NT_SET_INFORMATION_THREAD = WIN7_NT_SET_INFORMATION_THREAD;
}


void HookSyscalls()
{
	//Keep the syscall addresses in global variables
	NtProtectVirtualMemory = (proto_NtProtectVirtualMemory)ServiceTable[SysN.NT_PROTECT_VIRTUAL_MEMORY];
	NtAllocateVirtualMemory = (proto_NtAllocateVirtualMemory)ServiceTable[SysN.NT_ALLOCATE_VIRTUAL_MEMORY];
	NtFreeVirtualMemory = (proto_NtFreeVirtualMemory)ServiceTable[SysN.NT_FREE_VIRTUAL_MEMORY];
	NtCreateThread = (proto_NtCreateThread)ServiceTable[SysN.NT_CREATE_THREAD];
	NtQueryVirtualMemory = (proto_NtQueryVirtualMemory)ServiceTable[SysN.NT_QUERY_VIRTUAL_MEMORY];
	NtTerminateProcess = (proto_NtTerminateProcess)ServiceTable[SysN.NT_TERMINATE_PROCESS];
	NtTerminateThread = (proto_NtTerminateProcess)ServiceTable[SysN.NT_TERMINATE_THREAD];
	NtCreateProcessEx = (proto_NtCreateProcessEx)ServiceTable[SysN.NT_CREATE_PROCESS_EX];
	NtDeleteFile =	(proto_NtDeleteFile)ServiceTable[SysN.NT_DELETE_FILE];
	NtMapViewOfSection =	(proto_NtMapViewOfSection)ServiceTable[SysN.NT_MAP_VIEW_OF_SECTION];
	NtCreateSection = (proto_NtCreateSection)ServiceTable[SysN.NT_CREATE_SECTION];
	NtCreateThreadEx = (proto_NtCreateThreadEx)ServiceTable[SysN.NT_CREATE_THREAD_EX];
	NtSuspendThread = (proto_NtSuspendThread)ServiceTable[SysN.NT_SUSPEND_THREAD];
	NtSetInformationThread = (proto_NtSetInformationThread)ServiceTable[SysN.NT_SET_INFORMATION_THREAD]; 

	disable_cr0();
		
	ServiceTable[SysN.NT_PROTECT_VIRTUAL_MEMORY] = NtProtectVirtualMemory_hook;
	ServiceTable[SysN.NT_ALLOCATE_VIRTUAL_MEMORY]  = NtAllocateVirtualMemory_hook;
	ServiceTable[SysN.NT_FREE_VIRTUAL_MEMORY]  = NtFreeVirtualMemory_hook;
	ServiceTable[SysN.NT_TERMINATE_PROCESS]  = NtTerminateProcess_hook;
	ServiceTable[SysN.NT_QUERY_VIRTUAL_MEMORY]  = NtQueryVirtualMemory_hook;
	ServiceTable[SysN.NT_MAP_VIEW_OF_SECTION] = NtMapViewOfSection_hook;

	enable_cr0();	
}

void UnhookSyscalls()
{
	disable_cr0();	

	ServiceTable[SysN.NT_PROTECT_VIRTUAL_MEMORY] = NtProtectVirtualMemory;
	ServiceTable[SysN.NT_ALLOCATE_VIRTUAL_MEMORY]  = NtAllocateVirtualMemory;
	ServiceTable[SysN.NT_FREE_VIRTUAL_MEMORY]  = NtFreeVirtualMemory;
	ServiceTable[SysN.NT_TERMINATE_PROCESS]  = NtTerminateProcess;
	ServiceTable[SysN.NT_QUERY_VIRTUAL_MEMORY]  = NtQueryVirtualMemory;
	ServiceTable[SysN.NT_MAP_VIEW_OF_SECTION] = NtMapViewOfSection;

	enable_cr0();
}

