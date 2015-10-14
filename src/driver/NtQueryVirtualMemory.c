#include "win_kernl.h"
#include "memory_state.h"
#include "utils.h"

extern unsigned int TargetPid;
extern proto_NtQueryVirtualMemory NtQueryVirtualMemory;
extern proto_MiCopyOnWrite MiCopyOnWrite;
extern proto_MiQueryAddressState MiQueryAddressState;
extern int do_log;

NTSTATUS NTAPI NtQueryVirtualMemory_hook(HANDLE ProcessHandle, PVOID BaseAddress, __int32 MemoryInformationClass,PVOID MemoryInformation, ULONG MemoryInformationLength, PULONG ReturnLength)
{
	//hook disabled
	return NtQueryVirtualMemory(ProcessHandle,BaseAddress,MemoryInformationClass,MemoryInformation,MemoryInformationLength,ReturnLength);
}