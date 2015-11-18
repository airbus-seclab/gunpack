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