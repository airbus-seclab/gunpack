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
extern proto_NtMapViewOfSection NtMapViewOfSection;
extern int do_log;

NTSTATUS NTAPI NtMapViewOfSection_hook(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PULONG ViewSize,SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect)
{
	NTSTATUS result,r;
	ULONG OldProtect;
	HANDLE Pid;
	PMYEPROCESS pProc = NULL;
	int take_hook = 0;
	
	//Performe the genuine syscall
	result = NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize , InheritDisposition, AllocationType, Protect);
	if (result != STATUS_SUCCESS)
		return result;	
	
	//Reference target process kernel object
	r = ObReferenceObjectByHandle(ProcessHandle,PROCESS_ALL_ACCESS,*PsProcessType,UserMode,(PVOID)&pProc,NULL);
	if( r == STATUS_SUCCESS )
	{
		if (  ((HANDLE)pProc->UniqueProcessId == (HANDLE)TargetPid) && ( PsGetCurrentProcessId() == (HANDLE)TargetPid) )
			take_hook = 1;
		
		ObDereferenceObject(pProc);
		pProc = NULL;
	}		
	
	if (take_hook)
	{
		pdebug(do_log,"[NtMapViewOfSection_hook] called : 0x%x, 0x%x",*BaseAddress,*ViewSize);
		ProtectExecutablePTEs((ULONG_PTR)*BaseAddress,*ViewSize);	
	}
	
	return result;
}