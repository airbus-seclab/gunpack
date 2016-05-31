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

extern proto_NtTerminateProcess NtTerminateProcess;
extern proto_NtSuspendProcess ZwSuspendProcess;

NTSTATUS NTAPI NtTerminateProcess_hook(HANDLE ProcessHandle, ULONG ExitCode)
{
	NTSTATUS r = STATUS_UNSUCCESSFUL;
	NTSTATUS result = STATUS_UNSUCCESSFUL;
    PEPROCESS pProc = NULL;
    HANDLE TargetPid = NULL;
    HANDLE CurrentPid = PsGetCurrentProcessId();
    int take_hook = 0;
    terminateprocess_event evt = {0};

	//Reference target process kernel object
	r = ObReferenceObjectByHandle(ProcessHandle,PROCESS_ALL_ACCESS,*PsProcessType,UserMode,(PVOID)&pProc,NULL);
	if( r == STATUS_SUCCESS )
	{
        TargetPid = pProc->UniqueProcessId;
        
        //If the target process is one of the process we monitor, we'll take the hook
		if ( IsProcessTracked( TargetPid ) ) 
			take_hook = 1;
		
		ObDereferenceObject(pProc);
		pProc = NULL;
	}
    

    if ( take_hook )
	{
        evt.ProcessId = CurrentPid;
        evt.TargetProcessId = TargetPid;

        AddEventToBuffer(EVENT_TERMINATE_PROCESS , sizeof(evt), (PVOID)&evt);  

        //Suspend the monitored process
        ZwSuspendProcess(ProcessHandle);
        
        result = STATUS_ACCESS_DENIED;
    }
    else
    {
        //Another process is being terminated
        result = NtTerminateProcess(ProcessHandle, ExitCode);
    }
 
    return result;
}