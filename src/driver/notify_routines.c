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

#include "DriverDefs.h"
#include "win_kernl.h"
#include "utils.h"
#include "userland_comm.h"
#include "events.h"
#include "tracked_process.h"

void ThreadNotifyRoutine(HANDLE ProcessId, HANDLE  ThreadId, BOOLEAN Create)
{
    create_thread_event thread_event;
    
    thread_event.ProcessId = ProcessId;
    thread_event.NewThreadId = ThreadId;
    thread_event.Create = Create;
    thread_event.ThreadId = PsGetCurrentThreadId();
    
    //Not interested in events of process we do not track
    if ( IsProcessTracked(ProcessId) == 0 )
        return;    

    AddEventToBuffer(EVENT_CREATE_THREAD, sizeof(thread_event), (PVOID)&thread_event);

    if (Create)
        pdebug(1,"Process pid(%d) create thread(%d)",(DWORD)ProcessId,(DWORD)ThreadId);
    else
        pdebug(1,"Process pid(%d) terminate thread(%d)",(DWORD)ProcessId,(DWORD)ThreadId);        
}

void ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    create_process_event proc_event;
    
    //Not interested in events of process we do not track
    if ( IsProcessTracked(ParentId) == 0 )
        return;
    
    proc_event.ParentId = ParentId;
    proc_event.ProcessId = ProcessId;   
    proc_event.Create = Create;
    
    AddEventToBuffer(EVENT_CREATE_PROCESS, sizeof(proc_event), (PVOID)&proc_event);  
    
    if (Create)
        pdebug(1,"Process pid(%d) create process pid(%d)",(DWORD)ParentId,(DWORD)ProcessId);
    else
        pdebug(1,"Process pid(%d) terminate process pid(%d)",(DWORD)ParentId,(DWORD)ProcessId);  
}


void LoadImageNotifyRoutine(PUNICODE_STRING pFullImageName, HANDLE ProcessId, PIMAGE_INFO pImageInfo)
{
    load_image_event img_event;
    
    if (!pImageInfo)
        return;
    
    //Not interested in events of process we do not track
    if ( IsProcessTracked(ProcessId) == 0 )
        return;       
    
    memset(&img_event,0,sizeof(img_event));
    img_event.BaseAddress = pImageInfo->ImageBase;
    img_event.ProcessId = ProcessId;
    
    if (pFullImageName)
    {
        memcpy( img_event.DllName, pFullImageName->Buffer, min( pFullImageName->Length , sizeof(img_event.DllName)) );
    }
    
    pdebug(1,"Process pid(%d) loaded an image at base address 0x%x",ProcessId,pImageInfo->ImageBase);    
    pdebug(1,"Current Pid(%d)",PsGetCurrentProcessId()); 

    AddEventToBuffer(EVENT_LOAD_LIBRARY, sizeof(img_event), (PVOID)&img_event);  
}