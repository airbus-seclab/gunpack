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

#include "userland_comm.h"
#include "events.h"
#include "syscall_hook.h"
#include "tracked_process.h"
#include "utils.h"


extern PKEVENT UserlandNotidyEvent;
extern PKEVENT IoctEvent;
extern PVOID ExceptionBuffer;

PKMUTEX  pMutex = NULL;

int InitUserlandCommunication()
{
    
    ExceptionBuffer = ExAllocatePoolWithTag(NonPagedPool, EXCEPTION_BUFFER_SIZE, GPAK_TAG);
    if(!ExceptionBuffer)
	{
		pdebug(1,"[DriverEntry] Unable to allocate ExceptionBuffer\n");	
		return STATUS_UNSUCCESSFUL;	
	}    
    
    pMutex = ExAllocatePoolWithTag(NonPagedPool,sizeof(KMUTEX),GPAK_TAG);
    if(!pMutex)
    {
        pdebug(1,"Unable to allocate mutex, not enough memory");
        return 0;
    }

    KeInitializeMutex(pMutex,0);
    
    return 1;
}

VOID AddEventToBuffer(unsigned short EventType, unsigned short EventSize, unsigned char * EventBuffer)
{   
    event_header * pEvtBuffer;
    
    /*
        Ensure that events and mutex are initialized
    */
    if(!UserlandNotidyEvent)
        return;
    
    if(!IoctEvent)
        return;
    
    if (!pMutex)
        return;
    
    // Ensure that the global Exception buffer is initialized
    if (!ExceptionBuffer)
        return;
      
    //Set a mutex to ensure that only one thread at a time can set an event
    KeWaitForSingleObject(pMutex, UserRequest, KernelMode, FALSE, NULL);
    
    if ( (EventSize + sizeof(event_header)) <= EXCEPTION_BUFFER_SIZE )
    {
        
        //Copy Exception in Buffer
        pEvtBuffer = (event_header *)ExceptionBuffer;
        
        pEvtBuffer->event_type = EventType;
        pEvtBuffer->event_size = EventSize;    

        memcpy( (unsigned char *)ExceptionBuffer + sizeof(event_header),EventBuffer,EventSize);
        
        //Notify userland that an event is waiting
        KeSetEvent(UserlandNotidyEvent, 1, FALSE);

        if (IoctEvent)
        {            
            //Wait for userland program to retrieve the event wia Ioctl
            KeWaitForSingleObject(IoctEvent, Executive, KernelMode, FALSE, NULL);
            
            if (IoctEvent)
            {
                KeClearEvent(IoctEvent);
            }            
        }
    }

    //Release mutex for next event
    KeReleaseMutex(pMutex, FALSE);
}

VOID CloseUuserlandCommunication()
{
    //Acquire the mutex
    KeWaitForSingleObject(pMutex, UserRequest, KernelMode, FALSE, NULL);
    
    if(ExceptionBuffer)
    {
        ExFreePool(ExceptionBuffer);
        ExceptionBuffer = NULL;
    }
    
    KeReleaseMutex(pMutex, FALSE);
}