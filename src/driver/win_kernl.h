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

#ifndef WIN_KERNL_H
#define WIN_KERNL_H

#include <Wdm.h>
#include <ntddk.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <process.h>
#include <Ntstrsafe.h>


//Building for windows 7
#if WINVER==0x0601
    #ifdef _M_X64
        #include "win_7_x64.h"
    #else
        #include "win_7_x86.h"
    #endif
#else
    #pragma message ( "Building for unsupported OS version dude !" )
#endif

#ifdef _M_X64
    #define PAGE_MASK 0xFFFFFFFFFFFFF000
#else
    #define PAGE_MASK 0xFFFFF000    
#endif


#pragma comment(lib,"ntoskrnl.lib")

#define DEBOGUE 1

/*
#if DEBOGUE
#define pdebug(format, ...) DbgPrint ( format, ## __VA_ARGS__)
#else if
#define pdebug(format, ...)
#endif
*/

#define pdebug(doit,format, ...) \
	if (doit) \
		DbgPrint ( format, ## __VA_ARGS__)
		
#define FALSE 0
#define TRUE  1

#define KERNEL_MODE 0
#define USER_MODE	1

#define PAGE_SIZE 0x1000
#define INVALID_HANDLE_VALUE (HANDLE)-1

#define READ_ACCESS 0
#define WRITE_ACCESS 1
#define EXECUTE_ACCESS 8

#define MEM_IMAGE 0x1000000

#define MAX_PATH 260

#define PROCESS_TERMINATE 1
#define PROCESS_QUERY_INFORMATION 0x400
#define PROCESS_SUSPEND_RESUME 0x800

NTSTATUS PsRemoveCreateThreadNotifyRoutine(
  PVOID NotifyRoutine
);

NTSTATUS PsRemoveLoadImageNotifyRoutine(
  PVOID NotifyRoutine
);

NTSTATUS PsSetCreateProcessNotifyRoutineEx(
  PVOID NotifyRoutine,
  BOOLEAN Remove
);

NTSTATUS PsSetCreateProcessNotifyRoutineEx(
  PVOID NotifyRoutine,
  BOOLEAN Remove
);

NTSTATUS PsSetLoadImageNotifyRoutine(
  PVOID NotifyRoutine
);

NTSTATUS PsSetCreateThreadNotifyRoutine(
  PVOID NotifyRoutine
);

NTSTATUS PsSetCreateProcessNotifyRoutine(
  PVOID NotifyRoutine,
  BOOLEAN Remove  
);

NTSTATUS ZwQueryVirtualMemory(
  HANDLE                   ProcessHandle,
  PVOID                    BaseAddress,
  ULONG                    MemoryInformationClass,
  PVOID                    MemoryInformation,
  SIZE_T                   MemoryInformationLength,
  PSIZE_T                  ReturnLength
);

NTSTATUS ZwTerminateProcess(
  HANDLE   ProcessHandle,
  NTSTATUS ExitStatus
);

NTSTATUS ZwOpenProcess(
  PHANDLE            ProcessHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PCLIENT_ID         ClientId
);

NTSTATUS NTAPI MmMarkPhysicalMemoryAsBad(PHYSICAL_ADDRESS StartAddress, PLARGE_INTEGER NumberOfButes);



#endif