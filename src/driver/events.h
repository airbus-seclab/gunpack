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

#ifndef EVENTS_H
#define EVENTS_H

//types of events
#define EVENT_EXCEPTION 0
#define EVENT_SYSCALL   1
#define EVENT_CREATE_PROCESS 2
#define EVENT_CREATE_THREAD 3
#define EVENT_LOAD_LIBRARY 4
#define EVENT_TERMINATE_PROCESS 5
#define EVENT_VIRTUAL_ALLOC 6
#define EVENT_VIRTUAL_PROTECT 7
#define EVENT_VIRTUAL_FREE 8
#define EVENT_MAP_VIEW_OF_SECTION 9

typedef struct event_header{
    unsigned short event_type;
    unsigned short event_size;    
} event_header;

typedef struct create_process_event{
    HANDLE ParentId;
    HANDLE ProcessId;
    BOOLEAN Create;
}create_process_event;

typedef struct create_thread_event{
    HANDLE ProcessId;
    HANDLE NewThreadId;
    HANDLE ThreadId;
    BOOLEAN Create;
}create_thread_event;

typedef struct load_image_event{
    PVOID BaseAddress;
    HANDLE ProcessId;
    wchar_t DllName[MAX_PATH];
}load_image_event;

typedef struct terminateprocess_event{
    HANDLE ProcessId;
    HANDLE TargetProcessId;
}terminateprocess_event;

typedef struct virtualalloc_event{
    HANDLE ProcessId;
    HANDLE ThreadId;
    HANDLE TargetProcessId;
    PVOID BaseAddress;
    ULONG RegionSize;
    ULONG AllocationType;
    ULONG Protect;
    ULONG result;
}virtualalloc_event;

typedef struct virtualprotect_event{
    HANDLE ProcessId;
    HANDLE TargetProcessId;
    PVOID BaseAddress;
    ULONG RegionSize;
    ULONG Protect;
    ULONG result;
}virtualprotect_event;

typedef struct virtualfree_event{
    HANDLE ProcessId;
    PVOID BaseAddress;
    ULONG RegionSize;
    ULONG FreeType;
    ULONG result;
}virtualfree_event;

typedef struct mapviewofsection_event{
    HANDLE ProcessId;
    HANDLE TargetPid;
    PVOID BaseAddress;
    ULONG ZeroBits;
    ULONG ViewSize;
    ULONG AllocationType;
    ULONG Protect;
    ULONG result;
}mapviewofsection_event;


#endif