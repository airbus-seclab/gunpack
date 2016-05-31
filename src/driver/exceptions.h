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

#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include "win_kernl.h"

#pragma pack(push,1)

typedef struct{
    ULONG_PTR Eax;
    ULONG_PTR Ecx;
    ULONG_PTR Edx;    
    ULONG_PTR Ebx;
    ULONG_PTR Esp;
    ULONG_PTR Esi;
    ULONG_PTR Edi;
    ULONG_PTR Eip;
} THE_CONTEXT;

typedef struct{
    THE_CONTEXT Ctx;
    HANDLE Pid;
    HANDLE Tid;
	PVOID AccessedAddress;
	ULONG AccessType;
	ULONG InDllLoad;
	LONG LockCount;
	LONG RecursionCount;
	HANDLE OwningThread;
	HANDLE CurrentThread;
	LONGLONG PhysicalAddress;
	ULONG_PTR DllBaseAddress;
} EXCEPTION_INFO, *PEXCEPTION_INFO;

#pragma pack(pop)

#endif