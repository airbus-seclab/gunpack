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

#ifndef EXCEPTIONS_LIST_H
#define EXCEPTIONS_LIST_H

#include "win_kernl.h"

#pragma pack(push,1)
typedef struct{
	PVOID AccessedAddress;
	ULONG AccessType;
	ULONG InDllLoad;
	LONG LockCount;
	LONG RecursionCount;
	HANDLE OwningThread;
	HANDLE CurrentThread;
	LONGLONG PhysicalAddress;
	ULONG_PTR Esp;
	ULONG_PTR Esp_top_value;
	USHORT DllName[MAX_PATH];
} EXCEPTION_INFO, *PEXCEPTION_INFO;

typedef struct{
	PVOID NextElement;
	EXCEPTION_INFO ExceptionInfo;
} EXCEPTION_ELEMENT, *PEXCEPTION_ELEMENT;

typedef struct{
	PEXCEPTION_ELEMENT FirstElement;
	PEXCEPTION_ELEMENT LastElement;
	ULONG Count;
} EXCEPTION_LIST, * PEXCEPTION_LIST;
#pragma pack(pop)

void InitExceptionList();
ULONG GetExceptionCount();
void AddExceptionToList(PEXCEPTION_INFO pExp);
void GetFirstException(PEXCEPTION_INFO pOutExp);
void CleanupExceptionsList();
void InitAccessArray();

#endif