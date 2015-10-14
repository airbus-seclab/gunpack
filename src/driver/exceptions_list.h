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