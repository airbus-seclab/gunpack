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

#include "exceptions_list.h"

EXCEPTION_LIST ExceptionList;
KSPIN_LOCK ListLock;

void InitExceptionList()
{
	PEXCEPTION_LIST pList = &ExceptionList;
	
	KeInitializeSpinLock(&ListLock);
	
	pList->FirstElement = NULL;
	pList->LastElement = NULL;
	pList->Count = 0;
}

ULONG GetExceptionCount()
{
	PEXCEPTION_LIST pList = &ExceptionList;
	KLOCK_QUEUE_HANDLE hLock;
	ULONG ListCount;
	
	//KeAcquireInStackQueuedSpinLock(&ListLock,&hLock);
	
	ListCount = pList->Count;
	
	//KeReleaseInStackQueuedSpinLock(&hLock);
	
	return ListCount;
}

void GetFirstException(PEXCEPTION_INFO pOutExp)
{
	PEXCEPTION_LIST pList = &ExceptionList;
	PEXCEPTION_ELEMENT pCurrentElement;
	KLOCK_QUEUE_HANDLE hLock;
	
	//KeAcquireInStackQueuedSpinLock(&ListLock,&hLock);
	
	pCurrentElement = pList->FirstElement;
	if (pCurrentElement)
	{
		memcpy(pOutExp,&pCurrentElement->ExceptionInfo,sizeof(EXCEPTION_INFO));
		
		pList->FirstElement = pList->FirstElement->NextElement;
		pList->Count--;
		
		ExFreePool(pCurrentElement);
	}
	
	//If list is empty remove dangling pointer
	if (pList->Count == 0)
	{
		pList->FirstElement = NULL;
		pList->LastElement = NULL;
	}
	
	//KeReleaseInStackQueuedSpinLock(&hLock);
}

void AddExceptionToList(PEXCEPTION_INFO pExp)
{
	PEXCEPTION_ELEMENT pNewElement;
	PEXCEPTION_LIST pList = &ExceptionList;
	KLOCK_QUEUE_HANDLE hLock;
	
	if (!pExp)
		return;
		
	//Allocate memory for new element
	pNewElement = ExAllocatePool(PagedPool,sizeof(EXCEPTION_ELEMENT));
	if(!pNewElement)
		return;
	
	//KeAcquireInStackQueuedSpinLock(&ListLock,&hLock);
	
	//Init new element
	pNewElement->NextElement = NULL;
	memcpy(&pNewElement->ExceptionInfo,pExp,sizeof(EXCEPTION_INFO));
	//If list is empty
	if( pList->FirstElement == NULL )
	{
		//The new element becomes the only element in the list
		pList->FirstElement = pNewElement;
		pList->LastElement = pNewElement;
		pList->Count = 1;
	}
	else
	{
		//If the list is not empty we add the element at the end of the list
		pList->LastElement->NextElement = pNewElement;
		pList->LastElement = pNewElement;
		pList->Count++;
	}
	
	//KeReleaseInStackQueuedSpinLock(&hLock);
		
	return;
}

//Retrieve all elements to cleanup the list
void CleanupExceptionsList()
{
	ULONG i = 0;
	EXCEPTION_INFO DummyException;
	KLOCK_QUEUE_HANDLE hLock;
	
	//KeAcquireInStackQueuedSpinLock(&ListLock,&hLock);
	
	for (i = 0 ; i < GetExceptionCount(); i++)
		GetFirstException(&DummyException);
		
	//KeReleaseInStackQueuedSpinLock(&hLock);
}