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

#ifndef SINGLE_STEP_H
#define SINGLE_STEP_H

#include "win_kernl.h"

#define MAX_ACCESS_ARRAY_SIZE 512
#define SLOT_USED 1
#define SLOT_FREE 0 

typedef struct{
	HANDLE OwningThread;
	PVOID AccessedAddress;
	ULONG State;
} KernelSingleStepAccess;

typedef struct{
	HANDLE OwningThread;
	ULONG State;
} UserSingleStepAccess;

void InitAccessArray();
int IsThreadSingleStepped(HANDLE OwningThread);
int AddSingleStepThread(HANDLE OwningThread);
PVOID GetAccessAddressOfThread(HANDLE OwningThread);
int AddAccessAddress(HANDLE OwningThread, PVOID AccessedAddress);

#endif