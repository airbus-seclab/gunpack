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

#ifndef TRACKED_PROCESS_H
#define TRACKED_PROCESS_H

#include "win_kernl.h"

#define INVALID_PID 0xFFFFFFFF
#define PID_ARRAY_SIZE  32

void InitProcessArray();
int IsProcessInArray(HANDLE Pid);
int RemoveProcessFromArray(HANDLE Pid);
int AddTrackedProcess(HANDLE Pid);
int IsProcessTracked(HANDLE Pid);
void SuspendTrackedProcesses();
int GetTrackedInfo(HANDLE Pid, ULONG_PTR * pRwePage);
int SetTrackedRWEPage(HANDLE Pid, ULONG_PTR RwePage);
int GetFirstException(HANDLE Pid, int * first_excpt);
int SetFirstException(HANDLE Pid, int first_excpt);
int IsProcessSuspended(HANDLE Pid);
int SetProcessSuspended(HANDLE Pid);
int GetNextProcessInArray(HANDLE * pPid);
int RemoveProcessFromArray(HANDLE Pid);

typedef struct tracked_process_struct{
    HANDLE Pid;
    ULONG_PTR RwePage;
    int first_excpt;
    int suspended;
    int tracked;
} tracked_process_struct;

#endif