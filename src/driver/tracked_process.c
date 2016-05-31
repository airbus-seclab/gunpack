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

#include "tracked_process.h"
#include "utils.h"

//unsigned int TargetPidCount = 0; 
tracked_process_struct TargetPidArray[PID_ARRAY_SIZE];

void InitProcessArray()
{
    unsigned int i;
    int r = 0;
    
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        TargetPidArray[i].Pid = (HANDLE)INVALID_PID;
        TargetPidArray[i].RwePage = 0;
        TargetPidArray[i].first_excpt = 1;
        TargetPidArray[i].suspended = 0;
        TargetPidArray[i].tracked = 0;
    }
}

int AddTrackedProcess(HANDLE Pid)
{
    unsigned int i;
    int r = 0;
    
    //Search the array for a free slot
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        //free slot found
        if (TargetPidArray[i].Pid == (HANDLE)INVALID_PID)
        {
            TargetPidArray[i].Pid = Pid;
            TargetPidArray[i].tracked = 1;
            //todo , init the other members
            r = 1;
            
            pdebug(1,"added process at index %d",i);
            
            break;
        }
    }

    return r;
}

int IsProcessInArray(HANDLE Pid)
{
    unsigned int i;
    int r = 0;
    
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        //pid found
        if (TargetPidArray[i].Pid == Pid)
        {
            r = 1;
        }
    }
    
    return r;
}

int GetNextProcessInArray(HANDLE * pPid)
{
    unsigned int i;
    int r = 0;
    
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        //pid found
        if ( (TargetPidArray[i].Pid != (HANDLE)INVALID_PID) )
        {
            *pPid = TargetPidArray[i].Pid;
            r = 1;
        }
    }
    
    return r;  
}

int RemoveProcessFromArray(HANDLE Pid)
{
    unsigned int i;
    int r = 0;
    
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        //pid found
        if (TargetPidArray[i].Pid == Pid)
        {
            TargetPidArray[i].Pid = (HANDLE)INVALID_PID;
            TargetPidArray[i].RwePage = 0;
            TargetPidArray[i].first_excpt = 1;
            TargetPidArray[i].suspended = 0;
            TargetPidArray[i].tracked = 0;            
            r = 1;
        }
    }
    
    return r;  
}

int IsProcessTracked(HANDLE Pid)
{
    unsigned int i;
    int r = 0;
    
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        //pid found
        if (TargetPidArray[i].Pid == Pid)
        {
            r = TargetPidArray[i].tracked;
        }
    }
    
    //pdebug(1,"Process %d not tracked",(ULONG_PTR)Pid);
    
    return r;
}

int SetProcessSuspended(HANDLE Pid)
{
    unsigned int i;
    int r = 0;
    
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        //pid found
        if (TargetPidArray[i].Pid == Pid)
        {
            r = TargetPidArray[i].suspended = 1;
        }
    }
    
    return r;
}

int IsProcessSuspended(HANDLE Pid)
{
    unsigned int i;
    int r = 0;
    
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        //pid found
        if (TargetPidArray[i].Pid == Pid)
        {
            r = TargetPidArray[i].suspended;
        }
    }
    
    return r;
}



int UnTrackProcess(HANDLE Pid)
{
    unsigned int i;
    int r = 0;
    
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        //pid found
        if (TargetPidArray[i].Pid == Pid)
        {
            TargetPidArray[i].tracked = 0;
            r = 1;
        }
    }
    
    return r;
}





int GetTrackedInfo(HANDLE Pid, ULONG_PTR * pRwePage)
{
    unsigned int i;
    int r = 0;
    
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        //pid found
        if (TargetPidArray[i].Pid == Pid)
        {
            r = 1;
            *pRwePage = TargetPidArray[i].RwePage;
        }
    }
    
    return r;
}

int SetTrackedRWEPage(HANDLE Pid, ULONG_PTR RwePage)
{
    unsigned int i;
    int r = 0;
    
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        //pid found
        if (TargetPidArray[i].Pid == Pid)
        {
            r = 1;
            TargetPidArray[i].RwePage = RwePage;
        }
    }
    
    return r;
}

int GetFirstException(HANDLE Pid, int * first_excpt)
{
    unsigned int i;
    int r = 0;
    
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        //pid found
        if (TargetPidArray[i].Pid == Pid)
        {
            r = 1;
            *first_excpt = TargetPidArray[i].first_excpt;
        }
    }
    
    return r;
}

int SetFirstException(HANDLE Pid, int first_excpt)
{
    unsigned int i;
    int r = 0;
    
    for (i=0; i < PID_ARRAY_SIZE; i++)
    {
        //pid found
        if (TargetPidArray[i].Pid == Pid)
        {
            r = 1;
            TargetPidArray[i].first_excpt = first_excpt;
        }
    }
    
    return r;
}