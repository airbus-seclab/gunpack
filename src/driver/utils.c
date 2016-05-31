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

#include "win_kernl.h"
#include "utils.h"
#include "memory_state.h"
#include "tracked_process.h"
#include "DriverDefs.h"

extern proto_NtQueryVirtualMemory NtQueryVirtualMemory;
extern ConfigStruct GlobalConfigStruct;
extern unsigned int TargetPidArray[];
extern unsigned int TargetPidCount;
extern proto_PsGetNextProcess PsGetNextProcess;
extern proto_PsSuspendProcess PsSuspendProcess;
extern proto_PsTerminateProcess PsTerminateProcess;
extern proto_PsResumeProcess PsResumeProcess;


void DisplayPageFilePTE(LARGE_INTEGER l)
{
    PTE pte;
    ULONG PageFileOffset;
    
    pte.raw = l;
    
    //Not interested in present PTE
    if ( pte.pte.present )
    {
        return;
    }
    
    //Not interested int Unknown PTE
    if ( pte.raw.LowPart == 0 )
        return;
    
    //Not prototype PTE neither transition PTE
    //This should be a page file PTE
    if ( !pte.pte.prototype && !pte.pte.reserved )
    {

        PageFileOffset = pte.raw.LowPart >> 12;
        
        if (PageFileOffset != 0)
            pdebug(1,"High : 0x%x, Low : 0x%x", pte.raw.HighPart, pte.raw.LowPart);
                
    }
}

void * FindSignatureWithHoles(unsigned char * Start, unsigned int max_size, unsigned char * Signature, unsigned int SignatureSize)
{
	unsigned int i,j;
	unsigned char * p;
	char found;
	
	p = Start;
	
	for (i = 0; i< max_size; i++)
	{
		found=1;
		j=0;
		
		while ((j<SignatureSize) && found)
		{
			if ( (Signature[j] != 0) && ( Signature[j] != p[j] ) )
			{
				found = 0;
			}
			j++;
		}
	
		if (found)
		{
			return p;
		}
		
		p = p + 1;
	}
	
	return NULL;
}

void * FindSignature(unsigned char * Start, unsigned int max_size, unsigned char * Signature, unsigned int SignatureSize)
{
	unsigned int i;
	unsigned char * p;
	
	p = Start;
	
	for (i=0; i < max_size; i ++)
	{
		
		if (memcmp(Signature,p,SignatureSize) == 0)
		{
			return p;
		}

		p = p + 1;
	}
	
	return NULL;
}

void * FindSignatureInProcessModule(PEPROCESS ProcessObj, HANDLE hProcess, unsigned char * StartAddress, ULONG_PTR Size, unsigned char * Signature, ULONG SignatureSize)
{
	MEMORY_BASIC_INFORMATION32 MemoryInfo;
	SIZE_T retLen = 0;
	ULONG_PTR CurrentOffset = 0;
	NTSTATUS r;
	int loop = 1;
	unsigned char PreviousMode;
	unsigned char *p = NULL;
	KAPC_STATE ApcState;
	void * result = NULL;
	unsigned char previous_mode;
	
	while( (CurrentOffset < Size) && loop )
	{
		memset(&MemoryInfo,0,sizeof(MemoryInfo));
		retLen = sizeof(MEMORY_BASIC_INFORMATION32);

		r = ZwQueryVirtualMemory(hProcess,(void *)(StartAddress + CurrentOffset),0,&MemoryInfo,sizeof(MEMORY_BASIC_INFORMATION32),&retLen);
		if ( r == STATUS_SUCCESS )
		{
			if ((MemoryInfo.State == MEM_COMMIT) && (MemoryInfo.Protect == PAGE_EXECUTE_READ) && (MemoryInfo.Type == MEM_IMAGE))
			{
				//Attach kernel to the target process
				KeStackAttachProcess(ProcessObj,&ApcState);			

				pdebug(GlobalConfigStruct.debug_log,"[FindSignatureInProcessModule] MemoryInfo.BaseAddress : %p, MemoryInfo.RegionSize = %x\n",MemoryInfo.BaseAddress, MemoryInfo.RegionSize);
				
				p = FindSignature((unsigned char *)MemoryInfo.BaseAddress, MemoryInfo.RegionSize, Signature, SignatureSize);
				if (p)
				{
					result = p;
					loop = 0;
				}
				
				KeUnstackDetachProcess(&ApcState);	
			}
			
			CurrentOffset += MemoryInfo.RegionSize;
		}
		else
		{
			pdebug(GlobalConfigStruct.debug_log,"[FindSignatureInProcessModule] NtQueryVirtualMemory failed r = 0x%x\n",r);
			CurrentOffset += PAGE_SIZE;
		}

	}

	return result;
}

unsigned char * ComputeBranchAddress(unsigned char * instr_offset)
{
	int delta;
	unsigned char * result;
	
	if ( (instr_offset[0] == 0xE8) || (instr_offset[0] == 0xE9) )
	{
		delta = *(int *)(instr_offset + 1);
		result = instr_offset + delta + 5;
		return result;
	}
	else
		return NULL;
}

int PatchBranch(int BranchType, unsigned char * offset, unsigned char * BranchTarget)
{
	if (BranchType == JMP_FAR)
		offset[0] = 0xE9;
	else if (BranchType == CALL)
		offset[0] = 0xE8;
	else
		return 0;
		
	*(unsigned int *)(offset + 1) = (unsigned int)BranchTarget - (unsigned int)offset - 5;

	return 1;
}

PVOID GetVadRoot( PEPROCESS process )
{
	PMYEPROCESS pProcess;
	
	pProcess = (PMYEPROCESS)PsGetCurrentProcess();
	
	if ( pProcess->VadRoot.BalancedRoot.RightChild )
		return pProcess->VadRoot.BalancedRoot.RightChild;
	else
		return pProcess->VadRoot.BalancedRoot.LeftChild;		
}

void SuspendTrackedProcesses()
{
    PEPROCESS Current = NULL;
    
    pdebug(1,"SuspendTrackedProcesses called ");
    
    //Iterate over all running processes
    do 
    {
        Current = PsGetNextProcess(Current);
        if (Current)
        {
            //pdebug(1,"pid = %d",Current->UniqueProcessId);
            //Suspend tracked processes
            if ( IsProcessTracked(Current->UniqueProcessId) )
            {
                SetProcessSuspended(Current->UniqueProcessId);
                //pdebug(1,"Suspending process pid(%d)",Current->UniqueProcessId);
                PsSuspendProcess(Current);
            }
        }
    }while(Current);
}

void ResumeAndUntrackProcesses()
{
    PEPROCESS Current = NULL;
    
    pdebug(1,"SuspendTrackedProcesses called ");
    
    //Iterate over all running processes
    do 
    {
        Current = PsGetNextProcess(Current);
        if (Current)
        {
            pdebug(1,"pid = %d",Current->UniqueProcessId);
            
            //Suspend tracked processes
            if ( IsProcessTracked(Current->UniqueProcessId) )
            {
                UnTrackProcess(Current->UniqueProcessId);
                pdebug(1,"resuming tracked process pid(%d)",Current->UniqueProcessId);
                PsResumeProcess(Current);
            }
        }
    }while(Current);
}


void SuspendTrackedProcess(HANDLE Pid)
{
    NTSTATUS r;
    HANDLE TargetProcess;
    CLIENT_ID TargetProcessId;
    OBJECT_ATTRIBUTES objAttr;
    PEPROCESS ProcessObj;
    
    if (IsProcessTracked(Pid))
    { 

        memset(&objAttr,0,sizeof(objAttr));
        objAttr.Length = sizeof(objAttr);
        
        TargetProcessId.UniqueThread = NULL;
        TargetProcessId.UniqueProcess = Pid;

        r = ZwOpenProcess(&TargetProcess, PROCESS_SUSPEND_RESUME, &objAttr, &TargetProcessId);
        if(r == STATUS_SUCCESS)
        {
            r = ObReferenceObjectByHandle(TargetProcess,PROCESS_SUSPEND_RESUME,*PsProcessType,UserMode,&ProcessObj,NULL);
			if( r == STATUS_SUCCESS )
			{
                if ( PsSuspendProcess(ProcessObj) != STATUS_SUCCESS )
                {
                    pdebug(1,"PsSuspendProcess failed !\n");
                }
                
                ObDereferenceObject(ProcessObj);
            }
            else
            {
                pdebug(1,"ObReferenceObjectByHandle failed !\n");
            }

            ZwClose(TargetProcess);
            TargetProcess = NULL;
        }
        else
            pdebug(1,"ZwOpenProcess failed !\n");
    }
}


void TerminateProcesses()
{
    HANDLE Pid = NULL;
    HANDLE TargetProcess;
    CLIENT_ID TargetProcessId;
    OBJECT_ATTRIBUTES objAttr;
    NTSTATUS r;
               
    while ( GetNextProcessInArray(&Pid) && (Pid != NULL) )
    {
        memset(&objAttr,0,sizeof(objAttr));
        objAttr.Length = sizeof(objAttr);
        
        TargetProcessId.UniqueThread = NULL;
        TargetProcessId.UniqueProcess = Pid;
        
        r = ZwOpenProcess(&TargetProcess, PROCESS_TERMINATE, &objAttr, &TargetProcessId);
        if(r == STATUS_SUCCESS)
        {
            if (RemoveProcessFromArray(Pid) == 0)
                pdebug(1,"RemoveProcessFromArray failed\n");
            
            if (ZwTerminateProcess(TargetProcess,0) != STATUS_SUCCESS)
                pdebug(1,"ZwTerminateProcess failed\n");
            else
                pdebug(1,"ZwTerminateProcess succeeded\n");
            
            ZwClose(TargetProcess);
            TargetProcess = NULL;
        }   
    }    
}
