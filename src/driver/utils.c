#include "win_kernl.h"
#include "utils.h"

extern proto_NtQueryVirtualMemory NtQueryVirtualMemory;
extern int do_log;

PVOID __declspec(naked) GetCurrentKThread()
{
	__asm{
		mov eax, fs:[124h]
		ret
	}
}

HANDLE GetProcessIdByhandle(HANDLE hProcess)
{
	int r;
	PEPROCESS pProcess = NULL;
	HANDLE Pid = (HANDLE)-1;
	
	if ( hProcess == (HANDLE)-1 )
	{
		pProcess = PsGetCurrentProcess();
		Pid = PsGetProcessId(pProcess);
	}
	else
	{
		r = ObReferenceObjectByHandle(hProcess,PROCESS_QUERY_INFORMATION,*PsProcessType,UserMode,&pProcess,NULL);
		if (r == STATUS_SUCCESS)
		{
			Pid = PsGetProcessId(pProcess);
			ObDereferenceObject(pProcess);
		}
		else
			Pid = (HANDLE)-1;
	}
	
	return Pid;
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
	ULONG retLen = 0;
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

				pdebug(do_log,"[FindSignatureInProcessModule] MemoryInfo.BaseAddress : %p, MemoryInfo.RegionSize = %x\n",MemoryInfo.BaseAddress, MemoryInfo.RegionSize);
				
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
			pdebug(do_log,"[FindSignatureInProcessModule] NtQueryVirtualMemory failed r = 0x%x\n",r);
			CurrentOffset += PAGE_SIZE;
		}

	}

	return result;
}

void disable_cr0()
{
	__asm
	{
		push eax
		mov eax, CR0
		and eax, 0FFFEFFFFh
		mov CR0, eax
		pop eax
	}

}

void enable_cr0()
{
	__asm
	{
		push eax
		mov eax, CR0
		or eax, NOT 0FFFEFFFFh
		mov CR0, eax
		pop eax
	}
}

unsigned char * ComputeBranchAddress(unsigned char * instr_offset)
{
	unsigned int delta;
	unsigned char * result;
	
	if ( (instr_offset[0] == 0xE8) || (instr_offset[0] == 0xE9) )
	{
		delta = *(unsigned int *)(instr_offset + 1);
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


PVOID __declspec(naked) get_cr3()
{
	__asm{
		mov eax, cr3
		ret
	};
}