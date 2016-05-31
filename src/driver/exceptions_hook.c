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

#include "includes.h"

extern ConfigStruct GlobalConfigStruct;
extern PLDR_DATA_TABLE_ENTRY * LdrpCurrentDllInitializer;
extern PRTL_CRITICAL_SECTION LdrpLoaderLock;
extern ULONG_PTR * MmUserProbeAddress;
extern ULONG MmProtectValues[32];
extern proto_MmAccessFault MmAccessFault;
extern int log_exceptions;
unsigned char * call_to_MmAccessFault = NULL;

proto_KeContextFromKframes KeContextFromKframes = NULL;
unsigned char * KiDispatchException_continue = NULL;
unsigned char * call_to_KeContextFromKframes = NULL;
unsigned char * KiDispatchException_end = NULL;

extern proto_MiCopyOnWrite MiCopyOnWrite;
extern proto_NtProtectVirtualMemory NtProtectVirtualMemory;

int CONVENTION do_exception_filter(PEXCEPTION_RECORD pExp, void * pKexp, PKTRAP_FRAME pTrap, int PreviousMode, int FirstChance);
void * do_exception_filter_ptr = do_exception_filter;
void HookInKiDispatchException(void);


ULONG RetrieveEspTop(ULONG * pEsp)
{
	try
	{
		ProbeForRead(pEsp,sizeof(ULONG),1);
		
		return *pEsp;
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		return 0;
	}
}

void RetrieveExceptionInfo(PEXCEPTION_INFO pExceptionInfo, ULONG AccessViolationType,PVOID AccessedAddress, PKTRAP_FRAME pTrap, int a)
{
	PLDR_DATA_TABLE_ENTRY pEntry;
	PTE * ppte_virtual = NULL;
	
	if( ! LdrpLoaderLock )
	{
		pdebug(GlobalConfigStruct.debug_log,"[RetrieveExceptionInfo] LdrpLoaderLock is null\n");
		return;
	}
	
	if (! LdrpCurrentDllInitializer )
	{
		pdebug(GlobalConfigStruct.debug_log,"[RetrieveExceptionInfo] LdrpCurrentDllInitializer is null\n");
		return;
	}
	
	try
	{
		ProbeForRead(LdrpLoaderLock,sizeof(LdrpLoaderLock),4);
		ProbeForRead(LdrpCurrentDllInitializer,sizeof(LdrpCurrentDllInitializer),4);
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		return;
	}
	
	memset(pExceptionInfo,0,sizeof(EXCEPTION_INFO));
	
	//Retrieve the loader current entry from userland
	pEntry = *LdrpCurrentDllInitializer;
	//
    pExceptionInfo->Pid = PsGetCurrentProcessId();
    pExceptionInfo->Tid = PsGetCurrentThreadId();
	pExceptionInfo->AccessType = AccessViolationType;
	pExceptionInfo->AccessedAddress = AccessedAddress;
	pExceptionInfo->LockCount = LdrpLoaderLock->LockCount;
	pExceptionInfo->RecursionCount = LdrpLoaderLock->RecursionCount;
	pExceptionInfo->OwningThread = LdrpLoaderLock->OwningThread;
	pExceptionInfo->CurrentThread = PsGetCurrentThreadId();
    
    pExceptionInfo->Ctx.Eax = pTrap->Eax;
    pExceptionInfo->Ctx.Ecx = pTrap->Ecx;
    pExceptionInfo->Ctx.Edx = pTrap->Edx;
    pExceptionInfo->Ctx.Ebx = pTrap->Ebx;
    pExceptionInfo->Ctx.Esp = pTrap->HardwareEsp;
    pExceptionInfo->Ctx.Esi = pTrap->Esi;
    pExceptionInfo->Ctx.Edi = pTrap->Edi;
    pExceptionInfo->Ctx.Eip = pTrap->Eip;    

	ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS((DWORD_PTR)AccessedAddress);
	if (ppte_virtual->pte.present)
	{
		pExceptionInfo->PhysicalAddress = (ppte_virtual->pte.address << 0xC) + ((DWORD_PTR)AccessedAddress & 0xFFF);
		pdebug(GlobalConfigStruct.debug_log,"[RetrieveExceptionInfo] Pte present, physical : 0x%x\n",ppte_virtual->pte.address);
	}
	else
	{
		pdebug(GlobalConfigStruct.debug_log,"[RetrieveExceptionInfo] Pte not present\n");
		pExceptionInfo->PhysicalAddress = 0xffffffffffffffff;
	}
	
	if (pEntry)
	{
		ULONG CopySize;
		
		pdebug(GlobalConfigStruct.debug_log,"[RetrieveExceptionInfo] DllBase : %p\n", pEntry->DllBase);
		pdebug(GlobalConfigStruct.debug_log,"[RetrieveExceptionInfo] BaseDllName : %S\n", pEntry->BaseDllName.Buffer);
		pdebug(GlobalConfigStruct.debug_log,"[RetrieveExceptionInfo] FullDllName : %S\n", pEntry->FullDllName.Buffer);
		
		pExceptionInfo->InDllLoad = 1;
		
		CopySize = min( MAX_PATH*sizeof(USHORT), pEntry->FullDllName.Length*sizeof(USHORT) );
		
		try
		{
			ProbeForRead(pEntry->FullDllName.Buffer,CopySize,1);
			//memcpy(&pExceptionInfo->DllName,pEntry->FullDllName.Buffer ,CopySize);		
		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			return;
		}
		
	}
	else
	{
		pExceptionInfo->InDllLoad = 0;
	}
}

int TreatKernellandException(ULONG_PTR ExceptionCode,ULONG_PTR AccessViolationType,ULONG_PTR AccessedAddress, PKTRAP_FRAME pTrap)
{
	NTSTATUS r;
	PVOID LastAccessedAddress = NULL;
	
	//Handle single-step exceptions
	if ( ExceptionCode == STATUS_SINGLE_STEP )
	{
		LastAccessedAddress = GetAccessAddressOfThread(PsGetCurrentThreadId());
		if(!LastAccessedAddress)
		{
			pdebug(GlobalConfigStruct.debug_log,"[TreatKernellandException] Oops GetAccessAddressOfThread failed !\n");
		}
		
		//Set page !WRITE & EXEC
		r = SetMemoryProtectionPae2( (ULONG_PTR)LastAccessedAddress, 0, 1 );
		pTrap->EFlags &= 0xFEFF;
		return 1;
	}

	//If eip and accessed address are in the same page
	if ( (AccessViolationType == WRITE_ACCESS) )
	{
		if( !AddAccessAddress(PsGetCurrentThreadId(),(PVOID)AccessedAddress))
		{
			pdebug(GlobalConfigStruct.debug_log,"[TreatKernellandException] Oops AddAccessAddress failed !\n");
		}
		
		SetMemoryProtectionPae2( AccessedAddress, 1, 0 );
		pTrap->EFlags |= 0x0100;
		return 1;
	}
	
	return 0;
}

int CONVENTION do_exception_filter(PEXCEPTION_RECORD pExp, void * pKexp, PKTRAP_FRAME pTrap, int PreviousMode, int FirstChance)
{
	int i;
	unsigned int * p;
	int result = 0;
    ULONG_PTR InstructionPointer = 0;
    ULONG_PTR  * test;

    //return pouet_orginal(pExp,pKexp,pTrap,PreviousMode,FirstChance);

	//
	// We catch only first chance exceptions
	//
	if ( !FirstChance )
		return result;
		
	//
	// Ensure that pExp and pTrap are both not null
	//
	if ( !pExp )
		return result;
	
	if ( !pTrap )
		return result;
        

    InstructionPointer = pTrap->Eip;    
    
	//
	// Ensure we are on the right process
	//
    if( IsProcessTracked(PsGetCurrentProcessId()) == 0 )
        return result;	
	
	//
	// We are only interested in STATUS_SINGLE_STEP exceptions caused by the
	//
	if ( pExp->ExceptionCode == STATUS_SINGLE_STEP )
	{

		if ( InstructionPointer  < *MmUserProbeAddress )
		{
			//Ensure the single-step was induced by our driver and not by the process itself
			if ( IsThreadSingleStepped(PsGetCurrentThreadId()) )
			{
				pdebug(GlobalConfigStruct.debug_log,"[do_exception_filter] SINGLE_STEP in userland, Eip = %p\n",InstructionPointer);
				//
				// Set page protection back to EXECUTE and not(WRITE)
				//
				if (SetMemoryProtectionPae2(InstructionPointer, 0, 1))
				{
					pdebug(GlobalConfigStruct.debug_log,"[do_exception_filter] Unactivate single-step\n");
					pTrap->EFlags &= 0xFEFF;
					return 1;
				}
			}
			else
			{
				pdebug(GlobalConfigStruct.debug_log,"[do_exception_filter] Not our SINGLE_STEP in userland, Eip = %p\n",InstructionPointer);
			}
		}
		else
		{
			pdebug(GlobalConfigStruct.debug_log,"[do_exception_filter] SINGLE_STEP in kernelland, Eip = %p\n",InstructionPointer);
			
			result = TreatKernellandException(STATUS_SINGLE_STEP,0,0,pTrap);
		}
	}
	
	return result;
}

/*
	IsARealFault determines if the fault generated is a "real" fault in the monitored program
	or a fault induced by our PTE modifications.
*/
int IsARealFault(ULONG_PTR FaultStatus, ULONG_PTR FaultAddress)
{
	PMMVAD VadRoot, FaultingVad;
	ULONG Protect;
	int result = 1;	
	
	Protect = GetVadMemoryProtect(FaultAddress);
	if (Protect == 0)
	{
		pdebug(GlobalConfigStruct.debug_log,"[IsARealFault] GetVadMemoryProtect failed! Returning true.\n");
		return 1;
	}
	
	if ( ShouldItFault(FaultStatus, Protect) )
	{
		result = 1;
	}
	else
		result = 0;
		
	pdebug(GlobalConfigStruct.debug_log,"[IsARealFault] ShouldItFault returned %d\n",result);
	pdebug(GlobalConfigStruct.debug_log,"[IsARealFault] FaultStatus %d, Protect : 0x%x\n",FaultStatus,Protect);
	
	return result;
}

// 
// Triggers copy on write at page level on a page that needs it.
// 
void HandleCopyOnWrite(ULONG BaseAddress)
{
	PMMVAD VadRoot, CurrentVad;
	ULONG Protect, ReturnedProtect;
	PTE * ppte_virtual = NULL;
	int r;
	PVOID NextVa;
	
	VadRoot = (PMMVAD)GetVadRoot(PsGetCurrentProcess());	

	pdebug(GlobalConfigStruct.debug_log,"[HandleCopyOnWrite] Vad root : 0x%x\n",VadRoot);	
	
	CurrentVad = LocateVadForPage(VadRoot, (ULONG)BaseAddress >> 0xC);
	if (!CurrentVad)
	{
		pdebug(GlobalConfigStruct.debug_log,"[HandleCopyOnWrite] No vad found !!\n");
		return;
	}
	
	Protect = MmProtectValues[CurrentVad->u.Protection];
	pdebug(GlobalConfigStruct.debug_log,"[HandleCopyOnWrite] Page 0x%x is at protect : 0x%x\n",BaseAddress,Protect);
	
	if ( (Protect & PAGE_WRITECOPY) || (Protect & PAGE_EXECUTE_WRITECOPY)  )
	{
		pdebug(GlobalConfigStruct.debug_log,"[HandleCopyOnWrite] Page 0x%x needs copy on write\n",BaseAddress);
			
		ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(BaseAddress);
		
		if ( ppte_virtual->raw.LowPart == 0 )
		{
			pdebug(GlobalConfigStruct.debug_log,"[HandleCopyOnWrite] PTE is NULL\n");
			MmAccessFault(FALSE, (PVOID)BaseAddress, UserMode, NULL);
		}
		
		if ( ppte_virtual->pte.present == 0 )
		{
			pdebug(GlobalConfigStruct.debug_log,"[HandleCopyOnWrite] PTE is not present\n");
			return;		
		}
		
		if ( (ppte_virtual->pte.d) || (ppte_virtual->pte.reserved) )
		{
			pdebug(GlobalConfigStruct.debug_log,"[HandleCopyOnWrite] PTE is already copy on write !\n");
			return;
		}
		
		if ( ppte_virtual->pte.present )
		{
			pdebug(GlobalConfigStruct.debug_log,"[HandleCopyOnWrite] chatte !\n");
			
			r = MiCopyOnWrite((PVOID)BaseAddress ,ppte_virtual);
		}
		else
			pdebug(GlobalConfigStruct.debug_log,"[HandleCopyOnWrite] pas chatte !\n");		
	}
	
	return;
}

void DisplayPTE(ULONG_PTR Page)
{
	PTE * ppte_virtual = NULL;

	// We hope pte virtual address is mapped...
	// We're feeling lucky
	ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(Page);
	
	pdebug(GlobalConfigStruct.debug_log,"[DisplayPTE] PTE High = 0x%x, Low = 0x%x\n",ppte_virtual->raw.HighPart, ppte_virtual->raw.LowPart);
}

void HandleRead(ULONG_PTR VirtualAddress)
{
    PTE * ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(VirtualAddress);
    unsigned int Writable, Executable;
    
    if( !ppte_virtual->pte.present )
    {
        //PTE is not present
        MmAccessFault(READ_ACCESS,(PVOID)VirtualAddress,UserMode,NULL);
        
        if( ppte_virtual->pte.present )
        {

            //Retrieve tracked info for this PTE
            GetTrackedPageInfo(VirtualAddress, &Writable, &Executable);

            //Reset this info
            SetTrackedPageInfo(VirtualAddress, Writable, Executable);
        }
    }    
}

NTSTATUS CONVENTION HookInMmAccessFault(ULONG_PTR FaultStatus,PVOID VirtualAddress,KPROCESSOR_MODE PreviousMode,PKTRAP_FRAME pTrap)
{
	//unsigned int current_pid;
	NTSTATUS result;
	ULONG VadProtect;
	PTE * ppte_virtual;
    int first_except = 0;
    HANDLE CurrentPid = PsGetCurrentProcessId();
    ULONG_PTR InstructionPointer = 0;
	
	ULONG_PTR AccessedAddress = (ULONG_PTR)VirtualAddress;
	EXCEPTION_INFO CurrentException;

	if (!pTrap)
		goto regular_treatment;
    
    
    InstructionPointer = pTrap->Eip;    
   
	//
	// Ensure we are on the right process
    //
    if ( IsProcessTracked(CurrentPid)==0)
        goto regular_treatment;
    
	//
	// TODO : try to do this somewhere else
	// We change the process protection to execute only on the very first exception of the process
	//
    if (!GetFirstException(CurrentPid,&first_except))
        goto regular_treatment;

	if (first_except)
	{
		PMMVAD VadRoot;
		
		SetFirstException(CurrentPid,0);
		ClearTrackedPages();
		VadRoot = (PMMVAD)GetVadRoot( PsGetCurrentProcess() );
		ParseProcessVad(VadRoot);
	}
    
	pdebug(GlobalConfigStruct.debug_log,"[HookInMmAccessFault] VirtualAddress = 0x%x, FaultStatus : 0x%x\n",VirtualAddress, FaultStatus);
    
	// 
	// Never modify kernel virtual address space
	// 
	if ( AccessedAddress >= *MmUserProbeAddress )
		goto regular_treatment;
	    
	//If page not tracked we exit
	if ( IsTrackedPage((ULONG_PTR)VirtualAddress) == 0 )
	{
		pdebug(GlobalConfigStruct.debug_log,"[HookInMmAccessFault] Page not tracked, regular treatment\n");
		goto regular_treatment;
	}
    
	// 
	// Access faults on read instructions are not handled, we pass it to MmAccessFault right away
	// 
	if ( (FaultStatus == READ_ACCESS) )
    {
        HandleRead(AccessedAddress);
		return STATUS_SUCCESS;
	}    

	if ( IsARealFault(FaultStatus,AccessedAddress) )
	{
		pdebug(GlobalConfigStruct.debug_log,"real fault at 0x%x\n",AccessedAddress);
		pdebug(GlobalConfigStruct.debug_log,"returning STATUS_ACCESS_VIOLATION\n");
		return STATUS_ACCESS_VIOLATION;
	}
	
	pdebug(GlobalConfigStruct.debug_log,"[HookInMmAccessFault] Treating exception on tracked page\n");
	
	//Userland exception
	if ( InstructionPointer <= *MmUserProbeAddress )
	{
		//
		// Retrieve information about the loader in the EXCEPTION_INFO structure and add it to the list
		//
		RetrieveExceptionInfo(&CurrentException,FaultStatus,(PVOID)AccessedAddress, pTrap, 1);
        
        //Send exception information to userland
        AddEventToBuffer(EVENT_EXCEPTION , sizeof(CurrentException), (PVOID)&CurrentException);
        
        // If Eip and AccessedAddress are in the same page we need a spacial treatment
        // It is a self modifying page
        if (  (FaultStatus == WRITE_ACCESS) && ( (InstructionPointer & PAGE_MASK) == (AccessedAddress & PAGE_MASK) ) )
        {
            /*
                There are two stategies :
                    - One is to put the page in RWX and then to single-step one instruction it is very slow
                    - One is to keep this page in RWX until the next WRITE Exception happens
            */
            
            //Next block implements single-step strategy
            if (GlobalConfigStruct.RWEPolicy == RWE_SINGLE_STEP)
            {
                //Set memory protection to both writable and executable
                SetMemoryProtectionPae2(AccessedAddress, 1, 1);
            
                pdebug(GlobalConfigStruct.debug_log,"[HookInMmAccessFault] Activate single-step\n");
                
                //Remember that there is a pending single-step on this userland thread
                AddSingleStepThread(PsGetCurrentThreadId());
                
                //Activate single-step of userland process
                pTrap->EFlags |= 0x100;
                
                //resume process execution
                return STATUS_SUCCESS;
            }
            //Next block implements RWE page strategy
            else
            {
                ULONG_PTR RwePage = 0;
                
                //Get Previous RwePage info
                if (GetTrackedInfo(PsGetCurrentProcessId(), &RwePage))
                {
                    //If another page is already RWE, set it back to RX
                    if (RwePage != 0)
                    {
                        SetMemoryProtectionPae2(RwePage, 0, 1);
                    }
                }
                
                //Set memory protection to both writable and executable
                //on the accessed address
                SetMemoryProtectionPae2(AccessedAddress, 1, 1);
                
                //AccessedAddress is now the allowed RwePage for the current process
                SetTrackedRWEPage(PsGetCurrentProcessId(), AccessedAddress);
                
                return STATUS_SUCCESS;
            }
        }
        
		/*
		   If fault on write access on memory, change its PTE to make it writable but not executable
		   If fault on execute access do the opposite
		*/
		if ( FaultStatus == WRITE_ACCESS )
		{
            //If we are in the RWE page case
            if (GlobalConfigStruct.RWEPolicy == RWE_SINGLE_PAGE)
            {
                
                /*
                    Remove the RWE page of the tracked process if any
                */
                
                ULONG_PTR RwePage = 0;
                
                //Get Previous RwePage info
                if (GetTrackedInfo(PsGetCurrentProcessId(), &RwePage))
                {
                    if (RwePage != 0)
                    {
                        //Set page protection back to RX
                        SetMemoryProtectionPae2(RwePage, 0, 1);
                        
                        pdebug(1,"Disable RWE page\n");
                        
                        //Set the RWE page info to 0
                        SetTrackedRWEPage(PsGetCurrentProcessId(), 0);                                                 
                    }
                }
            }
            
            SetMemoryProtectionPae2((ULONG)AccessedAddress,1,0 );
		}
		else if ( FaultStatus == EXECUTE_ACCESS )
		{
			SetMemoryProtectionPae2((ULONG)AccessedAddress,0,1 );		
		}
		else
			pdebug(GlobalConfigStruct.debug_log,"[HookInMmAccessFault] WTF ???!!\n");
	}
	else
	{
		pdebug(GlobalConfigStruct.debug_log,"[HookInMmAccessFault] kernelland exception, eip = 0x%p\n, AccessedAddress = 0x%x\n", InstructionPointer, AccessedAddress );
		
		TreatKernellandException(0,FaultStatus,AccessedAddress,pTrap);
	}
	
	//
	// Resume thread's execution without going through exception handling 
	//
	return STATUS_SUCCESS;
	
regular_treatment:

	return MmAccessFault(FaultStatus, VirtualAddress, PreviousMode, pTrap);
}

int UnHookExceptionDispatcher()
{
	cr0_disable_write_protect();
	PatchBranch(CALL,call_to_KeContextFromKframes,(unsigned char *)KeContextFromKframes);
	cr0_enable_write_protect();
	
	return 1;
}

int UnHookKiTrap0E()
{
	cr0_disable_write_protect();
	PatchBranch(CALL,call_to_MmAccessFault,(unsigned char *)MmAccessFault);
	cr0_enable_write_protect();
	
	return 1;
}

int HookKiTrap0E(PVOID KernelImageBase, ULONG KernelImageSize)
{
	unsigned char before_MmAccessFaultCall[] =   {0x55,0x8B,0x45,0x6C,0x83,0xE0,0x01,0x50,0x57,0x8B,0x00,0x64,0xD1,0x00,0x23,0x00};
	
	call_to_MmAccessFault = FindSignatureWithHoles(KernelImageBase,KernelImageSize,before_MmAccessFaultCall,sizeof(before_MmAccessFaultCall));
	if (!call_to_MmAccessFault)
	{
		pdebug(GlobalConfigStruct.debug_log,"[HookKiTrap0E] Error : unable to find before_MmAccessFaultCall\n");
		return 0;
	}
	
	//There's a delta because the kernel uses a global variable which my be relocated
	call_to_MmAccessFault += (5 + sizeof(before_MmAccessFaultCall));
	
	pdebug(GlobalConfigStruct.debug_log,"[HookKiTrap0E] call_to_MmAccessFault : 0x%x\n",call_to_MmAccessFault);
	
	//Compute the MmAccessFault address
	MmAccessFault = (proto_MmAccessFault)ComputeBranchAddress(call_to_MmAccessFault);
	if(!MmAccessFault)
	{
		return 0;
	}	

	pdebug(GlobalConfigStruct.debug_log,"[HookKiTrap0E] MmAccessFault : 0x%x\n",MmAccessFault);
		
	cr0_disable_write_protect();
	PatchBranch(CALL,call_to_MmAccessFault,(unsigned char *)HookInMmAccessFault);
	cr0_enable_write_protect();
    
	return 1;
}


int HookExceptionDispatcher(PVOID KernelImageBase, ULONG KernelImageSize)
{
	unsigned char * r = NULL;
	unsigned char inside_KiDispatchException_signature[] = {0x89,0x65,0xE8,0x8B,0xFC,0x89,0x7D,0xBC,0x8D,0x45,0xD8,0x50};
	unsigned char endof_KiDispatchException_signature[] = {0x8D,0xA5,0xE8,0xFE,0xFF,0xFF};
	unsigned char before_KeContextFromKframes_call_signature[] = {0x57,0xFF,0x75,0x0C,0xFF,0x75,0x10};
		
	r = FindSignature(KernelImageBase,KernelImageSize,inside_KiDispatchException_signature,sizeof(inside_KiDispatchException_signature));
	if (!r)
	{
		pdebug(GlobalConfigStruct.debug_log,"[HookExceptionDispatcher] Error : unable to find inside_KiDispatchException_signature\n");		
		return 0;
	}
	
	KiDispatchException_end = FindSignature((void *)r,0x1000,endof_KiDispatchException_signature,sizeof(endof_KiDispatchException_signature));
	if(!KiDispatchException_end)
	{
		pdebug(GlobalConfigStruct.debug_log,"[HookExceptionDispatcher] Error : unable to find endof_KiDispatchException_signature\n");
		return 0;
	}
	
	call_to_KeContextFromKframes = FindSignature((void *)r,0x1000,before_KeContextFromKframes_call_signature,sizeof(before_KeContextFromKframes_call_signature));
	if(!call_to_KeContextFromKframes)
	{
		pdebug(GlobalConfigStruct.debug_log,"[HookExceptionDispatcher] Error : unable to find before_KeContextFromKframes_call_signature\n");
		return 0;
	}
	
	//switch to the call
	call_to_KeContextFromKframes += sizeof(before_KeContextFromKframes_call_signature);
	
	//The KiDispatchException_continue is located at the return of the call
	KiDispatchException_continue = call_to_KeContextFromKframes + 5;
	
	//Compute the KeContextFromKframes address
	KeContextFromKframes = (proto_KeContextFromKframes)ComputeBranchAddress(call_to_KeContextFromKframes);
	if(!KeContextFromKframes)
	{
		return 0;
	}
	
	pdebug(1,"[HookExceptionDispatcher] KeContextFromKframes =  0x%p\n",KeContextFromKframes);	
	pdebug(1,"[HookExceptionDispatcher] KiDispatchException_end =  0x%p\n",KiDispatchException_end);
	pdebug(1,"[HookExceptionDispatcher] KiDispatchException_continue =  0x%p\n",KiDispatchException_continue);
    
	cr0_disable_write_protect();
	PatchBranch(JMP_FAR,call_to_KeContextFromKframes,(unsigned char *)HookInKiDispatchException);
	cr0_enable_write_protect();

	return 1;
}