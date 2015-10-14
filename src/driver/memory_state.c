#include "memory_state.h"
#include "utils.h"

#define PAGE_GUARD 0x100
extern proto_MiQueryAddressState MiQueryAddressState;
//extern proto_MmGetVirtualForPhysical MmGetVirtualForPhysical;
extern proto_MiMakePdeExistAndMakeValid MiMakePdeExistAndMakeValid;
extern proto_NtQueryVirtualMemory NtQueryVirtualMemory;
extern proto_NtProtectVirtualMemory NtProtectVirtualMemory;
extern proto_NtProtectVirtualMemory ZwProtectVirtualMemory;
extern HANDLE TargetProcessHandle;
unsigned char TrackedPages[0x7FFFF];
extern proto_MmAccessFault MmAccessFault;
extern proto_MiCopyOnWrite MiCopyOnWrite;
extern ULONG_PTR * MmUserProbeAddress;
//MiProtectVirtualMemory_proto MiProtectVirtualMemory = NULL;
extern int do_log;

ULONG MmProtectValues[32] = {
	PAGE_NOACCESS,
	PAGE_READONLY,
	PAGE_EXECUTE,
	PAGE_EXECUTE_READ,
	PAGE_READWRITE,
	PAGE_WRITECOPY,
	PAGE_EXECUTE_READWRITE,
	PAGE_EXECUTE_WRITECOPY,
	PAGE_NOACCESS,
	PAGE_NOCACHE | PAGE_READONLY,
	PAGE_NOCACHE | PAGE_EXECUTE,
	PAGE_NOCACHE | PAGE_EXECUTE_READ,
	PAGE_NOCACHE | PAGE_READWRITE,
	PAGE_NOCACHE | PAGE_WRITECOPY,
	PAGE_NOCACHE | PAGE_EXECUTE_READWRITE,
	PAGE_NOCACHE | PAGE_EXECUTE_WRITECOPY,
	PAGE_NOACCESS,
	PAGE_GUARD | PAGE_READONLY,
	PAGE_GUARD | PAGE_EXECUTE,
	PAGE_GUARD | PAGE_EXECUTE_READ,
	PAGE_GUARD | PAGE_READWRITE,
	PAGE_GUARD | PAGE_WRITECOPY,
	PAGE_GUARD | PAGE_EXECUTE_READWRITE,
	PAGE_GUARD | PAGE_EXECUTE_WRITECOPY,
	PAGE_NOACCESS,
	PAGE_WRITECOMBINE | PAGE_READONLY,
	PAGE_WRITECOMBINE | PAGE_EXECUTE,
	PAGE_WRITECOMBINE | PAGE_EXECUTE_READ,
	PAGE_WRITECOMBINE | PAGE_READWRITE,
	PAGE_WRITECOMBINE | PAGE_WRITECOPY,
	PAGE_WRITECOMBINE | PAGE_EXECUTE_READWRITE,
	PAGE_WRITECOMBINE | PAGE_EXECUTE_WRITECOPY
};

void ClearTrackedPages()
{
	memset(TrackedPages,0,sizeof(TrackedPages));
}

int IsTrackedPage(ULONG_PTR PageAddress)
{
	return TrackedPages[(ULONG_PTR)PageAddress >> 0xC];
}

void SetTrackedPage(ULONG_PTR PageAddress)
{
	TrackedPages[(ULONG_PTR)PageAddress >> 0xC] = 1;
}

void SetUntrackedPage(ULONG_PTR PageAddress)
{
	TrackedPages[(ULONG_PTR)PageAddress >> 0xC] = 0;
}

int IsMemoryTracked(ULONG Page)
{
	PTE * ppte_virtual = NULL;
	
	return 1;
	
	ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(Page);

	if ( ppte_virtual->pte.present == 0 )
	{
		//pdebug(do_log,"[IsMemoryTracked] pte for page 0x%x not present\n",Page);
		return 0;
	}
}

//
// TODO : Handle large pages
//
PTE * EnsurePteOK(ULONG_PTR Page)
{
	PDE * ppde_virtual = NULL;
	PTE * ppte_virtual = NULL;
	PMMPTE_SOFTWARE pmme = NULL;

	// We hope pte virtual address is mapped...
	ppde_virtual = (PDE *)PDE_VIRTUAL_FROM_ADDRESS(Page);
	ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(Page);

	if( !ppte_virtual )
		return NULL;

	if ( ppde_virtual->large_page.ps )
	{
		pdebug(do_log,"[EnsurePteOK] LARGE PAGE !!!!!!!!!\n");
		return NULL;
	}

	//
	// If pte is not present (full zero) we cause an access fault to make the OS
	// set it up.
	//
	if ( ppte_virtual->raw.LowPart == 0 )
	{
		MmAccessFault(FALSE, (PVOID)Page, UserMode, NULL);	
	}
	
	pdebug(do_log,"[EnsurePteOK] PTE HighPart : 0x%x, LowPart : 0x%x\n",ppte_virtual->raw.HighPart, ppte_virtual->raw.LowPart);	
	
	if ( ppte_virtual->raw.LowPart == 0 )
	{
		pdebug(do_log,"[EnsurePteOK] unknown PTE found, exiting !\n");
		return NULL;
	}
	
	if ( ppte_virtual->pte.present == 0 )
	{
		pmme = (PMMPTE_SOFTWARE)ppte_virtual;
		
		if ( (pmme->Prototype) && !(pmme->Transition) )
		{
			pdebug(do_log,"[EnsurePteOK] Prototype PTE\n");
		}
		else if ( pmme->Prototype && pmme->Transition )
		{
			pdebug(do_log,"[EnsurePteOK] Transition PTE \n");
		}
		else if ( (pmme->PageFileLow == 0) && ( pmme->PageFileHigh == 0 ) )
		{
			pdebug(do_log,"[EnsurePteOK] Demand zero PTE \n");
		}
		
		pdebug(do_log,"[EnsurePteOK] Highpart 0x%x, Lowpart : 0x%x\n", ppte_virtual->raw.HighPart , ppte_virtual->raw.LowPart);
		
		return NULL;
	}
	
	return ppte_virtual;
}

int GetMemoryProtectionPae(ULONG Page, unsigned int * pWritable, unsigned int * pExecutable)
{
	PTE * ppte_virtual = NULL;
	
	pdebug(do_log,"[GetMemoryProtectionPae] called on virtual address : 0x%x\n",Page);
	
	ppte_virtual = EnsurePteOK(Page);
	if( !ppte_virtual )
		return 0;

	if ( ppte_virtual->pte.rw == 1 )
		*pWritable = 1;
	else
		*pWritable = 0;
	
	if ( ppte_virtual->pte.xd == 1 )
		*pExecutable = 0;
	else
		*pExecutable = 1;

	return 1;
}


int SetMemoryProtectionPae2(ULONG Page, unsigned int Writable, unsigned int Executable)
{

	PTE * ppte_virtual = NULL;

	
	//This should not happen, but just in case
	if ( (ULONG_PTR)Page > (ULONG_PTR)*MmUserProbeAddress)
		return 0;
	
	ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(Page);

	pdebug(do_log,"[SetMemoryProtectionPae2] called on virtual address : 0x%x\n",Page);

	//
	// Change memory protection bits according to input params
	//
	if ( Writable )
	{
		ppte_virtual->pte.rw = 1;
		ppte_virtual->pte.d = 1;
	}
	else
		ppte_virtual->pte.rw = 0;

	if ( Executable )
		ppte_virtual->pte.xd = 0;
	else
		ppte_virtual->pte.xd = 1;

	SetTrackedPage(Page);		

	//
	// Trigger TLB flush
	// 
	__asm{
		mov eax, cr3
		mov cr3, eax
		invlpg Page
	};
	

	pdebug(do_log,"[SetMemoryProtectionPae2] result : 0x%x 0x%x\n",ppte_virtual->raw.HighPart, ppte_virtual->raw.LowPart);

	return 1;
}


int ProtectExecutablePTEs(ULONG_PTR Base, SIZE_T Size)
{
	PMMVAD VadRoot = NULL;
	PMMVAD CurrentVad = NULL;
	SIZE_T VadRegionSize;
	ULONG VadPageProtection,Protect,State;
	PVOID NextVa;
	SIZE_T i;
	ULONG_PTR CurrentPage;
	PTE * ppte_virtual;
	NTSTATUS r;
	
	VadRoot = (PMMVAD)GetVadRoot(PsGetCurrentProcess());	
	if (!VadRoot)
	{
		pdebug(do_log,"[ProtectMemoryRange] error : GetVadRoot failed !\n");
		return 0;
	}
	
	CurrentVad = LocateVadForPage(VadRoot, (ULONG)Base >> 0xC);
	if(!CurrentVad)
	{
		pdebug(do_log,"[ProtectMemoryRange] error : LocateVadForPage failed !\n");
		return 0;
	}
	
	VadRegionSize = CurrentVad->EndingVpn - CurrentVad->StartingVpn + 1;
	VadRegionSize = VadRegionSize * PAGE_SIZE;
	VadPageProtection = MmProtectValues[CurrentVad->u.Protection];
	
	pdebug(do_log,"%x %x\n",(Base + Size),(CurrentVad->EndingVpn + 1)*PAGE_SIZE);
	
	if ( (Base + Size) > (CurrentVad->EndingVpn + 1)*PAGE_SIZE )
	{
		pdebug(do_log,"[ProtectMemoryRange] error : memory region not contained in Vad !\n");
		return 0;
	}

	//Modifying guard pages protection is a bad idea
	if ( VadPageProtection & PAGE_GUARD )
	{
		return 0;
	}
	
	for (i=0;i<Size;i+=PAGE_SIZE)
	{
		Protect = 0;
		CurrentPage = Base + i;
		pdebug(do_log,"[ProtectMemoryRange] current page : 0x%x\n",CurrentPage);
		
		ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(CurrentPage);
	
		//Trigger a read access fault to make pte present
		MmAccessFault(READ_ACCESS,(PVOID)CurrentPage,UserMode,NULL);

		//Do not work on non-present PTE
		if ( !ppte_virtual->pte.present )
		{
			pdebug(do_log,"[ProtectMemoryRange] not present pte : 0x%x 0x%x\n",ppte_virtual->raw.HighPart,ppte_virtual->raw.LowPart);
			
			if ( ppte_virtual->pte.prototype == 1 )
			{
				/*
				__asm{
					int 3
				};
				*/
			}
			
			continue;
		}
		
		//Check the VAD for the whole allocation. Force all pages to become copy on write
		if ( (VadPageProtection & PAGE_WRITECOPY) || (VadPageProtection & PAGE_EXECUTE_WRITECOPY) )
		{
			if ( (ppte_virtual->pte.present) && (!ppte_virtual->pte.reserved) )
			{
				pdebug(do_log,"[ProtectExecutablePTEs] Before MiCopyOnWrite : 0x%x 0x%x!\n",ppte_virtual->raw.HighPart,ppte_virtual->raw.LowPart);
				
				r = MiCopyOnWrite((PVOID)CurrentPage ,ppte_virtual);
				if (!r)
				{
					pdebug(do_log,"[ProtectExecutablePTEs] MiCopyOnWrite failed !\n",r);
				}
				else
				{
					ppte_virtual->pte.reserved = 1;
					pdebug(do_log,"[ProtectExecutablePTEs] After MiCopyOnWrite : 0x%x 0x%x !\n",ppte_virtual->raw.HighPart,ppte_virtual->raw.LowPart);
				}
			}
		}
		
		State = MiQueryAddressState((PVOID)CurrentPage,CurrentVad,PsGetCurrentProcess(),&Protect, &NextVa);
		
		pdebug(do_log,"[ProtectMemoryRange] State = 0x%x, VadPageProtection = 0x%x, Protect = 0x%x\n",State, VadPageProtection ,Protect);
		
		//Do no work on un-commited pages
		if ( !(State & MEM_COMMIT ) )
			continue;
		
		//If page is 
		if ( (Protect & PAGE_EXECUTE_READWRITE) || (Protect & PAGE_READWRITE) )
		{		
			pdebug(do_log,"[ProtectMemoryRange] Writable page\n");
			
			SetMemoryProtectionPae2(CurrentPage,0,1);
		}
		else if ( (Protect & PAGE_WRITECOPY) || (Protect & PAGE_EXECUTE_WRITECOPY) )
		{
			pdebug(do_log,"[ProtectMemoryRange] Copy writable page\n");
			
			pdebug(do_log,"[ProtectMemoryRange] 0x%x 0x%x\n",ppte_virtual->raw.HighPart, ppte_virtual->raw.LowPart);
			
			//Check to see if the page is not yet copy on write. If it is not yet copy on write trigger a fault on write.
			if ( (ppte_virtual->pte.copyonwrite) && (!ppte_virtual->pte.reserved) )
			{
				MmAccessFault(WRITE_ACCESS,(PVOID)CurrentPage,UserMode,0);
			}
			
			pdebug(do_log,"[ProtectMemoryRange] 0x%x 0x%x\n",ppte_virtual->raw.HighPart, ppte_virtual->raw.LowPart);

			SetMemoryProtectionPae2(CurrentPage,0,1);
		}
		else if ( (Protect & PAGE_READONLY) || (Protect & PAGE_EXECUTE) || (Protect & PAGE_EXECUTE_READ) )
		{
			pdebug(do_log,"[ProtectMemoryRange] READONLY or PAGE_EXECUTE\n");
			
			if ( ppte_virtual->pte.reserved )
			{
				pdebug(do_log,"[ProtectMemoryRange] copywrited page\n");
			}
			
			SetMemoryProtectionPae2(CurrentPage,0,1);
		}
	}
	
	return 1;
}

void ParseProcessVad(PMMVAD pVad)
{
	ULONG VadPageProtection = 0;
	ULONG RegionSize = 0;	
	
	if ( !pVad )
		return;
		
	ParseProcessVad(pVad->LeftChild);
	ParseProcessVad(pVad->RightChild);
	
	VadPageProtection = MmProtectValues[pVad->u.Protection];

	pdebug(do_log,"VadRoot->StartingVpn : 0x%x\n", pVad->StartingVpn);
	pdebug(do_log,"VadRoot->EndingVpn : 0x%x\n", pVad->EndingVpn);
	pdebug(do_log,"VadPageProtection : 0x%x\n",VadPageProtection);
	pdebug(do_log,"Commit flag : %d\n",pVad->u.MemCommit);
	
	RegionSize = pVad->EndingVpn - pVad->StartingVpn + 1;
	RegionSize = RegionSize * PAGE_SIZE;	

	ProtectExecutablePTEs( (ULONG_PTR)(pVad->StartingVpn*PAGE_SIZE), RegionSize);
}

/*
	This function locates the MMVAD structure that contains a given
	Vpn.
	
	return:
		SUCCESS : PMMVAD of the Vad containing the page
		FAIL : NULL pointer
*/
PMMVAD LocateVadForPage(PMMVAD pVad, ULONG PageVpn)
{
	if (!pVad)
		return NULL;	
		
	if (  ( PageVpn <= pVad->EndingVpn ) && ( PageVpn >= pVad->StartingVpn) )
	{
		return pVad;
	}
	else if ( PageVpn < pVad->StartingVpn )
	{
		return LocateVadForPage(pVad->LeftChild, PageVpn);
	}
	else if ( PageVpn > pVad->EndingVpn )
	{
		return LocateVadForPage(pVad->RightChild, PageVpn);
	}
	else
		return NULL;
}

ULONG GetVadMemoryProtect(ULONG_PTR BaseAddress)
{
	PMMVAD VadRoot = NULL;
	PMMVAD CurrentVad = NULL;
	ULONG Protect = 0;
	PVOID NextVa = NULL;
	PTE * ppte_virtual = NULL;
	PMMPTE_SOFTWARE pmmte_virtual = NULL;
	
	VadRoot = (PMMVAD)GetVadRoot(PsGetCurrentProcess());	
	if (!VadRoot)
		return Protect;

	CurrentVad = LocateVadForPage(VadRoot, (ULONG)BaseAddress >> 0xC);
	if (CurrentVad)
	{
		ppte_virtual = (PTE *)PTE_VIRTUAL_FROM_ADDRESS(BaseAddress);
		
		//Trigger access fault to make pte present
		MmAccessFault(0,(PVOID)BaseAddress,UserMode,NULL);

		if ( ppte_virtual->pte.present )
			MiQueryAddressState((PVOID)BaseAddress, CurrentVad, PsGetCurrentProcess(), &Protect, &NextVa );
		else
		{
			pdebug(do_log,"[GetVadMemoryProtect] Pte is invalid !\n");
			
			//Not present PTE so cast it to MMPTE_SOFTWARE
			pmmte_virtual = (PMMPTE_SOFTWARE)ppte_virtual;
			
			//Do no handle Prototype PTEs
			if (pmmte_virtual->Prototype)
			{
				pdebug(do_log,"[GetVadMemoryProtect] Do no handle Prototype PTEs\n");
				return Protect;
			}
			
			Protect = MmProtectValues[pmmte_virtual->Protection];
		}
	}
	else
		pdebug(do_log,"[GetVadMemoryProtect] LocateVadForPage failed !\n");
	
	return Protect;
}

int IsProtectCompatible(unsigned int VirtualMemoryProtect, ULONG_PTR AccessViolationType)
{
	if ( (AccessViolationType == WRITE_ACCESS) && IsWritable(VirtualMemoryProtect) )
	{
		return 1;
	}
	
	if ( (AccessViolationType == EXECUTE_ACCESS) && IsExecutable(VirtualMemoryProtect) )
	{
		return 1;
	}	
	
	return 0;
}

int IsWritable(ULONG Protect)
{
	if ( Protect == PAGE_READWRITE )
		return 1;
		
	if ( Protect == PAGE_EXECUTE_READWRITE )
		return 1;

	return 0;
}

int IsExecutable(ULONG Protect)
{

	if ( Protect == PAGE_EXECUTE )
		return 1;

	if ( Protect == PAGE_EXECUTE_READ )
		return 1;
		
	if ( Protect == PAGE_EXECUTE_READWRITE )
		return 1;

	if ( Protect == PAGE_EXECUTE_WRITECOPY )
		return 1;
		
	return 0;
}

/*
	FaultStatus : 1 or 8, any other input is invalid
	PageRights : 

	return :
		1 : will lead to a call to MmAccessFault
		0 : the fault will be handled by our handler
*/
int ShouldItFault(ULONG_PTR FaultStatus,  ULONG PageRights)
{
	PMYEPROCESS ProcessObj;
	
	ProcessObj = PsGetCurrentProcess();

	/*
	TODO : there seem to be a problem with the Pcb.Flags field of KPROCESS struct
	maybe our KPROCESS structure is wrong ?
	pdebug(do_log,"[ShouldItFault] ExecuteDisable : 0x%d", ProcessObj->Pcb.Flags.ExecuteDisable);
	pdebug(do_log,"[ShouldItFault] ExecuteEnable : 0x%d", ProcessObj->Pcb.Flags.ExecuteEnable); 
	pdebug(do_log,"[ShouldItFault] Permanent : 0x%d", ProcessObj->Pcb.Flags.Permanent);
	pdebug(do_log,"[ShouldItFault] Unused1 : 0x%d", ProcessObj->Pcb.Unused1);
	*/
	
	//Dirty work around to fix the DEP problem
	//would be better to interpret the flags of the KPROCESS struct
	if ( FaultStatus == EXECUTE_ACCESS )
	{
		return 0;
	}
	
	if ( ( FaultStatus != WRITE_ACCESS ) && ( FaultStatus != EXECUTE_ACCESS ) )
	{
		pdebug(do_log,"[ShouldItFault] ERROR : unexpected fault status : 0x%x\n",FaultStatus);
		return 1;
	}
	
	//Any access on those kind of pages will trigger should trigger a fault
	if ( (PageRights == PAGE_NOACCESS) || (PageRights & PAGE_READONLY) || (PageRights & PAGE_GUARD) )
	{
		return 1;
	}

	if ( FaultStatus == WRITE_ACCESS )
	{
		if ( (PageRights & PAGE_READWRITE) || (PageRights & PAGE_EXECUTE_READWRITE) || (PageRights & PAGE_WRITECOPY) )
			return 0;
		else
			return 1;
	}	
	else if ( FaultStatus == EXECUTE_ACCESS )
	{
		if ( (PageRights & PAGE_EXECUTE_READ) || (PageRights & PAGE_EXECUTE_READWRITE) || (PageRights & PAGE_EXECUTE) || (PageRights & PAGE_EXECUTE_WRITECOPY) )
			return 0;
		else
			return 1;		
	}
	
	//We should never come here...
	pdebug(do_log,"[ShouldItFault] WTF ???\n"); 
	
	return 1;
}