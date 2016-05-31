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

extern unsigned char TrackedPages[0x7FFFF];

//Global variables
HANDLE TargetProcessHandle = INVALID_HANDLE_VALUE;
PLDR_DATA_TABLE_ENTRY * LdrpCurrentDllInitializer = NULL;
PRTL_CRITICAL_SECTION * LdrpLoaderLock = NULL;
ULONG_PTR * MmUserProbeAddress = NULL;

int do_log = 0;
int log_exceptions = 0;

ConfigStruct GlobalConfigStruct = {0};

proto_MiQueryAddressState MiQueryAddressState = NULL;
proto_MiCopyOnWrite MiCopyOnWrite = NULL;
proto_NtSuspendProcess ZwSuspendProcess = NULL;
proto_MmAccessFault MmAccessFault = NULL;
proto_MiMakePdeExistAndMakeValid MiMakePdeExistAndMakeValid = NULL;
proto_PsGetNextProcess PsGetNextProcess = NULL;
proto_PsSuspendProcess PsSuspendProcess = NULL;
proto_PsResumeProcess PsResumeProcess = NULL;

PKEVENT UnpackEventObj = NULL;
PKEVENT UserlandNotidyEvent = NULL;
PKEVENT IoctEvent = NULL;

void ** ServiceTable = NULL;

PVOID ExceptionBuffer = NULL;

void DriverUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS DriverCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DriverDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DriverIoControl(PDEVICE_OBJECT pDeviceObject, PIRP Irp);

int FunctionResolver()
{
	UNICODE_STRING FunctionName;
    
	memset(&FunctionName,0,sizeof(FunctionName));	
	RtlInitUnicodeString(&FunctionName,L"MmUserProbeAddress");
	MmUserProbeAddress = MmGetSystemRoutineAddress(&FunctionName);
	if( !MmUserProbeAddress)
	{
		pdebug(1,"[FunctionResolver] ERROR : Unable to find MmUserProbeAddress!\n");
		return 0;
	}
	pdebug(1,"[FunctionResolver] MmUserProbeAddress : %p\n",*MmUserProbeAddress);

	memset(&FunctionName,0,sizeof(FunctionName));	
	RtlInitUnicodeString(&FunctionName,L"PsSuspendProcess");
	PsSuspendProcess = MmGetSystemRoutineAddress(&FunctionName);
	if( !PsSuspendProcess)
	{
		pdebug(1,"[FunctionResolver] ERROR : Unable to find PsSuspendProcess!\n");
		return 0;
	}
	pdebug(1,"[FunctionResolver] PsSuspendProcess : %p\n",PsSuspendProcess);
    
	memset(&FunctionName,0,sizeof(FunctionName));	
	RtlInitUnicodeString(&FunctionName,L"PsResumeProcess");
	PsResumeProcess = MmGetSystemRoutineAddress(&FunctionName);
	if( !PsResumeProcess)
	{
		pdebug(1,"[FunctionResolver] ERROR : Unable to find PsResumeProcess!\n");
		return 0;
	}
	pdebug(1,"[FunctionResolver] PsResumeProcess : %p\n",PsResumeProcess);   
    
    
	return 1;
}

int GetKernelBaseAndSize(PVOID *pImageBaseAddress, ULONG * pImageSize) {
    PSYSTEM_MODULE SystemModule = NULL;
    NTSTATUS r;
    ULONG SystemInfoLength = 0;
    PVOID Buffer = NULL;
    ULONG Count = 0;
    ULONG i = 0;
	LPCSTR CurrentModuleName = NULL;
    
    //SystemModuleInformation = 11
    (VOID)ZwQuerySystemInformation(11, &SystemInfoLength, 0, &SystemInfoLength);
    Buffer = ExAllocatePool(NonPagedPool, SystemInfoLength);
	if(!Buffer)
    {
        pdebug(1,"[GetKernelBaseAndSize] ExAllocatePool failed : 0x%x");
		return 0;
	}
	
	//SystemModuleInformation = 11
    r = ZwQuerySystemInformation(11, Buffer, SystemInfoLength, NULL);
    if (r != STATUS_SUCCESS)
    {
        pdebug(1,"GetKernelBaseAndSize] ZwQuerySystemInformation failed : 0x%x", r);
		return 0;
    }
 
    Count = ((PSYSTEM_MODULE_INFORMATION)Buffer)->ModulesCount;
    
    for(i = 0; i < Count; ++i)
	{
        SystemModule = &((PSYSTEM_MODULE_INFORMATION)Buffer)->Modules[i];
		
		CurrentModuleName = (LPCSTR)SystemModule->Name;
		
		if ( strstr(CurrentModuleName,"nt") && strstr(CurrentModuleName,".exe") && ( ((ULONG_PTR)SystemModule->ImageBaseAddress > (ULONG_PTR)*MmUserProbeAddress ) ) )
		{
			*pImageBaseAddress = SystemModule->ImageBaseAddress;
			*pImageSize = SystemModule->ImageSize;
			
			ExFreePool(Buffer);
			return 1;
		}
    }
	
    return 0;
}

int ResolvePdeFunctions7_64bits(PVOID kernelbase, SIZE_T kernelsize)
{
	unsigned char MmAccessFault_signature[] = {0x48,0x89,0x5C,0x24,0x20,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0x20,0x01,0x00,0x00,0x48,0x8D,0xAC,0x24,0x80,0x00,0x00,0x00,0x48,0x83,0xE5,0xC0,0x48,0x8B,0xC2,0x4D,0x8B,0xF1,0x45,0x0F,0xB6,0xD0,0x48,0xC1,0xF8,0x30,0x4C,0x8B,0xEA,0x4C,0x8B,0xD9,0x48};
	unsigned char ZwSuspendProcess_signature[] = {0x48,0x8B,0xC4,0xFA,0x48,0x83,0xEC,0x10,0x50,0x9C,0x6A,0x10,0x48,0x8D,0x00,0x00,0x00,0x00,0x00,0x50,0xB8,0x7A,0x01,0x00,0x00,0xE9};
	unsigned char MiQueryAddressState_signature[] = {0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,0x24,0x10,0x48,0x89,0x74,0x24,0x20,0x4C,0x89,0x44,0x24,0x18,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x00,0x4C,0x8B,0xF9,0x48,0x8B,0xC1,0x48,0xB9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48};
	unsigned char MiCopyOnWrite_signture[] = {0x48,0x89,0x5C,0x24,0x18,0x48,0x89,0x54,0x24,0x10,0x48,0x89,0x4C,0x24,0x08,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0x00,0x00,0x00,0x00,0x48,0x8D,0x6C,0x24,0x00,0x48,0x83,0xE5,0xC0,0x48,0x8B,0x32,0x4C,0x8B,0xD1};
	unsigned char PsGetNextProcess_signature[] = {0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x00,0x65,0x48,0x8B,0x34,0x25,0x88,0x01,0x00,0x00,0x45,0x33,0xED};
    ULONG_PTR p;
    
	MmAccessFault = (proto_MmAccessFault)FindSignatureWithHoles(kernelbase, kernelsize - sizeof(MmAccessFault_signature) - 1 , MmAccessFault_signature, sizeof(MmAccessFault_signature));
	if( !MmAccessFault)
		return 0;
    
	ZwSuspendProcess = (proto_NtSuspendProcess)FindSignatureWithHoles(kernelbase, kernelsize - sizeof(ZwSuspendProcess_signature) - 1 , ZwSuspendProcess_signature, sizeof(ZwSuspendProcess_signature));
	if( !ZwSuspendProcess)
		return 0; 

	MiQueryAddressState = (proto_MiQueryAddressState)FindSignatureWithHoles(kernelbase, kernelsize - sizeof(MiQueryAddressState_signature) - 1 , MiQueryAddressState_signature, sizeof(MiQueryAddressState_signature));
	if( !MiQueryAddressState)
		return 0;
    
	MiCopyOnWrite = (proto_MiCopyOnWrite)FindSignatureWithHoles(kernelbase, kernelsize - sizeof(MiCopyOnWrite_signture) - 1 , MiCopyOnWrite_signture, sizeof(MiCopyOnWrite_signture));
	if( !MiCopyOnWrite)
		return 0;

    //TODO: understand why there is a page that faults in the middle of ntoskrnl image
	PsGetNextProcess = (proto_PsGetNextProcess)FindSignatureWithHoles((PVOID)MmUserProbeAddress, kernelsize - sizeof(PsGetNextProcess_signature) - 1 , PsGetNextProcess_signature, sizeof(PsGetNextProcess_signature));
	if( !PsGetNextProcess)
		return 0;    
    
    pdebug(1,"[ResolvePdeFunctions7] MmAccessFault 0x%p\n",MmAccessFault);
    pdebug(1,"[ResolvePdeFunctions7] ZwSuspendProcess 0x%p\n",ZwSuspendProcess);
	pdebug(1,"[ResolvePdeFunctions7] MiQueryAddressState 0x%p\n",MiQueryAddressState);
	pdebug(1,"[ResolvePdeFunctions7] MiCopyOnWrite 0x%p\n",MiCopyOnWrite);
	pdebug(1,"[ResolvePdeFunctions7] PsGetNextProcess 0x%p\n",PsGetNextProcess);
    
    return 1;
}


int ResolvePdeFunctions7_32bits(PVOID kernelbase, SIZE_T kernelsize)
{
	unsigned char MmAccessFault_signature32bits_7[] = {0x8B,0xFF,0x55,0x8B,0xEC,0x83,0xE4,0xF8,0x83,0xEC,0x00,0x53,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xC1,0xEE,0x09,0xC1,0x00,0x12,0x00,0xF8,0x3F,0x00,0x00,0x81,0xE6};
	unsigned char ZwSuspendProcess_signature[] = {0xB8,0x6E,0x01,0x00,0x00,0x8D,0x54,0x24,0x04,0x9C,0x6A,0x08,0xE8};     
	unsigned char MiQueryAddressState_signature[] = {0x8B,0xFF,0x55,0x8B,0xEC,0x83,0xEC,0x18,0x8B,0x55,0x18,0x83,0x65,0xFC,0x00,0x53,0x8B,0x5D,0x08,0x56,0x57,0x8B,0xF3,0xC1,0xEE,0x12,0x8B,0xFB};
	unsigned char MiCopyOnWrite_signture[] = {0x8B,0xFF,0x55,0x8B,0xEC,0x83,0xE4,0xF8,0x83,0xEC,0x5C,0x8B,0x45,0x0C,0x8B,0x08,0x8B,0x55,0x08};
    unsigned char PsGetNextProcess_signature[] = {0x8B,0xFF,0x55,0x8B,0xEC,0x51,0x51,0x83,0x65,0xFC,0x00,0x83,0x65,0xF8,0x00,0x53,0x56,0x64,0x8B,0x35,0x24,0x01,0x00,0x00,0x66,0xFF,0x8E,0x86,0x00,0x00,0x00,0x57,0x6A,0x11};
	
	MmAccessFault = (proto_MmAccessFault)FindSignatureWithHoles(kernelbase, kernelsize - sizeof(MmAccessFault_signature32bits_7) - 1 , MmAccessFault_signature32bits_7, sizeof(MmAccessFault_signature32bits_7));
	if( !MmAccessFault)
	{
		pdebug(1,"[ResolvePdeFunctions7] MmAccessFault not found !");
		return 0;
	}

	ZwSuspendProcess = (proto_NtSuspendProcess)FindSignature(kernelbase, kernelsize - sizeof(ZwSuspendProcess_signature) - 1 , ZwSuspendProcess_signature, sizeof(ZwSuspendProcess_signature));
	if( !ZwSuspendProcess)
		return 0; 
    
	MiQueryAddressState = (proto_MiQueryAddressState)FindSignature(kernelbase, kernelsize - sizeof(MiQueryAddressState_signature) - 1 , MiQueryAddressState_signature, sizeof(MiQueryAddressState_signature));
	if( !MiQueryAddressState)
		return 0;

	MiCopyOnWrite = (proto_MiCopyOnWrite)FindSignature(kernelbase, kernelsize - sizeof(MiCopyOnWrite_signture) - 1 , MiCopyOnWrite_signture, sizeof(MiCopyOnWrite_signture));
	if( !MiCopyOnWrite)
		return 0;
    
	PsGetNextProcess = (proto_PsGetNextProcess)FindSignature(kernelbase, kernelsize - sizeof(PsGetNextProcess_signature) - 1 , PsGetNextProcess_signature, sizeof(PsGetNextProcess_signature));
	if( !PsGetNextProcess)
		return 0;    
    
	pdebug(1,"[ResolvePdeFunctions7] MiQueryAddressState 0x%x\n",MiQueryAddressState);
	pdebug(1,"[ResolvePdeFunctions7] MiCopyOnWrite 0x%x\n",MiCopyOnWrite);
	pdebug(1,"[ResolvePdeFunctions7] MmAccessFault 0x%x\n",MmAccessFault);
	pdebug(1,"[ResolvePdeFunctions7] PsGetNextProcess 0x%x\n",PsGetNextProcess);
	
	return 1;
}


PVOID FindKeServiceDescriptorTable(PVOID kernelbase, SIZE_T kernelsize)
{
   unsigned char KeServiceDescriptorTable_signature[] = {0x4C,0x8D,0x15,0x00,0x00,0x00,0x00,0x4C,0x8D,0x1D,0x00,0x00,0x00,0x00,0xF7,0x83,0x00,0x01,0x00,0x00,0x80,0x00,0x00,0x00,0x4D,0x0F,0x45,0xD3,0x42,0x3B,0x44,0x17,0x10,0x0F,0x83};
    
    ULONG_PTR r;
	UNICODE_STRING FunctionName;
    PVOID KeFindConfigurationNextEntry;
    LONG delta;
    
    r = (ULONG_PTR)FindSignatureWithHoles((PVOID)kernelbase, kernelsize - sizeof(KeServiceDescriptorTable_signature) - 1 , KeServiceDescriptorTable_signature, sizeof(KeServiceDescriptorTable_signature));
    pdebug(1,"r = 0x%p",r);
    r += 3;
    
    delta = *((LONG *)r);
    
    r = r + delta + 4;
    
    pdebug(1,"delta = 0x%x",delta);
    pdebug(1,"r = 0x%p",r);   
    return (PVOID)r;
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
	unsigned int i;
	UNICODE_STRING DeviceName,Win32Device;
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status = 0;
	RTL_OSVERSIONINFOW OsInfo;
	int OsSupported = FALSE;
	PVOID KernelImageBase;
	ULONG KernelImageSize;
	
	RtlInitUnicodeString(&DeviceName,DEVICE_NAME);
	RtlInitUnicodeString(&Win32Device,DOS_DEVICE_NAME);
	
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DriverDefaultHandler;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->DriverStartIo = NULL;

	status = IoCreateDevice(DriverObject,
							0,
							&DeviceName,
							FILE_DEVICE_UNKNOWN,
							0,
							FALSE,
							&DeviceObject);
	if (!NT_SUCCESS(status))
		return status;
	if (!DeviceObject)
		return STATUS_UNEXPECTED_IO_ERROR;

	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->AlignmentRequirement = FILE_WORD_ALIGNMENT;
	status = IoCreateSymbolicLink(&Win32Device, &DeviceName);

	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	ServiceTable = KeServiceDescriptorTable.ServiceTable;

	pdebug(1,"[DriverEntry] ServiceTable : 0x%p\n",ServiceTable);	
	
	RtlGetVersion(&OsInfo);
	
	pdebug(1,"[DriverEntry] OS Major version : 0x%x\n",OsInfo.dwMajorVersion);
	pdebug(1,"[DriverEntry] OS Minor version : 0x%x\n",OsInfo.dwMinorVersion);
	
	if ( (OsInfo.dwMajorVersion == 6) && (OsInfo.dwMinorVersion == 1) )
	{
		
	}
	else
	{
		pdebug(1,"[DriverEntry] ERROR : Unsupported operating system !\n");
		return STATUS_UNSUCCESSFUL;
	}
	
	if (! FunctionResolver() )
	{
		pdebug(1,"[DriverEntry] ERROR : One of the required functions was not resolved !\n");
		return STATUS_UNSUCCESSFUL;		
	}
	
	if( ! GetKernelBaseAndSize(&KernelImageBase, &KernelImageSize) )
	{
		pdebug(1,"[DriverEntry] Error : unable find kernel image base and size \n");	
		return STATUS_UNSUCCESSFUL;	
	}
	else
	{
		pdebug(1,"[DriverEntry] Kernel image base : 0x%p \n",KernelImageBase);
		pdebug(1,"[DriverEntry] Kernel image size 0x%x\n",KernelImageSize);	
	}

	if( ! ResolvePdeFunctions7_32bits(KernelImageBase, KernelImageSize) )
	{
		pdebug(1,"[DriverEntry] Error : unable to resolve PDE function \n");	
		return STATUS_UNSUCCESSFUL;	
	}
    
    if ( !InitUserlandCommunication() )
	{
		pdebug(1,"[DriverEntry] Error initializing userland communication stuff\n");	
		return STATUS_UNSUCCESSFUL;	
	}       
    
	//Hook system calls
    HookSyscalls(KernelImageBase, KernelImageSize);  
	
	//Hook kernel exception dispatcher
	HookKiTrap0E(KernelImageBase,KernelImageSize);
	HookExceptionDispatcher(KernelImageBase,KernelImageSize);
	
    //Set notify routines
    PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine,FALSE);
    PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    
	return STATUS_SUCCESS;
}

int ResolveNtdllPointers(PEPROCESS ProcessObj, HANDLE ProcessHandle)
{
	PUCHAR p;
	unsigned char LdrpCurrentDllInitializer_signature[] = {0xC6,0x45,0xE7,0x00,0x89,0x5D,0xFC,0xC7,0x45,0x98,0x24,0x00,0x00,0x00,0x89,0x5D,0x9C,0x6A,0x07,0x59,0x33,0xC0};
	unsigned char LdrpLoaderLock_signature[] = {0x8B,0xFF,0x55,0x8B,0xEC,0x83,0xEC,0x44,0x64,0x8B,0x0D,0x18,0x00,0x00,0x00,0x53,0x56,0x8B,0x75,0x08,0x33,0xC0,0x81,0xFE};
	
	p = FindSignatureInProcessModule(ProcessObj,ProcessHandle,0,(ULONG_PTR)*MmUserProbeAddress,LdrpCurrentDllInitializer_signature,sizeof(LdrpCurrentDllInitializer_signature));
	if( p )
	{					
		p = p - sizeof(void *);
		LdrpCurrentDllInitializer = *(void **)p;
		pdebug(1,"[ResolveNtdllPointers] ntdll!LdrpCurrentDllInitializer : %p\n",LdrpCurrentDllInitializer);
	}
	else
		return 0;
	
	p = FindSignatureInProcessModule(ProcessObj,ProcessHandle,0,(ULONG_PTR)*MmUserProbeAddress,LdrpLoaderLock_signature,sizeof(LdrpLoaderLock_signature));
	if( p )
	{
		p = p + sizeof(LdrpLoaderLock_signature);
		LdrpLoaderLock = *(void **)p;	
		pdebug(1,"[ResolveNtdllPointers] ntdll!LdrpLoaderLock : %p\n",LdrpLoaderLock);
	}
	else
		return 0;
	
	return 1;
}

NTSTATUS DriverIoControl(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION pIoStackLocation = NULL;
	PVOID InBuffer = NULL;
	ULONG InBufferSize = 0, OutBufferSize = 0;
	PVOID OutBuffer = NULL;
	HANDLE hUserlandNotidyEvent = INVALID_HANDLE_VALUE;  
	HANDLE hIoctEvent = INVALID_HANDLE_VALUE;  
	PidStruct MyPidStruct = {0};
	NTSTATUS r, result = STATUS_UNSUCCESSFUL;
	PidStruct * pPidStruct = NULL;
	ULONG ReturnedBytes = 0;
	KAPC_STATE ApcState;
	PEPROCESS ProcessObj = NULL;
	
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);	
	
	InBuffer = Irp->AssociatedIrp.SystemBuffer;
	InBufferSize = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
	
	OutBuffer = Irp->AssociatedIrp.SystemBuffer;
	OutBufferSize = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

	switch(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_SET_PID :
		{
            EXCEPTION_INFO dummy;
            UNICODE_STRING EventName;
            
			memset(TrackedPages,0,sizeof(TrackedPages));
		
			pPidStruct = (PidStruct *)InBuffer;
			
			pdebug(1,"[DriverIoControl] UserlandNotidyEvent : %p",pPidStruct->UserlandNotidyEvent);
			pdebug(1,"[DriverIoControl] target process handle : %p",pPidStruct->TargetProcessHandle);
            
			GlobalConfigStruct.debug_log = pPidStruct->debug_log;
            GlobalConfigStruct.RWEPolicy = pPidStruct->RWEPolicy;
            GlobalConfigStruct.InitiallyNonExecutable = pPidStruct->InitiallyNonExecutable;
            
			TargetProcessHandle = pPidStruct->TargetProcessHandle;
            hUserlandNotidyEvent = pPidStruct->UserlandNotidyEvent;         
            
			r = ObReferenceObjectByHandle(hUserlandNotidyEvent,EVENT_ALL_ACCESS,*ExEventObjectType,UserMode,&UserlandNotidyEvent,NULL);
			if( r == STATUS_SUCCESS )
			{
				pdebug(1,"[DriverIoControl] UserlandNotidyEvent: %p\n",UserlandNotidyEvent);
			}
			else
			{
				pdebug(1,"[DriverIoControl] Error : unable to get event object");
				result = STATUS_UNSUCCESSFUL;
				break;
			}

            RtlInitUnicodeString(
                &EventName,
                L""
            );            
            
            IoctEvent = IoCreateSynchronizationEvent(&EventName, &hIoctEvent);
            if( IoctEvent )
			{
				pdebug(1,"[DriverIoControl] IoctEvent: %p\n",IoctEvent);
			}
			else
			{
				pdebug(1,"[DriverIoControl] Error : IoCreateNotificationEvent failed\n");
				result = STATUS_UNSUCCESSFUL;
				break;
			}
            
            KeClearEvent(IoctEvent);
            
			r = ObReferenceObjectByHandle(TargetProcessHandle,PROCESS_QUERY_INFORMATION,*PsProcessType,UserMode,&ProcessObj,NULL);
			if( r == STATUS_SUCCESS )
			{
				pdebug(1,"[DriverIoControl] ProcessObj: %p\n",ProcessObj);
			}
			else
			{
				pdebug(1,"[DriverIoControl] Error : unable to find process object : 0x%x\n",r);
				result = STATUS_UNSUCCESSFUL;
				break;
			}

			if( !ResolveNtdllPointers(ProcessObj,TargetProcessHandle) )
			{
				pdebug(1,"[DriverIoControl] Error : ResolveNtdllPointers failed\n");
				result = STATUS_UNSUCCESSFUL;
				break;
			}

			pdebug(1,"[DriverIoControl] Exception list initiated\n");
			
			InitAccessArray();
            InitProcessArray();
            
            if ( AddTrackedProcess(PsGetProcessId(ProcessObj)) == 0 )
            {
                pdebug(1,"[DriverIoControl] Error : AddTrackedProcess failed\n");
				result = STATUS_UNSUCCESSFUL;
				break;                
            }
            
			if ( ProcessObj )
			{
				ObDereferenceObject(ProcessObj);
				ProcessObj = NULL;
			}
            
			pdebug(1,"[DriverIoControl] Returning\n");

			result = STATUS_SUCCESS;
			break;
		}
        
        case IOCTL_ADD_TRACKED:
        {
            HANDLE Pid;
            
            Pid = *((HANDLE *)InBuffer);
            pdebug(1,"[DriverIoControl] IOCTL_ADD_TRACKED, added Pid : 0x%x\n",(ULONG_PTR)Pid);
            
            if ( AddTrackedProcess(Pid) == 0 )
            {
                pdebug(1,"[DriverIoControl] Error : AddTrackedProcess failed\n");
				result = STATUS_UNSUCCESSFUL;
				break;  
            }
            
			ReturnedBytes = 0;
			result = STATUS_SUCCESS;  
            
            break;
        }        
        
        case IOCTL_SUSPEND_TRACKED:
        {
            
            pdebug(1,"[DriverIoControl] IOCTL_SUSPEND_TRACKED\n");
            SuspendTrackedProcesses();
            
			ReturnedBytes = 0;
			result = STATUS_SUCCESS;  
            
            break;
        }
        
        case IOCTL_UNTRACK_AND_RESUME_PROCESSES:
        {
			pdebug(1,"[DriverIoControl] IOCTL_UNTRACK_AND_RESUME_PROCESSES\n");           
            
            ResumeAndUntrackProcesses();
            
            //Set event to resume locked process
            KeSetEvent(IoctEvent,1,FALSE);
            
			ReturnedBytes = 0;
			result = STATUS_SUCCESS;
            
            break;     
        }        

		case IOCTL_CLEANUP:
		{
			pdebug(1,"[DriverIoControl] IOCTL_CLEANUP\n");
            
            /*
                Untrack and terminate all tracked process
            */
            TerminateProcesses();
            
			if (UserlandNotidyEvent)
			{
				ObDereferenceObject(UserlandNotidyEvent);
				UserlandNotidyEvent = NULL;
			}
            
			if (IoctEvent)
			{
				ZwClose(IoctEvent);
				IoctEvent = NULL;
			}

			ReturnedBytes = 0;
			result = STATUS_SUCCESS;
            
            break;            
		}
        
        case IOCTL_RETRIEVE_EXCEPTION:
        {
            event_header * pHandler = NULL;
            DWORD RequiredSize;

            pHandler = (event_header* )ExceptionBuffer;
            
            RequiredSize = pHandler->event_size + sizeof(event_header);
            
            if ( OutBufferSize >= RequiredSize )
            {
                memcpy(OutBuffer,ExceptionBuffer,RequiredSize);
                ReturnedBytes = RequiredSize;
            }
            else
                ReturnedBytes = 0;
            
            if (IoctEvent)
            {
                KeSetEvent(IoctEvent,1,FALSE);
            }
            
			result = STATUS_SUCCESS;
            
            break;
        }
        
	}
	
entry_end:
	
	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	Irp->IoStatus.Status = result;
	Irp->IoStatus.Information = ReturnedBytes;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	
	return result;
}

void DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING Win32Device;
	LARGE_INTEGER Interval;

	RtlInitUnicodeString(&Win32Device,DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&Win32Device);
	IoDeleteDevice(DriverObject->DeviceObject);
	
	UnHookKiTrap0E();
	UnHookExceptionDispatcher();
	UnhookSyscalls();
	
	Interval.HighPart = 0;
	//A few microsecs
	Interval.LowPart = 0x3B9ACA00;
	
	//Sleep, attempt to avoid blue screens on driver unload
	KeDelayExecutionThread(KernelMode,FALSE,&Interval);
   		
    CloseUuserlandCommunication();
    
    //Set notify routines
    PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine,TRUE);
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
  
	
	pdebug(1,"[DriverUnload] Driver unloaded\n");
}

NTSTATUS DriverCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}