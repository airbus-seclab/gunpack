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

#include "DriverDefs.h"
#include "win_kernl.h"
#include "syscall_hook.h"
#include "utils.h"
#include "exceptions_list.h"
#include "exceptions_hook.h"
#include "memory_state.h"


extern int EventSignaled;
extern unsigned char TrackedPages[0x7FFFF];
extern unsigned int first_exception_in_process;

//Global variables
unsigned int TargetPid = INVALID_PID;
HANDLE TargetProcessHandle = INVALID_HANDLE_VALUE;
PLDR_DATA_TABLE_ENTRY * LdrpCurrentDllInitializer = NULL;
PRTL_CRITICAL_SECTION * LdrpLoaderLock = NULL;
ULONG_PTR * MmUserProbeAddress = NULL;

int do_log = 0;
int log_exceptions = 0;

proto_MiQueryAddressState MiQueryAddressState = NULL;
proto_MiCopyOnWrite MiCopyOnWrite = NULL;
proto_NtProtectVirtualMemory ZwProtectVirtualMemory = NULL;
proto_NtSuspendThread ZwSuspendThread = NULL;
proto_MmAccessFault MmAccessFault = NULL;
proto_MiMakePdeExistAndMakeValid MiMakePdeExistAndMakeValid = NULL;

PKEVENT EventObj = NULL;
void ** ServiceTable;
__declspec(dllimport) SST KeServiceDescriptorTable;

void DriverUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS DriverCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DriverDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DriverIoControl(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
ULONG_PTR ProgramOep = (ULONG_PTR)-1;

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
	
	return 1;

}

int GetKernelBaseAndSize(PVOID *pImageBaseAddress, ULONG * pImageSize) {
    PSYSTEM_MODULE SystemModule = NULL;
    ULONG_PTR SystemInfoLength = 0;
    PVOID Buffer = NULL;
    ULONG Count = 0;
    ULONG i = 0;
	LPCSTR CurrentModuleName = NULL;

    //SystemModuleInformation = 11
    (VOID)ZwQuerySystemInformation(11, &SystemInfoLength, 0, &SystemInfoLength);
    Buffer = ExAllocatePool(NonPagedPool, SystemInfoLength);
	if(!Buffer)
		return 0;
		
	//SystemModuleInformation = 11
    (VOID)ZwQuerySystemInformation(11, Buffer, SystemInfoLength, NULL);
 
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

int ResolvePdeFunctions7(PVOID kernelbase, SIZE_T kernelsize)
{
	unsigned char MakePDeValid_signature32bits_7[] = {0x8B,0xFF,0x55,0x8B,0xEC,0x83,0xE4,0xF8,0x83,0xEC,0x0C,0x56,0x8B,0x75,0x08,0x8B,0xC6,0xC1,0xE8,0x09,0x25,0xF8,0xFF,0x7F};
	unsigned char MmAccessFault_signature32bits_7[] = {0x8B,0xFF,0x55,0x8B,0xEC,0x83,0xE4,0xF8,0x83,0xEC,0x00,0x53,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xC1,0xEE,0x09,0xC1,0x00,0x12,0x00,0xF8,0x3F,0x00,0x00,0x81,0xE6};
	unsigned char ZwProtectVirtualMemory_signature[] = {0xB8,0xD7,0x00,0x00,0x00,0x8D,0x54,0x24,0x04,0x9C,0x6A,0x08,0xE8};
	unsigned char ZwQueryVirtualMemory_signature[] = {0xB8,0x0B,0x01,0x00,0x00,0x8D,0x54,0x24,0x04,0x9C,0x6A,0x08,0xE8};
	unsigned char ZwSuspendThread_signature[] = {0xB8,0x6F,0x01,0x00,0x00,0x8D,0x54,0x24,0x04,0x9C,0x6A,0x08,0xE8};
	unsigned char MiQueryAddressState_signature[] = {0x8B,0xFF,0x55,0x8B,0xEC,0x83,0xEC,0x18,0x8B,0x55,0x18,0x83,0x65,0xFC,0x00,0x53,0x8B,0x5D,0x08,0x56,0x57,0x8B,0xF3,0xC1,0xEE,0x12,0x8B,0xFB};
	unsigned char MiCopyOnWrite_signture[] = {0x8B,0xFF,0x55,0x8B,0xEC,0x83,0xE4,0xF8,0x83,0xEC,0x5C,0x8B,0x45,0x0C,0x8B,0x08,0x8B,0x55,0x08};
	
	MmAccessFault = (proto_MmAccessFault)FindSignatureWithHoles(kernelbase, kernelsize - sizeof(MmAccessFault_signature32bits_7) - 1 , MmAccessFault_signature32bits_7, sizeof(MmAccessFault_signature32bits_7));
	if( !MmAccessFault)
	{
		pdebug(1,"[ResolvePdeFunctions7] MmAccessFault not found !");
		return 0;
	}

	ZwProtectVirtualMemory = (proto_NtProtectVirtualMemory)FindSignature(kernelbase, kernelsize - sizeof(ZwProtectVirtualMemory_signature) - 1 , ZwProtectVirtualMemory_signature, sizeof(ZwProtectVirtualMemory_signature));
	if( !ZwProtectVirtualMemory)
		return 0;
		
	
	ZwSuspendThread = (proto_NtSuspendThread)FindSignature(kernelbase, kernelsize - sizeof(ZwSuspendThread_signature) - 1 , ZwSuspendThread_signature, sizeof(ZwSuspendThread_signature));
	if( !ZwSuspendThread)
		return 0;

	MiQueryAddressState = (proto_MiQueryAddressState)FindSignature(kernelbase, kernelsize - sizeof(MiQueryAddressState_signature) - 1 , MiQueryAddressState_signature, sizeof(MiQueryAddressState_signature));
	if( !MiQueryAddressState)
		return 0;

	
	MiCopyOnWrite = (proto_MiCopyOnWrite)FindSignature(kernelbase, kernelsize - sizeof(MiCopyOnWrite_signture) - 1 , MiCopyOnWrite_signture, sizeof(MiCopyOnWrite_signture));
	if( !MiCopyOnWrite)
		return 0;
	
	pdebug(1,"[ResolvePdeFunctions7] ZwProtectVirtualMemory 0x%x\n",ZwProtectVirtualMemory);
	pdebug(1,"[ResolvePdeFunctions7] MiQueryAddressState 0x%x\n",MiQueryAddressState);
	pdebug(1,"[ResolvePdeFunctions7] MiCopyOnWrite 0x%x\n",MiCopyOnWrite);
	pdebug(1,"[ResolvePdeFunctions7] MmAccessFault 0x%x\n",MmAccessFault);
	
	return 1;
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
	pdebug(0,"[DriverEntry] sizeof(KPROCESS) : 0x%x\n",sizeof(KPROCESS));
	
	if ( (OsInfo.dwMajorVersion == 6) && (OsInfo.dwMinorVersion == 1) )
	{
		SetSyscallNumbersSeven();
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

	if( ! ResolvePdeFunctions7(KernelImageBase, KernelImageSize) )
	{
		pdebug(1,"[DriverEntry] Error : unable to resolve PDE function \n");	
		return STATUS_SUCCESS;	
	}		

	//Hook system calls
	HookSyscalls();
	
	//Hook kernel exception dispatcher
	HookKiTrap0E(KernelImageBase,KernelImageSize);
	HookExceptionDispatcher(KernelImageBase,KernelImageSize);
		
	return STATUS_SUCCESS;
}

int ResolveNtdllPointers(PEPROCESS ProcessObj, HANDLE ProcessHandle)
{
	PUCHAR p;
	unsigned char LdrpCurrentDllInitializer_signature[] = {0xC6,0x45,0xE7,0x00,0x89,0x5D,0xFC,0xC7,0x45,0x98,0x24,0x00,0x00,0x00,0x89,0x5D,0x9C,0x6A,0x07,0x59,0x33,0xC0};
	unsigned char LdrpLoaderLock_signature[] = {0x8B,0xFF,0x55,0x8B,0xEC,0x83,0xEC,0x44,0x64,0x8B,0x0D,0x18,0x00,0x00,0x00,0x53,0x56,0x8B,0x75,0x08,0x33,0xC0,0x81,0xFE};
	
	p = FindSignatureInProcessModule(ProcessObj,ProcessHandle,0,*MmUserProbeAddress,LdrpCurrentDllInitializer_signature,sizeof(LdrpCurrentDllInitializer_signature));
	if( p )
	{					
		p = p - sizeof(void *);
		LdrpCurrentDllInitializer = *(void **)p;
		pdebug(1,"[ResolveNtdllPointers] ntdll!LdrpCurrentDllInitializer : %p\n",LdrpCurrentDllInitializer);
	}
	else
		return 0;
	
	p = FindSignatureInProcessModule(ProcessObj,ProcessHandle,0,*MmUserProbeAddress,LdrpLoaderLock_signature,sizeof(LdrpLoaderLock_signature));
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
	HANDLE hUnpackEvent = INVALID_HANDLE_VALUE;
	PidStruct MyPidStruct = {0};
	NTSTATUS r, result = STATUS_UNSUCCESSFUL;
	PidStruct * pPidStruct = NULL;
	MemModifStruct * pMemModifStruct = NULL;
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
		
			memset(TrackedPages,0,sizeof(TrackedPages));
		
			pPidStruct = (PidStruct *)InBuffer;
			
			pdebug(1,"[DriverIoControl] target Pid : %d",pPidStruct->Pid);
			pdebug(1,"[DriverIoControl] UnpackEvent : %p",pPidStruct->UnpackEvent);
			pdebug(1,"[DriverIoControl] target process handle : %p",pPidStruct->TargetProcessHandle);
			
			do_log = pPidStruct->do_log;
			TargetPid = pPidStruct->Pid;
			TargetProcessHandle = pPidStruct->TargetProcessHandle;
			hUnpackEvent = pPidStruct->hUnpackEvent;
			ProgramOep = (ULONG_PTR)pPidStruct->ExpectedEip;
			
			if (ProgramOep != 0)
				log_exceptions = 0;
			else
				log_exceptions = 1;
			
			r = ObReferenceObjectByHandle(hUnpackEvent,EVENT_ALL_ACCESS,*ExEventObjectType,UserMode,&EventObj,NULL);
			if( r == STATUS_SUCCESS )
			{
				pdebug(1,"[DriverIoControl] EventObj: %p\n",EventObj);
				//ObDereferenceObject is done in cleanup
			}
			else
			{
				pdebug(1,"[DriverIoControl] Error : unable to get event object\n");
				result = STATUS_UNSUCCESSFUL;
				break;
			}
			
			r = ObReferenceObjectByHandle(TargetProcessHandle,PROCESS_ALL_ACCESS,*PsProcessType,UserMode,&ProcessObj,NULL);
			if( r == STATUS_SUCCESS )
			{
				pdebug(1,"[DriverIoControl] ProcessObj: %p\n",ProcessObj);
			}
			else
			{
				pdebug(1,"[DriverIoControl] Error : unable to find process object\n");
				result = STATUS_UNSUCCESSFUL;
				break;
			}

			if( !ResolveNtdllPointers(ProcessObj,TargetProcessHandle) )
			{
				pdebug(1,"[DriverIoControl] Error : ResolveNtdllPointers failed\n");
				result = STATUS_UNSUCCESSFUL;
				break;
			}

			InitExceptionList();
			pdebug(1,"[DriverIoControl] Exception list initiated\n");

			first_exception_in_process = 1;
			EventSignaled = 0;
			
			InitAccessArray();
			
			if ( ProcessObj )
			{
				ObDereferenceObject(ProcessObj);
				ProcessObj = NULL;
			}
			
			pdebug(1,"[DriverIoControl] Returning\n");

			result = STATUS_SUCCESS;
			break;
		}
		
		case IOCTL_GET_EXCEPTION:
		{
			if (OutBufferSize >= sizeof(EXCEPTION_INFO))
			{
				GetFirstException( (PEXCEPTION_INFO)OutBuffer );
				ReturnedBytes = sizeof(EXCEPTION_INFO);
				result = STATUS_SUCCESS;
				break;
			}
		
			result = STATUS_INFO_LENGTH_MISMATCH;
		
			break;
		}
		
		case IOCTL_GET_EXCEPTION_COUNT:
		{
			ULONG ExceptionCount = 0;

			if (OutBufferSize >= sizeof(ULONG))
			{
				ExceptionCount = GetExceptionCount();
				
				pdebug(1,"[DriverIoControl][IOCTL_GET_EXCEPTION_COUNT] ExceptionCount = %d\n",ExceptionCount);
				
				*(ULONG *)OutBuffer = ExceptionCount;
				
				ReturnedBytes = sizeof(ULONG);
				result = STATUS_SUCCESS;
				break;
			}		
				
			result = STATUS_INFO_LENGTH_MISMATCH;
		
			break;
		}
		
		case IOCTL_CLEANUP:
		{
			TargetPid = INVALID_PID;
			
			pdebug(1,"[DriverIoControl] IOCTL_CLEANUP\n");
			
			CleanupExceptionsList();
			
			pdebug(1,"[DriverIoControl][IOCTL_CLEANUP] : exceptions list cleaned up\n");
			
			if (EventObj)
			{
				ObDereferenceObject(EventObj);
				EventObj = NULL;
			}
			
			ReturnedBytes = 0;
			result = STATUS_SUCCESS;
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
	unsigned char * p;
	
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