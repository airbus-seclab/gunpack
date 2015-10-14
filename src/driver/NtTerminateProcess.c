#include "win_kernl.h"
#include "memory_state.h"
#include "utils.h"

extern unsigned int TargetPid;
extern proto_NtTerminateProcess NtTerminateProcess;
extern proto_NtSuspendThread ZwSuspendThread;
//extern proto_NtTerminateThread ZwTerminateThread;
extern PKEVENT EventObj;
extern int do_log;
int EventSignaled = 0;

NTSTATUS NTAPI NtTerminateProcess_hook(HANDLE ProcessHandle, ULONG ExitCode)
{
	NTSTATUS r;
	PEPROCESS pEproc;
	NTSTATUS result;
	HANDLE CurrentThreadId;
	CLIENT_ID cid;
	HANDLE CurrentThreadHandle;
	OBJECT_ATTRIBUTES obj_attr;
	LARGE_INTEGER Large;
	
	if ( PsGetCurrentProcessId() != (HANDLE)TargetPid )
	{
		return NtTerminateProcess(ProcessHandle,ExitCode);
	}
	
	if ( ProcessHandle != (HANDLE)-1 )
	{
		return NtTerminateProcess(ProcessHandle,ExitCode);		
	}
	
	pdebug(do_log,"[NtTerminateProcess] Target process trying to kill himself\n");
	
	//Signal unpack event for the userland process
	if( EventSignaled == 0)
	{
		KeSetEvent(EventObj,0,0);
		EventSignaled = 1;
	}
	
	CurrentThreadId = PsGetCurrentThreadId();
	
	pdebug(do_log,"[NtTerminateProcess] Current thread id : %d\n",CurrentThreadId);
	
	cid.UniqueProcess = NULL;
	cid.UniqueThread = CurrentThreadId;
	
	memset(&obj_attr,0,sizeof(obj_attr));
	obj_attr.Length = sizeof(obj_attr);
	
	r = ZwOpenThread(&CurrentThreadHandle,THREAD_ALL_ACCESS,&obj_attr,&cid);
	if (r == STATUS_SUCCESS)
	{
		pdebug(do_log,"[NtTerminateProcess] suspending current thread...\n");
		
		ZwSuspendThread(CurrentThreadHandle,NULL);
	}
	else
	{
		pdebug(do_log,"[NtTerminateProcess] ZwOpenThread failed : 0x%x\n",r);
	}
	
	
	return STATUS_ACCESS_DENIED;
}