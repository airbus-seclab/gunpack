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

#ifndef WIN_KERNL_H
#define WIN_KERNL_H

#include <Wdm.h>
#include <ntddk.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <process.h>

#pragma comment(lib,"ntoskrnl.lib")

#define DEBOGUE 1

/*
#if DEBOGUE
#define pdebug(format, ...) DbgPrint ( format, ## __VA_ARGS__)
#else if
#define pdebug(format, ...)
#endif
*/

#define pdebug(doit,format, ...) \
	if (doit) \
		DbgPrint ( format, ## __VA_ARGS__)
		
#define FALSE 0
#define TRUE  1

#define KERNEL_MODE 0
#define USER_MODE	1

#define PAGE_SIZE 0x1000
#define KERNEL_START 0x7FFFFFFF
#define INVALID_PID  0xFFFFFFFF
#define INVALID_HANDLE_VALUE (HANDLE)-1

#define READ_ACCESS 0
#define WRITE_ACCESS 1
#define EXECUTE_ACCESS 8

#define MEM_IMAGE 0x1000000

#define KI_EXCEPTION_ACCESS_VIOLATION 0x10000004
#define STATUS_NOT_COMMITED 0xC000002D

#define MAX_PATH 260

#define APC_STATE_SIZE 0x300

#define PROCESS_QUERY_INFORMATION 0x400

#define MM_NOIRQL 0xFFFFFFFF


NTSTATUS ZwQueryVirtualMemory(
  HANDLE                   ProcessHandle,
  PVOID                    BaseAddress,
  ULONG                    MemoryInformationClass,
  PVOID                    MemoryInformation,
  SIZE_T                   MemoryInformationLength,
  PSIZE_T                  ReturnLength
);


NTSTATUS NTAPI MmMarkPhysicalMemoryAsBad(PHYSICAL_ADDRESS StartAddress, PLARGE_INTEGER NumberOfButes);


#pragma pack(push,1)
typedef struct SystemServiceTable {
        void **     ServiceTable;
        UINT32*     CounterTable;
        UINT32      ServiceLimit;
        UINT32*     ArgumentTable;
} SST;

typedef struct _MMVAD_FLAGS {
    ULONG_PTR CommitCharge : 19;
    ULONG_PTR NoChange : 1;
    ULONG_PTR VadType : 3;
    ULONG_PTR MemCommit: 1;
    ULONG_PTR Protection : 5;
    ULONG_PTR Spare : 2;
    ULONG_PTR PrivateMemory : 1;
} MMVAD_FLAGS;

typedef struct _MMADDRESS_NODE
{
     ULONG u1;
     PVOID LeftChild;
     PVOID RightChild;
     ULONG StartingVpn;
     ULONG EndingVpn;
} MMADDRESS_NODE, *PMMADDRESS_NODE;

typedef struct _MM_AVL_TABLE
{
     MMADDRESS_NODE BalancedRoot;
     ULONG DepthOfTree: 5;
     ULONG Unused: 3;
     ULONG NumberGenericTableElements: 24;
     PVOID NodeHint;
     PVOID NodeFreeHint;
} MM_AVL_TABLE, *PMM_AVL_TABLE;

typedef struct _EX_PUSH_LOCK
{
     union
     {
          ULONG Locked: 1;
          ULONG Waiting: 1;
          ULONG Waking: 1;
          ULONG MultipleShared: 1;
          ULONG Shared: 28;
          ULONG Value;
          PVOID Ptr;
     };
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;

typedef struct _MMVAD
{
	ULONG u1;
	PVOID LeftChild;
	PVOID RightChild;
	ULONG StartingVpn;
	ULONG EndingVpn;
	MMVAD_FLAGS u;
	EX_PUSH_LOCK PushLock;
	ULONG u5;
	ULONG u2;
	union
	{
		PVOID Subsection;
		PVOID MappedSubsection;
	};
	PVOID FirstPrototypePte;
	PVOID LastContiguousPte;
} MMVAD, *PMMVAD;

typedef struct _OSVERSIONINFOW {
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR  szCSDVersion[ 128 ];     // Maintenance string for PSS usage
} OSVERSIONINFOW, *POSVERSIONINFOW, *LPOSVERSIONINFOW, RTL_OSVERSIONINFOW, *PRTL_OSVERSIONINFOW;

typedef struct _PEB_LDR_DATA
{
     ULONG Length;
     UCHAR Initialized;
     PVOID SsHandle;
     LIST_ENTRY InLoadOrderModuleList;
     LIST_ENTRY InMemoryOrderModuleList;
     LIST_ENTRY InInitializationOrderModuleList;
     PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     ULONG Flags;
     USHORT LoadCount;
     USHORT TlsIndex;
     union
     {
          LIST_ENTRY HashLinks;
          struct
          {
               PVOID SectionPointer;
               ULONG CheckSum;
          };
     };
     union
     {
          ULONG TimeDateStamp;
          PVOID LoadedImports;
     };
     PVOID EntryPointActivationContext;
     PVOID PatchInformation;
     LIST_ENTRY ForwarderLinks;
     LIST_ENTRY ServiceTagLinks;
     LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
  UCHAR                          Reserved1[2];
  UCHAR                          BeingDebugged;
  UCHAR                          Reserved2[1];
  PVOID                          Reserved3[2];
  PPEB_LDR_DATA                  Ldr;
} PEB, *PPEB;

typedef struct _RTL_CRITICAL_SECTION {
    PVOID DebugInfo;

    //
    //  The following three fields control entering and exiting the critical
    //  section for the resource
    //

    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;        // from the thread's ClientId->UniqueThread
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;        // force size on 64-bit systems when packed
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;

typedef struct _SYSTEM_MODULE {
  ULONG                Reserved1;
  ULONG                Reserved2;
  PVOID                ImageBaseAddress;
  ULONG                ImageSize;
  ULONG                Flags;
  USHORT                 Id;
  USHORT                 Rank;
  USHORT                 w018;
  USHORT                 NameOffset;
  UCHAR                 Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
  ULONG                ModulesCount;
  SYSTEM_MODULE        Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _MEMORY_BASIC_INFORMATION32 {
    __int32 BaseAddress;
    __int32 AllocationBase;
    __int32 AllocationProtect;
    __int32 RegionSize;
    __int32 State;
    __int32 Protect;
    __int32 Type;
} MEMORY_BASIC_INFORMATION32, *PMEMORY_BASIC_INFORMATION32;

typedef struct _EX_FAST_REF      // 3 elements, 0x4 bytes (sizeof)
{
  union                        // 3 elements, 0x4 bytes (sizeof)
  {
/*0x000*/         VOID*        Object;
/*0x000*/         ULONG32      RefCnt : 3; // 0 BitPosition
/*0x000*/         ULONG32      Value;
  };
}EX_FAST_REF, *PEX_FAST_REF;

typedef struct _HARDWARE_PTE           // 13 elements, 0x4 bytes (sizeof)
{
/*0x000*/     ULONG32      Valid : 1;            // 0 BitPosition
/*0x000*/     ULONG32      Write : 1;            // 1 BitPosition
/*0x000*/     ULONG32      Owner : 1;            // 2 BitPosition
/*0x000*/     ULONG32      WriteThrough : 1;     // 3 BitPosition
/*0x000*/     ULONG32      CacheDisable : 1;     // 4 BitPosition
/*0x000*/     ULONG32      Accessed : 1;         // 5 BitPosition
/*0x000*/     ULONG32      Dirty : 1;            // 6 BitPosition
/*0x000*/     ULONG32      LargePage : 1;        // 7 BitPosition
/*0x000*/     ULONG32      Global : 1;           // 8 BitPosition
/*0x000*/     ULONG32      CopyOnWrite : 1;      // 9 BitPosition
/*0x000*/     ULONG32      Prototype : 1;        // 10 BitPosition
/*0x000*/     ULONG32      reserved : 1;         // 11 BitPosition
/*0x000*/     ULONG32      PageFrameNumber : 20; // 12 BitPosition
}HARDWARE_PTE, *PHARDWARE_PTE;

typedef struct _ALPC_PROCESS_CONTEXT  // 3 elements, 0x10 bytes (sizeof)
{
/*0x000*/     struct _EX_PUSH_LOCK Lock;        // 7 elements, 0x4 bytes (sizeof)
/*0x004*/     struct _LIST_ENTRY ViewListHead;  // 2 elements, 0x8 bytes (sizeof)
/*0x00C*/     ULONG32      PagedPoolQuotaCache;
}ALPC_PROCESS_CONTEXT, *PALPC_PROCESS_CONTEXT;

typedef struct _MMSUPPORT                        // 21 elements, 0x6C bytes (sizeof)
{
/*0x000*/     struct _EX_PUSH_LOCK WorkingSetMutex;        // 7 elements, 0x4 bytes (sizeof)
/*0x004*/     struct _KGATE* ExitGate;
/*0x008*/     VOID*        AccessLog;
/*0x00C*/     struct _LIST_ENTRY WorkingSetExpansionLinks; // 2 elements, 0x8 bytes (sizeof)
/*0x014*/     ULONG32      AgeDistribution[7];
/*0x030*/     ULONG32      MinimumWorkingSetSize;
/*0x034*/     ULONG32      WorkingSetSize;
/*0x038*/     ULONG32      WorkingSetPrivateSize;
/*0x03C*/     ULONG32      MaximumWorkingSetSize;
/*0x040*/     ULONG32      ChargedWslePages;
/*0x044*/     ULONG32      ActualWslePages;
/*0x048*/     ULONG32      WorkingSetSizeOverhead;
/*0x04C*/     ULONG32      PeakWorkingSetSize;
/*0x050*/     ULONG32      HardFaultCount;
/*0x054*/     struct _MMWSL* VmWorkingSetList;
/*0x058*/     UINT16       NextPageColor;
/*0x05A*/     UINT16       LastTrimStamp;
/*0x05C*/     ULONG32      PageFaultCount;
/*0x060*/     ULONG32      RepurposeCount;
/*0x064*/     ULONG32      Spare[1];
/*0x068*/     ULONG32 Flags;               // 15 elements, 0x4 bytes (sizeof)
}MMSUPPORT, *PMMSUPPORT;


typedef struct _KEXECUTE_OPTIONSX
{
     UCHAR ExecuteDisable: 1;
     UCHAR ExecuteEnable: 1;
     UCHAR DisableThunkEmulation: 1;
     UCHAR Permanent: 1;
     UCHAR ExecuteDispatchEnable: 1;
     UCHAR ImageDispatchEnable: 1;
     UCHAR Spare: 2;
} KEXECUTE_OPTIONSX, *PKEXECUTE_OPTIONSX;


typedef struct _KGDTENTRY                 // 3 elements, 0x8 bytes (sizeof)
{
/*0x000*/     UINT16       LimitLow;
/*0x002*/     UINT16       BaseLow;
  union                                 // 2 elements, 0x4 bytes (sizeof)
  {
	  struct                            // 4 elements, 0x4 bytes (sizeof)
	  {
/*0x004*/             UINT8        BaseMid;
/*0x005*/             UINT8        Flags1;
/*0x006*/             UINT8        Flags2;
/*0x007*/             UINT8        BaseHi;
	  }Bytes;
	  struct                            // 10 elements, 0x4 bytes (sizeof)
	  {
/*0x004*/             ULONG32      BaseMid : 8;     // 0 BitPosition
/*0x004*/             ULONG32      Type : 5;        // 8 BitPosition
/*0x004*/             ULONG32      Dpl : 2;         // 13 BitPosition
/*0x004*/             ULONG32      Pres : 1;        // 15 BitPosition
/*0x004*/             ULONG32      LimitHi : 4;     // 16 BitPosition
/*0x004*/             ULONG32      Sys : 1;         // 20 BitPosition
/*0x004*/             ULONG32      Reserved_0 : 1;  // 21 BitPosition
/*0x004*/             ULONG32      Default_Big : 1; // 22 BitPosition
/*0x004*/             ULONG32      Granularity : 1; // 23 BitPosition
/*0x004*/             ULONG32      BaseHi : 8;      // 24 BitPosition
	  }Bits;
  }HighWord;
}KGDTENTRY, *PKGDTENTRY;

typedef struct _KIDTENTRY        // 4 elements, 0x8 bytes (sizeof)
{
/*0x000*/     UINT16       Offset;
/*0x002*/     UINT16       Selector;
/*0x004*/     UINT16       Access;
/*0x006*/     UINT16       ExtendedOffset;
}KIDTENTRY, *PKIDTENTRY;

typedef struct _KAFFINITY_EX // 4 elements, 0xC bytes (sizeof)
{
/*0x000*/     UINT16       Count;
/*0x002*/     UINT16       Size;
/*0x004*/     ULONG32      Reserved;
/*0x008*/     ULONG32      Bitmap[1];
}KAFFINITY_EX, *PKAFFINITY_EX;

typedef struct _KPROCESS                       // 34 elements, 0x98 bytes (sizeof)
{
/*0x000*/     struct _DISPATCHER_HEADER Header;          // 30 elements, 0x10 bytes (sizeof)
/*0x010*/     struct _LIST_ENTRY ProfileListHead;        // 2 elements, 0x8 bytes (sizeof)
/*0x018*/     ULONG32      DirectoryTableBase;
/*0x01C*/     struct _KGDTENTRY LdtDescriptor;           // 3 elements, 0x8 bytes (sizeof)
/*0x024*/     struct _KIDTENTRY Int21Descriptor;         // 4 elements, 0x8 bytes (sizeof)
/*0x02C*/     struct _LIST_ENTRY ThreadListHead;         // 2 elements, 0x8 bytes (sizeof)
/*0x034*/     ULONG32      ProcessLock;
/*0x038*/     struct _KAFFINITY_EX Affinity;             // 4 elements, 0xC bytes (sizeof)
/*0x044*/     struct _LIST_ENTRY ReadyListHead;          // 2 elements, 0x8 bytes (sizeof)
/*0x04C*/     struct _SINGLE_LIST_ENTRY SwapListEntry;   // 1 elements, 0x4 bytes (sizeof)
/*0x050*/     struct _KAFFINITY_EX ActiveProcessors;     // 4 elements, 0xC bytes (sizeof)
              union                                      // 2 elements, 0x4 bytes (sizeof)
              {
                  struct                                 // 5 elements, 0x4 bytes (sizeof)
                  {
/*0x05C*/             LONG32       AutoAlignment : 1;    // 0 BitPosition
/*0x05C*/             LONG32       DisableBoost : 1;     // 1 BitPosition
/*0x05C*/             LONG32       DisableQuantum : 1;   // 2 BitPosition
/*0x05C*/             ULONG32      ActiveGroupsMask : 1; // 3 BitPosition
/*0x05C*/             LONG32       ReservedFlags : 28;   // 4 BitPosition
                  };
/*0x05C*/         LONG32       ProcessFlags;
              };
/*0x060*/     CHAR         BasePriority;
/*0x061*/     CHAR         QuantumReset;
/*0x062*/     UINT8        Visited;
/*0x063*/     UINT8        Unused3;
/*0x064*/     ULONG32      ThreadSeed[1];
/*0x068*/     UINT16       IdealNode[1];
/*0x06A*/     UINT16       IdealGlobalNode;
/*0x06C*/     union                                      // 2 elements, 0x4 bytes (sizeof)
              {			  
				struct _KEXECUTE_OPTIONSX Flags;             // 9 elements, 0x1 bytes (sizeof)
				UCHAR  ExecuteOptions;
			  };
/*0x06D*/     UINT8        Unused1;
/*0x06E*/     UINT16       IopmOffset;
/*0x070*/     ULONG32      Unused4;
/*0x074*/     ULONG32      StackCount;            // 3 elements, 0x4 bytes (sizeof)
/*0x078*/     struct _LIST_ENTRY ProcessListEntry;       // 2 elements, 0x8 bytes (sizeof)
/*0x080*/     UINT64       CycleTime;
/*0x088*/     ULONG32      KernelTime;
/*0x08C*/     ULONG32      UserTime;
/*0x090*/     VOID*        VdmTrapcHandler;
/*0x094*/     UINT8        _PADDING0_[0x4];
}KPROCESS, *PKPROCESS;


typedef struct _EPROCESS                                      // 134 elements, 0x2C0 bytes (sizeof)
{
/*0x000*/     struct _KPROCESS Pcb;       //lame                                       // 34 elements, 0x98 bytes (sizeof)
/*0x098*/     struct _EX_PUSH_LOCK ProcessLock;                                  // 7 elements, 0x4 bytes (sizeof)
/*0x09C*/     UINT8        _PADDING0_[0x4];
/*0x0A0*/     union _LARGE_INTEGER CreateTime;                                   // 4 elements, 0x8 bytes (sizeof)
/*0x0A8*/     union _LARGE_INTEGER ExitTime;                                     // 4 elements, 0x8 bytes (sizeof)
/*0x0B0*/     struct _EX_RUNDOWN_REF RundownProtect;                             // 2 elements, 0x4 bytes (sizeof)
/*0x0B4*/     VOID*        UniqueProcessId;
/*0x0B8*/     struct _LIST_ENTRY ActiveProcessLinks;                             // 2 elements, 0x8 bytes (sizeof)
/*0x0C0*/     ULONG32      ProcessQuotaUsage[2];
/*0x0C8*/     ULONG32      ProcessQuotaPeak[2];
/*0x0D0*/     ULONG32      CommitCharge;
/*0x0D4*/     struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;
/*0x0D8*/     struct _PS_CPU_QUOTA_BLOCK* CpuQuotaBlock;
/*0x0DC*/     ULONG32      PeakVirtualSize;
/*0x0E0*/     ULONG32      VirtualSize;
/*0x0E4*/     struct _LIST_ENTRY SessionProcessLinks;                            // 2 elements, 0x8 bytes (sizeof)
/*0x0EC*/     VOID*        DebugPort;
              union                                                              // 3 elements, 0x4 bytes (sizeof)
              {
/*0x0F0*/         VOID*        ExceptionPortData;
/*0x0F0*/         ULONG32      ExceptionPortValue;
/*0x0F0*/         ULONG32      ExceptionPortState : 3;                           // 0 BitPosition
              };
/*0x0F4*/     struct _HANDLE_TABLE* ObjectTable;
/*0x0F8*/     struct _EX_FAST_REF Token;                                         // 3 elements, 0x4 bytes (sizeof)
/*0x0FC*/     ULONG32      WorkingSetPage;
/*0x100*/     struct _EX_PUSH_LOCK AddressCreationLock;                          // 7 elements, 0x4 bytes (sizeof)
/*0x104*/     struct _ETHREAD* RotateInProgress;
/*0x108*/     struct _ETHREAD* ForkInProgress;
/*0x10C*/     ULONG32      HardwareTrigger;
/*0x110*/     struct _MM_AVL_TABLE* PhysicalVadRoot;
/*0x114*/     VOID*        CloneRoot;
/*0x118*/     ULONG32      NumberOfPrivatePages;
/*0x11C*/     ULONG32      NumberOfLockedPages;
/*0x120*/     VOID*        Win32Process;
/*0x124*/     struct _EJOB* Job;
/*0x128*/     VOID*        SectionObject;
/*0x12C*/     VOID*        SectionBaseAddress;
/*0x130*/     ULONG32      Cookie;
/*0x134*/     ULONG32      Spare8;
/*0x138*/     struct _PAGEFAULT_HISTORY* WorkingSetWatch;
/*0x13C*/     VOID*        Win32WindowStation;
/*0x140*/     VOID*        InheritedFromUniqueProcessId;
/*0x144*/     VOID*        LdtInformation;
/*0x148*/     VOID*        VdmObjects;
/*0x14C*/     ULONG32      ConsoleHostProcess;
/*0x150*/     VOID*        DeviceMap;
/*0x154*/     VOID*        EtwDataSource;
/*0x158*/     VOID*        FreeTebHint;
/*0x15C*/     UINT8        _PADDING1_[0x4];
              union                                                              // 2 elements, 0x8 bytes (sizeof)
              {
/*0x160*/         struct _HARDWARE_PTE PageDirectoryPte;                         // 13 elements, 0x4 bytes (sizeof)
/*0x160*/         UINT64       Filler;
              };
/*0x168*/     VOID*        Session;
/*0x16C*/     UINT8        ImageFileName[15];
/*0x17B*/     UINT8        PriorityClass;
/*0x17C*/     struct _LIST_ENTRY JobLinks;                                       // 2 elements, 0x8 bytes (sizeof)
/*0x184*/     VOID*        LockedPagesList;
/*0x188*/     struct _LIST_ENTRY ThreadListHead;                                 // 2 elements, 0x8 bytes (sizeof)
/*0x190*/     VOID*        SecurityPort;
/*0x194*/     VOID*        PaeTop;
/*0x198*/     ULONG32      ActiveThreads;
/*0x19C*/     ULONG32      ImagePathHash;
/*0x1A0*/     ULONG32      DefaultHardErrorProcessing;
/*0x1A4*/     LONG32       LastThreadExitStatus;
/*0x1A8*/     struct _PEB* Peb;
/*0x1AC*/     struct _EX_FAST_REF PrefetchTrace;                                 // 3 elements, 0x4 bytes (sizeof)
/*0x1B0*/     union _LARGE_INTEGER ReadOperationCount;                           // 4 elements, 0x8 bytes (sizeof)
/*0x1B8*/     union _LARGE_INTEGER WriteOperationCount;                          // 4 elements, 0x8 bytes (sizeof)
/*0x1C0*/     union _LARGE_INTEGER OtherOperationCount;                          // 4 elements, 0x8 bytes (sizeof)
/*0x1C8*/     union _LARGE_INTEGER ReadTransferCount;                            // 4 elements, 0x8 bytes (sizeof)
/*0x1D0*/     union _LARGE_INTEGER WriteTransferCount;                           // 4 elements, 0x8 bytes (sizeof)
/*0x1D8*/     union _LARGE_INTEGER OtherTransferCount;                           // 4 elements, 0x8 bytes (sizeof)
/*0x1E0*/     ULONG32      CommitChargeLimit;
/*0x1E4*/     ULONG32      CommitChargePeak;
/*0x1E8*/     VOID*        AweInfo;
/*0x1EC*/     PVOID SeAuditProcessCreationInfo; // 1 elements, 0x4 bytes (sizeof)
/*0x1F0*/     struct _MMSUPPORT Vm;                                              // 21 elements, 0x6C bytes (sizeof)
/*0x25C*/     struct _LIST_ENTRY MmProcessLinks;                                 // 2 elements, 0x8 bytes (sizeof)
/*0x264*/     VOID*        HighestUserAddress;
/*0x268*/     ULONG32      ModifiedPageCount;
              union                                                              // 2 elements, 0x4 bytes (sizeof)
              {
/*0x26C*/         ULONG32      Flags2;
                  struct                                                         // 20 elements, 0x4 bytes (sizeof)
                  {
/*0x26C*/             ULONG32      JobNotReallyActive : 1;                       // 0 BitPosition
/*0x26C*/             ULONG32      AccountingFolded : 1;                         // 1 BitPosition
/*0x26C*/             ULONG32      NewProcessReported : 1;                       // 2 BitPosition
/*0x26C*/             ULONG32      ExitProcessReported : 1;                      // 3 BitPosition
/*0x26C*/             ULONG32      ReportCommitChanges : 1;                      // 4 BitPosition
/*0x26C*/             ULONG32      LastReportMemory : 1;                         // 5 BitPosition
/*0x26C*/             ULONG32      ReportPhysicalPageChanges : 1;                // 6 BitPosition
/*0x26C*/             ULONG32      HandleTableRundown : 1;                       // 7 BitPosition
/*0x26C*/             ULONG32      NeedsHandleRundown : 1;                       // 8 BitPosition
/*0x26C*/             ULONG32      RefTraceEnabled : 1;                          // 9 BitPosition
/*0x26C*/             ULONG32      NumaAware : 1;                                // 10 BitPosition
/*0x26C*/             ULONG32      ProtectedProcess : 1;                         // 11 BitPosition
/*0x26C*/             ULONG32      DefaultPagePriority : 3;                      // 12 BitPosition
/*0x26C*/             ULONG32      PrimaryTokenFrozen : 1;                       // 15 BitPosition
/*0x26C*/             ULONG32      ProcessVerifierTarget : 1;                    // 16 BitPosition
/*0x26C*/             ULONG32      StackRandomizationDisabled : 1;               // 17 BitPosition
/*0x26C*/             ULONG32      AffinityPermanent : 1;                        // 18 BitPosition
/*0x26C*/             ULONG32      AffinityUpdateEnable : 1;                     // 19 BitPosition
/*0x26C*/             ULONG32      PropagateNode : 1;                            // 20 BitPosition
/*0x26C*/             ULONG32      ExplicitAffinity : 1;                         // 21 BitPosition
                  };
              };
              union                                                              // 2 elements, 0x4 bytes (sizeof)
              {
/*0x270*/         ULONG32      Flags;
                  struct                                                         // 29 elements, 0x4 bytes (sizeof)
                  {
/*0x270*/             ULONG32      CreateReported : 1;                           // 0 BitPosition
/*0x270*/             ULONG32      NoDebugInherit : 1;                           // 1 BitPosition
/*0x270*/             ULONG32      ProcessExiting : 1;                           // 2 BitPosition
/*0x270*/             ULONG32      ProcessDelete : 1;                            // 3 BitPosition
/*0x270*/             ULONG32      Wow64SplitPages : 1;                          // 4 BitPosition
/*0x270*/             ULONG32      VmDeleted : 1;                                // 5 BitPosition
/*0x270*/             ULONG32      OutswapEnabled : 1;                           // 6 BitPosition
/*0x270*/             ULONG32      Outswapped : 1;                               // 7 BitPosition
/*0x270*/             ULONG32      ForkFailed : 1;                               // 8 BitPosition
/*0x270*/             ULONG32      Wow64VaSpace4Gb : 1;                          // 9 BitPosition
/*0x270*/             ULONG32      AddressSpaceInitialized : 2;                  // 10 BitPosition
/*0x270*/             ULONG32      SetTimerResolution : 1;                       // 12 BitPosition
/*0x270*/             ULONG32      BreakOnTermination : 1;                       // 13 BitPosition
/*0x270*/             ULONG32      DeprioritizeViews : 1;                        // 14 BitPosition
/*0x270*/             ULONG32      WriteWatch : 1;                               // 15 BitPosition
/*0x270*/             ULONG32      ProcessInSession : 1;                         // 16 BitPosition
/*0x270*/             ULONG32      OverrideAddressSpace : 1;                     // 17 BitPosition
/*0x270*/             ULONG32      HasAddressSpace : 1;                          // 18 BitPosition
/*0x270*/             ULONG32      LaunchPrefetched : 1;                         // 19 BitPosition
/*0x270*/             ULONG32      InjectInpageErrors : 1;                       // 20 BitPosition
/*0x270*/             ULONG32      VmTopDown : 1;                                // 21 BitPosition
/*0x270*/             ULONG32      ImageNotifyDone : 1;                          // 22 BitPosition
/*0x270*/             ULONG32      PdeUpdateNeeded : 1;                          // 23 BitPosition
/*0x270*/             ULONG32      VdmAllowed : 1;                               // 24 BitPosition
/*0x270*/             ULONG32      CrossSessionCreate : 1;                       // 25 BitPosition
/*0x270*/             ULONG32      ProcessInserted : 1;                          // 26 BitPosition
/*0x270*/             ULONG32      DefaultIoPriority : 3;                        // 27 BitPosition
/*0x270*/             ULONG32      ProcessSelfDelete : 1;                        // 30 BitPosition
/*0x270*/             ULONG32      SetTimerResolutionLink : 1;                   // 31 BitPosition
                  };
              };
/*0x274*/     LONG32       ExitStatus;
/*0x278*/     struct _MM_AVL_TABLE VadRoot;                                      // 6 elements, 0x20 bytes (sizeof)
/*0x298*/     struct _ALPC_PROCESS_CONTEXT AlpcContext;                          // 3 elements, 0x10 bytes (sizeof)
/*0x2A8*/     struct _LIST_ENTRY TimerResolutionLink;                            // 2 elements, 0x8 bytes (sizeof)
/*0x2B0*/     ULONG32      RequestedTimerResolution;
/*0x2B4*/     ULONG32      ActiveThreadsHighWatermark;
/*0x2B8*/     ULONG32      SmallestTimerResolution;
/*0x2BC*/     struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;
}MYEPROCESS, *PMYEPROCESS;


typedef struct _KAPC_STATE             // 5 elements, 0x18 bytes (sizeof)
{
/*0x000*/     struct _LIST_ENTRY ApcListHead[2];
/*0x010*/     struct _KPROCESS* Process;
/*0x014*/     UINT8        KernelApcInProgress;
/*0x015*/     UINT8        KernelApcPending;
/*0x016*/     UINT8        UserApcPending;
/*0x017*/     UINT8        _PADDING0_[0x1];
}KAPC_STATE, *PKAPC_STATE;


typedef struct _KTHREAD                                 // 114 elements, 0x200 bytes (sizeof)
{
/*0x000*/     struct _DISPATCHER_HEADER Header;                   // 30 elements, 0x10 bytes (sizeof)
/*0x010*/     UINT64       CycleTime;
/*0x018*/     ULONG32      HighCycleTime;
/*0x01C*/     UINT8        _PADDING0_[0x4];
/*0x020*/     UINT64       QuantumTarget;
/*0x028*/     VOID*        InitialStack;
/*0x02C*/     VOID*        StackLimit;
/*0x030*/     VOID*        KernelStack;
/*0x034*/     ULONG32      ThreadLock;
/*0x038*/     UINT8 WaitRegister;          // 8 elements, 0x1 bytes (sizeof)
/*0x039*/     UINT8        Running;
/*0x03A*/     UINT8        Alerted[2];
              union                                               // 2 elements, 0x4 bytes (sizeof)
              {
                  struct                                          // 14 elements, 0x4 bytes (sizeof)
                  {
/*0x03C*/             ULONG32      KernelStackResident : 1;       // 0 BitPosition
/*0x03C*/             ULONG32      ReadyTransition : 1;           // 1 BitPosition
/*0x03C*/             ULONG32      ProcessReadyQueue : 1;         // 2 BitPosition
/*0x03C*/             ULONG32      WaitNext : 1;                  // 3 BitPosition
/*0x03C*/             ULONG32      SystemAffinityActive : 1;      // 4 BitPosition
/*0x03C*/             ULONG32      Alertable : 1;                 // 5 BitPosition
/*0x03C*/             ULONG32      GdiFlushActive : 1;            // 6 BitPosition
/*0x03C*/             ULONG32      UserStackWalkActive : 1;       // 7 BitPosition
/*0x03C*/             ULONG32      ApcInterruptRequest : 1;       // 8 BitPosition
/*0x03C*/             ULONG32      ForceDeferSchedule : 1;        // 9 BitPosition
/*0x03C*/             ULONG32      QuantumEndMigrate : 1;         // 10 BitPosition
/*0x03C*/             ULONG32      UmsDirectedSwitchEnable : 1;   // 11 BitPosition
/*0x03C*/             ULONG32      TimerActive : 1;               // 12 BitPosition
/*0x03C*/             ULONG32      Reserved : 19;                 // 13 BitPosition
                  };
/*0x03C*/         LONG32       MiscFlags;
              };
              union                                               // 2 elements, 0x18 bytes (sizeof)
              {
/*0x040*/         struct _KAPC_STATE ApcState;                    // 5 elements, 0x18 bytes (sizeof)
                  struct                                          // 2 elements, 0x18 bytes (sizeof)
                  {
/*0x040*/             UINT8        ApcStateFill[23];
/*0x057*/             CHAR         Priority;
                  };
              };
/*0x058*/     ULONG32      NextProcessor;
/*0x05C*/     ULONG32      DeferredProcessor;
/*0x060*/     ULONG32      ApcQueueLock;
/*0x064*/     ULONG32      ContextSwitches;
/*0x068*/     UINT8        State;
/*0x069*/     CHAR         NpxState;
/*0x06A*/     UINT8        WaitIrql;
/*0x06B*/     CHAR         WaitMode;
/*0x06C*/     LONG32       WaitStatus;
/*0x070*/     struct _KWAIT_BLOCK* WaitBlockList;
              union                                               // 2 elements, 0x8 bytes (sizeof)
              {
/*0x074*/         struct _LIST_ENTRY WaitListEntry;               // 2 elements, 0x8 bytes (sizeof)
/*0x074*/         struct _SINGLE_LIST_ENTRY SwapListEntry;        // 1 elements, 0x4 bytes (sizeof)
              };
/*0x07C*/     struct _KQUEUE* Queue;
/*0x080*/     ULONG32      WaitTime;
              union                                               // 2 elements, 0x4 bytes (sizeof)
              {
                  struct                                          // 2 elements, 0x4 bytes (sizeof)
                  {
/*0x084*/             INT16        KernelApcDisable;
/*0x086*/             INT16        SpecialApcDisable;
                  };
/*0x084*/         ULONG32      CombinedApcDisable;
              };
/*0x088*/     VOID*        Teb;
/*0x08C*/     UINT8        _PADDING1_[0x4];
/*0x090*/     struct _KTIMER Timer;                               // 5 elements, 0x28 bytes (sizeof)
              union                                               // 2 elements, 0x4 bytes (sizeof)
              {
                  struct                                          // 10 elements, 0x4 bytes (sizeof)
                  {
/*0x0B8*/             ULONG32      AutoAlignment : 1;             // 0 BitPosition
/*0x0B8*/             ULONG32      DisableBoost : 1;              // 1 BitPosition
/*0x0B8*/             ULONG32      EtwStackTraceApc1Inserted : 1; // 2 BitPosition
/*0x0B8*/             ULONG32      EtwStackTraceApc2Inserted : 1; // 3 BitPosition
/*0x0B8*/             ULONG32      CalloutActive : 1;             // 4 BitPosition
/*0x0B8*/             ULONG32      ApcQueueable : 1;              // 5 BitPosition
/*0x0B8*/             ULONG32      EnableStackSwap : 1;           // 6 BitPosition
/*0x0B8*/             ULONG32      GuiThread : 1;                 // 7 BitPosition
/*0x0B8*/             ULONG32      UmsPerformingSyscall : 1;      // 8 BitPosition
/*0x0B8*/             ULONG32      ReservedFlags : 23;            // 9 BitPosition
                  };
/*0x0B8*/         LONG32       ThreadFlags;
              };
/*0x0BC*/     VOID*        ServiceTable;
/*0x0C0*/     struct _KWAIT_BLOCK WaitBlock[4];
/*0x120*/     struct _LIST_ENTRY QueueListEntry;                  // 2 elements, 0x8 bytes (sizeof)
/*0x128*/     struct _KTRAP_FRAME* TrapFrame;
/*0x12C*/     VOID*        FirstArgument;
              union                                               // 2 elements, 0x4 bytes (sizeof)
              {
/*0x130*/         VOID*        CallbackStack;
/*0x130*/         ULONG32      CallbackDepth;
              };
/*0x134*/     UINT8        ApcStateIndex;
/*0x135*/     CHAR         BasePriority;
              union                                               // 2 elements, 0x1 bytes (sizeof)
              {
/*0x136*/         CHAR         PriorityDecrement;
                  struct                                          // 2 elements, 0x1 bytes (sizeof)
                  {
/*0x136*/             UINT8        ForegroundBoost : 4;           // 0 BitPosition
/*0x136*/             UINT8        UnusualBoost : 4;              // 4 BitPosition
                  };
              };
/*0x137*/     UINT8        Preempted;
/*0x138*/     UINT8        AdjustReason;
/*0x139*/     CHAR         AdjustIncrement;
/*0x13A*/     CHAR         PreviousMode;
/*0x13B*/     CHAR         Saturation;
/*0x13C*/     ULONG32      SystemCallNumber;
/*0x140*/     ULONG32      FreezeCount;
/*0x144*/     struct _GROUP_AFFINITY UserAffinity;                // 3 elements, 0xC bytes (sizeof)
/*0x150*/     struct _KPROCESS* Process;
/*0x154*/     struct _GROUP_AFFINITY Affinity;                    // 3 elements, 0xC bytes (sizeof)
/*0x160*/     ULONG32      IdealProcessor;
/*0x164*/     ULONG32      UserIdealProcessor;
/*0x168*/     struct _KAPC_STATE* ApcStatePointer[2];
              union                                               // 2 elements, 0x18 bytes (sizeof)
              {
/*0x170*/         struct _KAPC_STATE SavedApcState;               // 5 elements, 0x18 bytes (sizeof)
                  struct                                          // 2 elements, 0x18 bytes (sizeof)
                  {
/*0x170*/             UINT8        SavedApcStateFill[23];
/*0x187*/             UINT8        WaitReason;
                  };
              };
/*0x188*/     CHAR         SuspendCount;
/*0x189*/     CHAR         Spare1;
/*0x18A*/     UINT8        OtherPlatformFill;
/*0x18B*/     UINT8        _PADDING2_[0x1];
/*0x18C*/     VOID*        Win32Thread;
/*0x190*/     VOID*        StackBase;
              union                                               // 7 elements, 0x30 bytes (sizeof)
              {
/*0x194*/         struct _KAPC SuspendApc;                        // 16 elements, 0x30 bytes (sizeof)
                  struct                                          // 2 elements, 0x30 bytes (sizeof)
                  {
/*0x194*/             UINT8        SuspendApcFill0[1];
/*0x195*/             UINT8        ResourceIndex;
/*0x196*/             UINT8        _PADDING3_[0x2E];
                  };
                  struct                                          // 2 elements, 0x30 bytes (sizeof)
                  {
/*0x194*/             UINT8        SuspendApcFill1[3];
/*0x197*/             UINT8        QuantumReset;
/*0x198*/             UINT8        _PADDING4_[0x2C];
                  };
                  struct                                          // 2 elements, 0x30 bytes (sizeof)
                  {
/*0x194*/             UINT8        SuspendApcFill2[4];
/*0x198*/             ULONG32      KernelTime;
/*0x19C*/             UINT8        _PADDING5_[0x28];
                  };
                  struct                                          // 2 elements, 0x30 bytes (sizeof)
                  {
/*0x194*/             UINT8        SuspendApcFill3[36];
/*0x1B8*/             struct _KPRCB* WaitPrcb;
/*0x1BC*/             UINT8        _PADDING6_[0x8];
                  };
                  struct                                          // 2 elements, 0x30 bytes (sizeof)
                  {
/*0x194*/             UINT8        SuspendApcFill4[40];
/*0x1BC*/             VOID*        LegoData;
/*0x1C0*/             UINT8        _PADDING7_[0x4];
                  };
                  struct                                          // 2 elements, 0x30 bytes (sizeof)
                  {
/*0x194*/             UINT8        SuspendApcFill5[47];
/*0x1C3*/             UINT8        LargeStack;
                  };
              };
/*0x1C4*/     ULONG32      UserTime;
              union                                               // 2 elements, 0x14 bytes (sizeof)
              {
/*0x1C8*/         struct _KSEMAPHORE SuspendSemaphore;            // 2 elements, 0x14 bytes (sizeof)
/*0x1C8*/         UINT8        SuspendSemaphorefill[20];
              };
/*0x1DC*/     ULONG32      SListFaultCount;
/*0x1E0*/     struct _LIST_ENTRY ThreadListEntry;                 // 2 elements, 0x8 bytes (sizeof)
/*0x1E8*/     struct _LIST_ENTRY MutantListHead;                  // 2 elements, 0x8 bytes (sizeof)
/*0x1F0*/     VOID*        SListFaultAddress;
/*0x1F4*/     struct _KTHREAD_COUNTERS* ThreadCounters;
/*0x1F8*/     struct _XSTATE_SAVE* XStateSave;
/*0x1FC*/     UINT8        _PADDING8_[0x4];
          }KTHREAD, *PKTHREAD;



typedef struct _ETHREAD                                              // 88 elements, 0x2B8 bytes (sizeof)
{
/*0x000*/     struct _KTHREAD Tcb;                                             // 114 elements, 0x200 bytes (sizeof)
/*0x200*/     union _LARGE_INTEGER CreateTime;                                 // 4 elements, 0x8 bytes (sizeof)
              union                                                            // 2 elements, 0x8 bytes (sizeof)
              {
/*0x208*/         union _LARGE_INTEGER ExitTime;                               // 4 elements, 0x8 bytes (sizeof)
/*0x208*/         struct _LIST_ENTRY KeyedWaitChain;                           // 2 elements, 0x8 bytes (sizeof)
              };
/*0x210*/     LONG32       ExitStatus;
              union                                                            // 2 elements, 0x8 bytes (sizeof)
              {
/*0x214*/         struct _LIST_ENTRY PostBlockList;                            // 2 elements, 0x8 bytes (sizeof)
                  struct                                                       // 2 elements, 0x8 bytes (sizeof)
                  {
/*0x214*/             VOID*        ForwardLinkShadow;
/*0x218*/             VOID*        StartAddress;
                  };
              };
              union                                                            // 3 elements, 0x4 bytes (sizeof)
              {
/*0x21C*/         struct _TERMINATION_PORT* TerminationPort;
/*0x21C*/         struct _ETHREAD* ReaperLink;
/*0x21C*/         VOID*        KeyedWaitValue;
              };
/*0x220*/     ULONG32      ActiveTimerListLock;
/*0x224*/     struct _LIST_ENTRY ActiveTimerListHead;                          // 2 elements, 0x8 bytes (sizeof)
/*0x22C*/     struct _CLIENT_ID Cid;                                           // 2 elements, 0x8 bytes (sizeof)
              union                                                            // 2 elements, 0x14 bytes (sizeof)
              {
/*0x234*/         struct _KSEMAPHORE KeyedWaitSemaphore;                       // 2 elements, 0x14 bytes (sizeof)
/*0x234*/         struct _KSEMAPHORE AlpcWaitSemaphore;                        // 2 elements, 0x14 bytes (sizeof)
              };
/*0x248*/     ULONG32 ClientSecurity;                // 4 elements, 0x4 bytes (sizeof)
/*0x24C*/     struct _LIST_ENTRY IrpList;                                      // 2 elements, 0x8 bytes (sizeof)
/*0x254*/     ULONG32      TopLevelIrp;
/*0x258*/     struct _DEVICE_OBJECT* DeviceToVerify;
/*0x25C*/     union _PSP_CPU_QUOTA_APC* CpuQuotaApc;
/*0x260*/     VOID*        Win32StartAddress;
/*0x264*/     VOID*        LegacyPowerObject;
/*0x268*/     struct _LIST_ENTRY ThreadListEntry;                              // 2 elements, 0x8 bytes (sizeof)
/*0x270*/     struct _EX_RUNDOWN_REF RundownProtect;                           // 2 elements, 0x4 bytes (sizeof)
/*0x274*/     struct _EX_PUSH_LOCK ThreadLock;                                 // 7 elements, 0x4 bytes (sizeof)
/*0x278*/     ULONG32      ReadClusterSize;
/*0x27C*/     LONG32       MmLockOrdering;
              union                                                            // 2 elements, 0x4 bytes (sizeof)
              {
/*0x280*/         ULONG32      CrossThreadFlags;
                  struct                                                       // 14 elements, 0x4 bytes (sizeof)
                  {
/*0x280*/             ULONG32      Terminated : 1;                             // 0 BitPosition
/*0x280*/             ULONG32      ThreadInserted : 1;                         // 1 BitPosition
/*0x280*/             ULONG32      HideFromDebugger : 1;                       // 2 BitPosition
/*0x280*/             ULONG32      ActiveImpersonationInfo : 1;                // 3 BitPosition
/*0x280*/             ULONG32      SystemThread : 1;                           // 4 BitPosition
/*0x280*/             ULONG32      HardErrorsAreDisabled : 1;                  // 5 BitPosition
/*0x280*/             ULONG32      BreakOnTermination : 1;                     // 6 BitPosition
/*0x280*/             ULONG32      SkipCreationMsg : 1;                        // 7 BitPosition
/*0x280*/             ULONG32      SkipTerminationMsg : 1;                     // 8 BitPosition
/*0x280*/             ULONG32      CopyTokenOnOpen : 1;                        // 9 BitPosition
/*0x280*/             ULONG32      ThreadIoPriority : 3;                       // 10 BitPosition
/*0x280*/             ULONG32      ThreadPagePriority : 3;                     // 13 BitPosition
/*0x280*/             ULONG32      RundownFail : 1;                            // 16 BitPosition
/*0x280*/             ULONG32      NeedsWorkingSetAging : 1;                   // 17 BitPosition
                  };
              };
              union                                                            // 2 elements, 0x4 bytes (sizeof)
              {
/*0x284*/         ULONG32      SameThreadPassiveFlags;
                  struct                                                       // 7 elements, 0x4 bytes (sizeof)
                  {
/*0x284*/             ULONG32      ActiveExWorker : 1;                         // 0 BitPosition
/*0x284*/             ULONG32      ExWorkerCanWaitUser : 1;                    // 1 BitPosition
/*0x284*/             ULONG32      MemoryMaker : 1;                            // 2 BitPosition
/*0x284*/             ULONG32      ClonedThread : 1;                           // 3 BitPosition
/*0x284*/             ULONG32      KeyedEventInUse : 1;                        // 4 BitPosition
/*0x284*/             ULONG32      RateApcState : 2;                           // 5 BitPosition
/*0x284*/             ULONG32      SelfTerminate : 1;                          // 7 BitPosition
                  };
              };
              union                                                            // 2 elements, 0x4 bytes (sizeof)
              {
/*0x288*/         ULONG32      SameThreadApcFlags;
                  struct                                                       // 4 elements, 0x4 bytes (sizeof)
                  {
                      struct                                                   // 8 elements, 0x1 bytes (sizeof)
                      {
/*0x288*/                 UINT8        Spare : 1;                              // 0 BitPosition
/*0x288*/                 UINT8        StartAddressInvalid : 1;                // 1 BitPosition
/*0x288*/                 UINT8        EtwPageFaultCalloutActive : 1;          // 2 BitPosition
/*0x288*/                 UINT8        OwnsProcessWorkingSetExclusive : 1;     // 3 BitPosition
/*0x288*/                 UINT8        OwnsProcessWorkingSetShared : 1;        // 4 BitPosition
/*0x288*/                 UINT8        OwnsSystemCacheWorkingSetExclusive : 1; // 5 BitPosition
/*0x288*/                 UINT8        OwnsSystemCacheWorkingSetShared : 1;    // 6 BitPosition
/*0x288*/                 UINT8        OwnsSessionWorkingSetExclusive : 1;     // 7 BitPosition
                      };
                      struct                                                   // 8 elements, 0x1 bytes (sizeof)
                      {
/*0x289*/                 UINT8        OwnsSessionWorkingSetShared : 1;        // 0 BitPosition
/*0x289*/                 UINT8        OwnsProcessAddressSpaceExclusive : 1;   // 1 BitPosition
/*0x289*/                 UINT8        OwnsProcessAddressSpaceShared : 1;      // 2 BitPosition
/*0x289*/                 UINT8        SuppressSymbolLoad : 1;                 // 3 BitPosition
/*0x289*/                 UINT8        Prefetching : 1;                        // 4 BitPosition
/*0x289*/                 UINT8        OwnsDynamicMemoryShared : 1;            // 5 BitPosition
/*0x289*/                 UINT8        OwnsChangeControlAreaExclusive : 1;     // 6 BitPosition
/*0x289*/                 UINT8        OwnsChangeControlAreaShared : 1;        // 7 BitPosition
                      };
                      struct                                                   // 6 elements, 0x1 bytes (sizeof)
                      {
/*0x28A*/                 UINT8        OwnsPagedPoolWorkingSetExclusive : 1;   // 0 BitPosition
/*0x28A*/                 UINT8        OwnsPagedPoolWorkingSetShared : 1;      // 1 BitPosition
/*0x28A*/                 UINT8        OwnsSystemPtesWorkingSetExclusive : 1;  // 2 BitPosition
/*0x28A*/                 UINT8        OwnsSystemPtesWorkingSetShared : 1;     // 3 BitPosition
/*0x28A*/                 UINT8        TrimTrigger : 2;                        // 4 BitPosition
/*0x28A*/                 UINT8        Spare1 : 2;                             // 6 BitPosition
                      };
/*0x28B*/             UINT8        PriorityRegionActive;
                  };
              };
/*0x28C*/     UINT8        CacheManagerActive;
/*0x28D*/     UINT8        DisablePageFaultClustering;
/*0x28E*/     UINT8        ActiveFaultCount;
/*0x28F*/     UINT8        LockOrderState;
/*0x290*/     ULONG32      AlpcMessageId;
              union                                                            // 2 elements, 0x4 bytes (sizeof)
              {
/*0x294*/         VOID*        AlpcMessage;
/*0x294*/         ULONG32      AlpcReceiveAttributeSet;
              };
/*0x298*/     struct _LIST_ENTRY AlpcWaitListEntry;                            // 2 elements, 0x8 bytes (sizeof)
/*0x2A0*/     ULONG32      CacheManagerCount;
/*0x2A4*/     ULONG32      IoBoostCount;
/*0x2A8*/     ULONG32      IrpListLock;
/*0x2AC*/     VOID*        ReservedForSynchTracking;
/*0x2B0*/     struct _SINGLE_LIST_ENTRY CmCallbackListHead;                    // 1 elements, 0x4 bytes (sizeof)
/*0x2B4*/     UINT8        _PADDING0_[0x4];
          }ETHREAD, *PETHREAD;




#pragma pack(pop)

NTSTATUS RtlGetVersion(
    __out __drv_at(lpVersionInformation->dwOSVersionInfoSize,  __inout)
        PRTL_OSVERSIONINFOW lpVersionInformation
 );
 
//NTSTATUS ZwQueryVirtualMemory(HANDLE , PVOID , __int32 , PVOID , ULONG , PULONG );
NTSTATUS ZwOpenThread(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID);
NTSTATUS ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);


void KeStackAttachProcess(PEPROCESS , void * );
void KeUnstackDetachProcess(void * );

HANDLE PsGetCurrentProcessId(void);
HANDLE PsGetProcessId(PEPROCESS Process);
HANDLE PsGetCurrentThreadId();


//Hooked functions prototypes
typedef NTSTATUS (NTAPI *proto_NtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI *proto_NtProtectVirtualMemory)(HANDLE, PVOID *, PULONG, ULONG, PULONG);
typedef NTSTATUS (NTAPI *proto_NtAllocateVirtualMemory)(HANDLE, PVOID *, ULONG, PULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *proto_NtFreeVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *proto_NtCreateThread)(PHANDLE, ACCESS_MASK , POBJECT_ATTRIBUTES , HANDLE , PCLIENT_ID , PCONTEXT , void * , BOOLEAN);
typedef NTSTATUS (NTAPI *proto_NtQueryVirtualMemory)(HANDLE , PVOID , __int32 , PVOID , ULONG , PULONG );
typedef NTSTATUS (NTAPI *proto_NtTerminateProcess)(HANDLE , ULONG );
typedef NTSTATUS (NTAPI *proto_NtTerminateThread)(HANDLE , ULONG );
typedef NTSTATUS (NTAPI *proto_NtCreateProcessEx)(HANDLE *,ULONG, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE,BOOLEAN);
typedef NTSTATUS (NTAPI *proto_NtDeleteFile)(POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *proto_NtMapViewOfSection)(HANDLE, HANDLE , PVOID *, ULONG , ULONG , PLARGE_INTEGER , PULONG ,SECTION_INHERIT , ULONG , ULONG );
typedef NTSTATUS (NTAPI *proto_NtCreateSection)(PHANDLE, ULONG,POBJECT_ATTRIBUTES,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
typedef NTSTATUS (NTAPI *proto_NtCreateThreadEx)(PHANDLE , ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, BOOLEAN, ULONG, ULONG, ULONG, PVOID);
typedef NTSTATUS (NTAPI *proto_KeFlushSingleTb) (PVOID, ULONG);

typedef ULONG (NTAPI * proto_MiCopyOnWrite)(PVOID, PVOID);
typedef ULONG (NTAPI * proto_MiQueryAddressState)(PVOID, PMMVAD, PEPROCESS, PULONG, PVOID *);
typedef void (NTAPI * proto_KeContextFromKframes)(PVOID, PVOID, PVOID);
typedef PPEB (NTAPI * proto_PsGetProcessPeb)(PEPROCESS Process);
typedef PVOID (NTAPI * proto_MmGetVirtualForPhysical)(PHYSICAL_ADDRESS PhysicalAddress);
typedef NTSTATUS (NTAPI * proto_NtSuspendThread)(HANDLE, PULONG);
typedef void (NTAPI * proto_MiMakePdeExistAndMakeValid)(PVOID, PEPROCESS, ULONG);
typedef NTSTATUS (NTAPI *proto_MmAccessFault)(ULONG_PTR, PVOID, KPROCESSOR_MODE, PVOID);
typedef PMMVAD (NTAPI * proto_MiCheckForConflictingVadExistence)(PEPROCESS, PVOID, PVOID);

typedef VOID (FASTCALL * proto_ExfAcquirePushLockExclusive)(PEX_PUSH_LOCK);
typedef VOID (FASTCALL * proto_ExfReleasePushLockExclusive)(PEX_PUSH_LOCK);

typedef VOID (FASTCALL * proto_ExfAcquirePushLockShared)(PEX_PUSH_LOCK);
typedef VOID (FASTCALL * proto_ExfReleasePushLockShared)(PEX_PUSH_LOCK);


typedef NTSTATUS (NTAPI * proto_NtSetInformationThread)(HANDLE,ULONG,PVOID,ULONG);

//Windows Vista and Windows 7 (32bits) KTRAP_FRAME structure
typedef struct _KTRAP_FRAME
{
	ULONG DbgEbp;
	ULONG DbgEip;
	ULONG DbgArgMark;
	ULONG DbgArgPointer;
	unsigned short TempSegCs;
	UCHAR Logging;
	UCHAR Reserved;
	ULONG TempEsp;
	ULONG Dr0;
	ULONG Dr1;
	ULONG Dr2;
	ULONG Dr3;
	ULONG Dr6;
	ULONG Dr7;
	ULONG SegGs;
	ULONG SegEs;
	ULONG SegDs;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG PreviousPreviousMode;
	void * ExceptionList;
	ULONG SegFs;
	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Ebp;
	ULONG ErrCode;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
	ULONG V86Es;
	ULONG V86Ds;
	ULONG V86Fs;
	ULONG V86Gs;
} KTRAP_FRAME, *PKTRAP_FRAME;

#endif