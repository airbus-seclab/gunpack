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

#ifndef MEMORY_STATE_H
#define MEMORY_STATE_H

#include "win_kernl.h"

#define INVALID_PROTECT_VALUE 0xFFFF
#define MEMORY_STATE_SIZE 0x80000

#define EXECUTABLE 1
#define WRITABLE 0

#define PAE_PTE_BASE	0xC0000000
#define PAE_PDE_BASE	0xC0600000
#define PDE_MASK		0x3FF8
#define PTE_MASK		0x7FFFF8

#define PTE_VIRTUAL_FROM_ADDRESS(p) (PAE_PTE_BASE + ((p >> 9) & PTE_MASK))
#define PDE_VIRTUAL_FROM_ADDRESS(p) ( PAE_PDE_BASE + ((p >> 0x12) & PDE_MASK))

typedef union _PTE
{
	struct
	{
		unsigned __int64 present:1;
		unsigned __int64 rw:1;
		unsigned __int64 lvl:1;
		unsigned __int64 pwt:1;
		unsigned __int64 pcd:1;		
		unsigned __int64 a:1;	
		unsigned __int64 d:1;
		unsigned __int64 ps:1;	
		unsigned __int64 g:1;
		unsigned __int64 copyonwrite:1;		
		unsigned __int64 prototype:1;
		unsigned __int64 reserved:1;		
		unsigned __int64 address:51;
		unsigned __int64 xd:1;
	}pte;
	
	LARGE_INTEGER raw;
} PTE;

typedef union _PAE_LINEAR_ADDRESS
{
	struct 
	{
	  unsigned __int32 offset:12;
	  unsigned __int32 table:9;
	  unsigned __int32 directory:9;
	  unsigned __int32 directory_pointer:2;
	} l;
	  
	unsigned __int32 raw;
} PAE_LINEAR_ADDRESS ;

typedef union _PDE
{
	struct 
	{
		unsigned __int64 present:1;
		unsigned __int64 rw:1;
		unsigned __int64 lvl:1;
		unsigned __int64 pwt:1;
		unsigned __int64 pcd:1;		
		unsigned __int64 a:1;	
		unsigned __int64 d:1;
		unsigned __int64 ps:1;	
		unsigned __int64 g:1;
		unsigned __int64 ignored:3;
		unsigned __int64 pat:1;
		unsigned __int64 reserved:8;
		unsigned __int64 address:42;
		unsigned __int64 xd:1;
	} large_page;
	
	struct 
	{
		unsigned __int64 present:1;
		unsigned __int64 rw:1;
		unsigned __int64 lvl:1;
		unsigned __int64 pwt:1;
		unsigned __int64 pcd:1;		
		unsigned __int64 a:1;	
		unsigned __int64 d:1;
		unsigned __int64 ps:1;
		unsigned __int64 address:56;
	} pte_info;	
	
	LARGE_INTEGER raw;
} PDE;

typedef struct _MMPTE_SOFTWARE {
    ULONG Valid : 1;
    ULONG PageFileLow : 4;
    ULONG Protection : 5;
    ULONG Prototype : 1;
    ULONG Transition : 1;
    ULONG PageFileHigh : 20;
} MMPTE_SOFTWARE, *PMMPTE_SOFTWARE;

typedef struct
{
	unsigned __int64 present:1;
	unsigned __int64 reserved1:2;
	unsigned __int64 pwt:1;
	unsigned __int64 pcd:1;
	unsigned __int64 reserved2:4;
	unsigned __int64 ignored:3;
	unsigned __int64 pd_address:48;
} PDPTE;

void InitMemoryStateBuffer();
void CleanupMemoryStateBuffer();
void SetMemoryProtectionOnRange(__int32 BaseAddress , __int32 RegionSize, __int32 Protect);
unsigned int GetMemoryProtection(ULONG Page);
void SnapshotMemoryRange(HANDLE hProcess,unsigned char * StartAddress, ULONG Size);
void SetExecutableMemory(HANDLE hProcess, unsigned char * StartAddress, ULONG_PTR Size);
int IsWritable(ULONG Protect);
int IsExecutable(ULONG Protect);
NTSTATUS ChangeMemoryProtection(void * TargetPageAddress, ULONG TargetPageSize, ULONG NewProtection);
int SetMemoryProtectionPae(ULONG Page, unsigned int Writable, unsigned int Executable);
void SetMemoryExecute(PEPROCESS process_obj, __int32 BaseAddress , __int32 RegionSize);
void ParseProcessVad(PMMVAD Vad);
void SetMemoryRegionAccess(__int32 BaseAddress , __int32 RegionSize, __int32 Writable, __int32 Executable);
int IsMemoryTracked(ULONG Page);
PMMVAD LocateVadForPage(PMMVAD pVad, ULONG PageVpn);
int ShouldItFault(ULONG_PTR FaultStatus,  ULONG PageRights);
void ZeroPtes();
ULONG GetVadMemoryProtect(ULONG_PTR BaseAddress);
int GetMemoryProtectionPae(ULONG Page, unsigned int * pWritable, unsigned int * pExecutable);
int SetMemoryProtectionPae2(ULONG Page, unsigned int Writable, unsigned int Executable);
int ProtectExecutablePTEs(ULONG_PTR Base, SIZE_T Size);
int IsTrackedPage(ULONG_PTR PageAddress);
void SetTrackedPage(ULONG_PTR PageAddress);
void SetUntrackedPage(ULONG_PTR PageAddress);
void ClearTrackedPages();
#endif