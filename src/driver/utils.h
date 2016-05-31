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

#ifndef UTILS_H
#define UTILS_H

#define JMP_FAR 0
#define CALL	1

#define KERNEL_MODE		0
#define USER_MODE		1

void * FindSignature(unsigned char * Start, unsigned int max_size, unsigned char * Signature, unsigned int SignatureSize);
void * FindSignatureWithHoles(unsigned char * Start, unsigned int max_size, unsigned char * Signature, unsigned int SignatureSize);
void * FindSignatureInProcessModule(PEPROCESS ProcessObj, HANDLE hProcess, unsigned char * StartAddress, ULONG_PTR Size, unsigned char * Signature, ULONG SignatureSize);
void cr0_disable_write_protect();
void cr0_enable_write_protect();
unsigned char * ComputeBranchAddress(unsigned char * instr_offset);
int PatchBranch(int BranchType, unsigned char * offset, unsigned char * BranchTarget);
unsigned char GetPreviousMode();
void SetPreviousMode(unsigned char flag);
void SetKernelMode();
void SetUserMode();
void * get_cr3();
PVOID GetVadRoot( PEPROCESS process );
HANDLE GetProcessIdByhandle(HANDLE hProcess);
PVOID GetCurrentKThread();
int IsPidTracked(unsigned int Pid);
void DisplayPageFilePTE(LARGE_INTEGER l);
void SuspendTrackedProcesses();
void TerminateProcesses();
void SuspendCurrentProcess();
int GetNextTrackedProcess(HANDLE * pPid);
int UnTrackProcess(HANDLE Pid);
void tlb_flush();
void SuspendTrackedProcess();
void ResumeAndUntrackProcesses();

#ifdef _M_X64
PVOID get_syscall_func(ULONG SyscallNumber);
void put_syscall_func(ULONG SyscallNumber, PVOID Func);
void kernel_trampoline();
void syscall_dispatcher();
void jmp_stub();
void hook_syscall_filter();
void jmp_stub_2();
void HookInKiDispatchException2();
#endif

#endif
