#ifndef UTILS_H
#define UTILS_H

#define JMP_FAR 0
#define CALL	1

#define KERNEL_MODE		0
#define USER_MODE		1

void * FindSignature(unsigned char * Start, unsigned int max_size, unsigned char * Signature, unsigned int SignatureSize);
void * FindSignatureWithHoles(unsigned char * Start, unsigned int max_size, unsigned char * Signature, unsigned int SignatureSize);
void * FindSignatureInProcessModule(PEPROCESS ProcessObj, HANDLE hProcess, unsigned char * StartAddress, ULONG Size, unsigned char * Signature, ULONG SignatureSize);
void disable_cr0();
void enable_cr0();
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

#endif
