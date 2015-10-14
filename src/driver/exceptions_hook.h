#ifndef EXCEPTIONS_HOOK_H
#define EXCEPTIONS_HOOK_H

#include "win_kernl.h"

int HookExceptionDispatcher(PVOID KernelImageBase, ULONG KernelImageSize);
int UnHookExceptionDispatcher();
int HookKiTrap0E(PVOID KernelImageBase, ULONG KernelImageSize);
int UnHookKiTrap0E();

#endif