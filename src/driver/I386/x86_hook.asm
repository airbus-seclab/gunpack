.386
.MODEL flat, stdcall
.code

EXTERN KiDispatchException_end:DWORD
EXTERN do_exception_filter_ptr:DWORD
EXTERN KiDispatchException_continue:DWORD
EXTERN KeContextFromKframes:DWORD

HookInKiDispatchException PROC
    push    dword ptr [ebp+18h] ; FirstChance
    push    dword ptr [ebp+14h] ; PreviousMode
    push    dword ptr [ebp+10h] ; PKTRAP_FRAME
    push    dword ptr [ebp+0Ch] ; pKexp
    push    dword ptr [ebp+8] ; PEXCEPTION_RECORD
    call    dword ptr [do_exception_filter_ptr]
    test    eax,eax
    ;if eax == 0 the exception was not catched by our driver
    ;therefore exception handling flow must continue
    je      Unhandled_exception
    ;If we handled the exception, we jump directly to the end of the exception handler.
    ;The kernel will then restore userland thread context using the KTRAP_FRAME structure
    ;we have modified
    jmp     dword ptr[KiDispatchException_end]
    
Unhandled_exception:
    ;Parameters of KeContextFromKframes are already on the stack at the beginning of HookInKiDispatchException.
    ;No need to push them twice.
    call    dword ptr[KeContextFromKframes]
    jmp     dword ptr[KiDispatchException_continue]

HookInKiDispatchException ENDP

END