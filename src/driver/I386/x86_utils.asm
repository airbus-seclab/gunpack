.386
.MODEL flat, stdcall
.code
cr0_disable_write_protect PROC
    push eax
    mov eax, CR0
    and eax, 0FFFEFFFFh
    mov CR0, eax
    pop eax
    ret
cr0_disable_write_protect ENDP

cr0_enable_write_protect PROC
    push eax
    mov eax, CR0
    or eax, NOT 0FFFEFFFFh
    mov CR0, eax
    pop eax
    ret
cr0_enable_write_protect ENDP

tlb_flush PROC
    mov eax, cr3
    mov cr3, eax
    ret
tlb_flush ENDP

END