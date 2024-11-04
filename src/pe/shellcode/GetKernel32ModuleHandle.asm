; https://dennisbabkin.com/blog/?t=how-to-implement-getprocaddress-in-shellcode
.code

GetImageBase PROC
    mov    rax, gs:[60h]       ; PEB
    mov    rax, [rax + 10h]    ; ImageBase
    ret
GetImageBase ENDP

GetKernel32ModuleHandle PROC
    mov    rax, gs:[60h]       ; PEB
    mov    rax, [rax + 18h]    ; Ldr
    mov    rax, [rax + 20h]    ; InMemoryOrderModuleList
    mov    rax, [rax]          ; Skip 'this' module and get to ntdll
    mov    rax, [rax]          ; Skip ntdll module and get to kernel32
    mov    rax, [rax + 20h]    ; DllBase for kernel32 --- size_t offset = offsetof(LDR_DATA_TABLE_ENTRY, DllBase) - sizeof(LIST_ENTRY);
    ret
GetKernel32ModuleHandle ENDP

jump_to_entry_point PROC
    push    rcx
    ret
jump_to_entry_point ENDP

END
