.data
    SE_DEBUG_NAME db "SeDebugPrivilege", 0
    strNewLine dw 13, 10, 0

.code
enb proc
    sub rsp, 68h

    call GetCurrentProcess
    mov rcx, rax
    mov rdx, 28h
    lea r8, [rsp+10h]
    call OpenProcessToken
    test rax, rax
    jz enb_fail

    xor rcx, rcx
    lea rdx, [SE_DEBUG_NAME]
    lea r8, [rsp+30h]
    call LookupPrivilegeValueA
    test rax, rax
    jz enb_close_handle

    mov dword ptr [rsp+20h], 1
    mov rax, [rsp+30h]
    mov [rsp+28h], rax
    mov dword ptr [rsp+38h], 2

    mov rcx, [rsp+10h]
    xor rdx, rdx
    lea r8, [rsp+20h]
    mov r9, 16
    mov qword ptr [rsp+20h], 0
    mov qword ptr [rsp+28h], 0
    call AdjustTokenPrivileges
    test rax, rax
    jz enb_close_handle

    mov rcx, [rsp+10h]
    call CloseHandle
    mov rax, 1
    add rsp, 68h
    ret

enb_close_handle:
    mov rcx, [rsp+10h]
    call CloseHandle

enb_fail:
    xor rax, rax
    add rsp, 68h
    ret
enb endp
end

// No Usage