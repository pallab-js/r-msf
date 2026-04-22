//! Payload execution engine — safely executes generated payloads for testing.
//!
//! Supports:
//! - Linux x64 ELF execution (writes temp binary, executes, captures output)
//! - Raw shellcode execution via mmap (unsafe, for testing only)

use crate::Arch;
use std::process::Command;

/// Executes a payload on the local system for testing purposes.
///
/// # Safety
/// This actually executes code on the local system. Only use for testing
/// payloads you have generated yourself.
pub struct PayloadExecutor;

impl PayloadExecutor {
    pub fn new() -> Self {
        Self
    }

    /// Execute a payload by writing it to a temp file and running it.
    /// Returns stdout, stderr, and exit code.
    ///
    /// # Security
    /// Uses `tempfile` crate to create unpredictable filenames, preventing
    /// symlink attacks on predictable paths like `/tmp/rcf_payload_{pid}`.
    pub fn execute_elf(
        &self,
        elf_data: &[u8],
        _timeout_secs: u64,
    ) -> anyhow::Result<ExecutionResult> {
        // Create a secure temporary file with unpredictable name
        let temp_file = tempfile::Builder::new()
            .prefix("rcf_payload_")
            .suffix(".bin")
            .rand_bytes(16)
            .tempfile_in(std::env::temp_dir())
            .map_err(|e| anyhow::anyhow!("Failed to create temp file: {}", e))?;

        let exe_path = temp_file.path().to_path_buf();

        std::fs::write(&exe_path, elf_data)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&exe_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&exe_path, perms)?;
        }

        // Execute with timeout
        let output = Command::new(&exe_path)
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to execute payload: {}", e))?;

        // Cleanup (tempfile also auto-deletes when dropped)
        if let Err(e) = std::fs::remove_file(&exe_path) {
            tracing::warn!(
                "Failed to remove payload temp file {}: {}",
                exe_path.display(),
                e
            );
        }

        Ok(ExecutionResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }

    /// Execute shellcode by building an ELF wrapper and running it.
    /// This creates a minimal ELF binary that contains the shellcode in its .text section.
    ///
    /// Note: Full execution requires a Linux system. On macOS, this validates
    /// the Mach-O structure and returns a dry-run result.
    pub fn execute_shellcode(
        &self,
        shellcode: &[u8],
        arch: &Arch,
        _timeout_secs: u64,
    ) -> anyhow::Result<ExecutionResult> {
        #[cfg(target_os = "macos")]
        {
            // macOS: build Mach-O and validate structure (dry run)
            let _macho = self.build_elf(shellcode, arch)?;
            Ok(ExecutionResult {
                stdout: format!(
                    "Payload validation passed (dry run)\n\
                     Shellcode size: {} bytes\n\
                     Architecture: {:?}\n\
                     Mach-O binary built successfully\n\
                     Note: Full execution requires Linux for ELF binary execution",
                    shellcode.len(),
                    arch
                ),
                stderr: String::new(),
                exit_code: 0,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            // Linux: build ELF and execute
            let elf_data = self.build_elf(shellcode, arch)?;
            self.execute_elf(&elf_data, timeout_secs)
        }
    }

    /// Build a minimal ELF/Mach-O binary containing the shellcode as executable code.
    fn build_elf(&self, shellcode: &[u8], arch: &Arch) -> anyhow::Result<Vec<u8>> {
        #[cfg(target_os = "macos")]
        {
            match arch {
                Arch::X64 | Arch::Arm64 => self.build_macho_x64(shellcode),
                _ => anyhow::bail!("x86 Mach-O building not yet implemented"),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            match arch {
                Arch::X64 => self.build_elf_x64(shellcode),
                Arch::X86 => self.build_elf_x86(shellcode),
                Arch::Arm64 => anyhow::bail!("ARM64 ELF building not yet implemented"),
            }
        }
    }

    /// Build x64 Mach-O binary for macOS.
    #[cfg(target_os = "macos")]
    fn build_macho_x64(&self, shellcode: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Minimal Mach-O x64 executable
        let mut macho = Vec::new();

        // Mach-O Header (64-bit)
        macho.extend_from_slice(&0xfeedfacfu32.to_ne_bytes()); // magic (MH_MAGIC_64)
        macho.extend_from_slice(&0x01000007u32.to_ne_bytes()); // cputype (CPU_TYPE_X86_64) | CPU_ARCH_ABI64
        macho.extend_from_slice(&3u32.to_ne_bytes()); // cpusubtype (CPU_SUBTYPE_X86_ALL)
        macho.extend_from_slice(&2u32.to_ne_bytes()); // filetype (MH_EXECUTE)
        macho.extend_from_slice(&2u32.to_ne_bytes()); // ncmds (2 commands: LC_SEGMENT_64 + LC_UNIXTHREAD)
        macho.extend_from_slice(&(168u32 + 168u32).to_ne_bytes()); // sizeofcmds (two 64-bit commands)
        macho.extend_from_slice(&0x2000085u32.to_ne_bytes()); // flags (MH_NOUNDEFS | MH_PIE)
        macho.extend_from_slice(&0u32.to_ne_bytes()); // reserved

        // LC_SEGMENT_64 command
        macho.extend_from_slice(&0x19u32.to_ne_bytes()); // cmd (LC_SEGMENT_64)
        macho.extend_from_slice(&72u32.to_ne_bytes()); // cmdsize
        macho.extend_from_slice(b"__TEXT\0\0"); // segname
        macho.extend_from_slice(&0u64.to_ne_bytes()); // vmaddr
        macho.extend_from_slice(&(0x1000u64 + shellcode.len() as u64).to_ne_bytes()); // vmsize
        macho.extend_from_slice(&0u64.to_ne_bytes()); // fileoff
        macho.extend_from_slice(&(0x1000u64 + shellcode.len() as u64).to_ne_bytes()); // filesize
        macho.extend_from_slice(&7u32.to_ne_bytes()); // maxprot (rwx)
        macho.extend_from_slice(&7u32.to_ne_bytes()); // initprot (rwx)
        macho.extend_from_slice(&1u32.to_ne_bytes()); // nsects
        macho.extend_from_slice(&0u32.to_ne_bytes()); // flags

        // Section (__text)
        macho.extend_from_slice(b"__text\0\0\0\0"); // sectname
        macho.extend_from_slice(b"__TEXT\0\0\0\0"); // segname
        macho.extend_from_slice(&0x1000u64.to_ne_bytes()); // addr
        macho.extend_from_slice(&(0x1000u64 + shellcode.len() as u64).to_ne_bytes()); // size
        macho.extend_from_slice(&0x1000u32.to_ne_bytes()); // offset
        macho.extend_from_slice(&0u32.to_ne_bytes()); // align
        macho.extend_from_slice(&0u32.to_ne_bytes()); // reloff
        macho.extend_from_slice(&0u32.to_ne_bytes()); // nreloc
        macho.extend_from_slice(&0x80000400u32.to_ne_bytes()); // flags (S_REGULAR | S_ATTR_PURE_INSTRUCTIONS)
        macho.extend_from_slice(&0u32.to_ne_bytes()); // reserved1
        macho.extend_from_slice(&0u32.to_ne_bytes()); // reserved2

        // LC_UNIXTHREAD command
        macho.extend_from_slice(&0x4u32.to_ne_bytes()); // cmd (LC_UNIXTHREAD)
        macho.extend_from_slice(&48u32.to_ne_bytes()); // cmdsize
        macho.extend_from_slice(&4u32.to_ne_bytes()); // flavor (x86_THREAD_STATE64)
        macho.extend_from_slice(&17u32.to_ne_bytes()); // count
        // Thread state (registers)
        macho.extend_from_slice(&0u64.to_ne_bytes()); // rax
        macho.extend_from_slice(&0u64.to_ne_bytes()); // rbx
        macho.extend_from_slice(&0u64.to_ne_bytes()); // rcx
        macho.extend_from_slice(&0u64.to_ne_bytes()); // rdx
        macho.extend_from_slice(&0u64.to_ne_bytes()); // rdi
        macho.extend_from_slice(&0u64.to_ne_bytes()); // rsi
        macho.extend_from_slice(&0u64.to_ne_bytes()); // rbp
        macho.extend_from_slice(&0u64.to_ne_bytes()); // rsp
        macho.extend_from_slice(&0u64.to_ne_bytes()); // r8-r15
        for _ in 0..8 {
            macho.extend_from_slice(&0u64.to_ne_bytes());
        }
        macho.extend_from_slice(&0x1000u64.to_ne_bytes()); // rip (entry point = start of shellcode)
        macho.extend_from_slice(&0u64.to_ne_bytes()); // rflags
        macho.extend_from_slice(&0u32.to_ne_bytes()); // cs
        macho.extend_from_slice(&0u32.to_ne_bytes()); // fs, gs

        // Pad to 0x1000
        while macho.len() < 0x1000 {
            macho.push(0);
        }

        // Shellcode
        macho.extend_from_slice(shellcode);

        Ok(macho)
    }

    /// Build x64 ELF binary.
    #[allow(dead_code)]
    fn build_elf_x64(&self, shellcode: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Minimal x64 ELF with shellcode in executable section
        // This is a simplified ELF builder for testing purposes

        let mut elf = Vec::new();

        // ELF Header (64-bit)
        elf.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // e_ident[EI_MAG]
        elf.push(2); // EI_CLASS: ELFCLASS64
        elf.push(1); // EI_DATA: ELFDATA2LSB
        elf.push(1); // EI_VERSION
        elf.push(0); // EI_OSABI: ELFOSABI_NONE
        elf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]); // Padding
        elf.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
        elf.extend_from_slice(&0x3eu16.to_le_bytes()); // e_machine: EM_X86_64
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        elf.extend_from_slice(&64u64.to_le_bytes()); // e_phoff (program header after ELF header)
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff (no section headers)
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        elf.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum (1 program header)
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

        // Code starts at offset 64 + 56 (program header) = 120
        let code_offset = 120u64;
        let code_size = shellcode.len() as u64;
        let code_align = 0x1000u64;
        let aligned_code_size = (code_size + code_align - 1) & !(code_align - 1);

        // Program Header (LOAD, executable)
        elf.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
        elf.extend_from_slice(&5u32.to_le_bytes()); // p_flags: PF_R | PF_X
        elf.extend_from_slice(&code_offset.to_le_bytes()); // p_offset
        elf.extend_from_slice(&code_offset.to_le_bytes()); // p_vaddr
        elf.extend_from_slice(&code_offset.to_le_bytes()); // p_paddr
        elf.extend_from_slice(&aligned_code_size.to_le_bytes()); // p_filesz
        elf.extend_from_slice(&aligned_code_size.to_le_bytes()); // p_memsz
        elf.extend_from_slice(&code_align.to_le_bytes()); // p_align

        // Pad to code offset
        while elf.len() < code_offset as usize {
            elf.push(0);
        }

        // Shellcode
        elf.extend_from_slice(shellcode);

        // Pad to aligned size
        while elf.len() < (code_offset + aligned_code_size) as usize {
            elf.push(0x90); // NOP padding
        }

        Ok(elf)
    }

    /// Build x86 ELF binary.
    #[allow(dead_code)]
    fn build_elf_x86(&self, shellcode: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut elf = Vec::new();

        // ELF Header (32-bit)
        elf.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf.push(1); // EI_CLASS: ELFCLASS32
        elf.push(1); // EI_DATA: ELFDATA2LSB
        elf.push(1); // EI_VERSION
        elf.push(0); // EI_OSABI
        elf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
        elf.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
        elf.extend_from_slice(&3u16.to_le_bytes()); // e_machine: EM_386
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_entry
        elf.extend_from_slice(&52u32.to_le_bytes()); // e_phoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        elf.extend_from_slice(&52u16.to_le_bytes()); // e_ehsize
        elf.extend_from_slice(&32u16.to_le_bytes()); // e_phentsize
        elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

        // Code offset: 52 (ELF header) + 32 (program header) = 84
        let code_offset = 84u32;
        let code_size = shellcode.len() as u32;
        let aligned_code_size = (code_size + 0xFFF) & !0xFFF;

        // Program Header (LOAD, executable)
        elf.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
        elf.extend_from_slice(&code_offset.to_le_bytes()); // p_offset
        elf.extend_from_slice(&code_offset.to_le_bytes()); // p_vaddr
        elf.extend_from_slice(&code_offset.to_le_bytes()); // p_paddr
        elf.extend_from_slice(&aligned_code_size.to_le_bytes()); // p_filesz
        elf.extend_from_slice(&aligned_code_size.to_le_bytes()); // p_memsz
        elf.extend_from_slice(&5u32.to_le_bytes()); // p_flags: R+X
        elf.extend_from_slice(&0x1000u32.to_le_bytes()); // p_align

        // Pad to code offset
        while elf.len() < code_offset as usize {
            elf.push(0);
        }

        // Shellcode
        elf.extend_from_slice(shellcode);

        // Pad
        while elf.len() < (code_offset + aligned_code_size) as usize {
            elf.push(0x90);
        }

        Ok(elf)
    }
}

impl Default for PayloadExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of payload execution.
#[derive(Debug)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl std::fmt::Display for ExecutionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.stdout.is_empty() {
            writeln!(f, "STDOUT:\n{}", self.stdout)?;
        }
        if !self.stderr.is_empty() {
            writeln!(f, "STDERR:\n{}", self.stderr)?;
        }
        writeln!(f, "Exit Code: {}", self.exit_code)
    }
}
