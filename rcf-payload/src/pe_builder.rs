//! Windows PE payload generator.
//!
//! Builds minimal PE executables from shellcode that can run on Windows.
//! Supports both x86 and x64 architectures.

use crate::generator::Arch;

/// PE file builder — constructs a minimal Windows PE executable.
pub struct PeBuilder;

impl PeBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Build a PE file from shellcode.
    pub fn build(&self, shellcode: &[u8], arch: &Arch, entry_rva: u32) -> Vec<u8> {
        let mut output = Vec::new();

        // Calculate sizes
        let dos_header_size = 64u32;
        let stub_size = 64u32;
        let nt_header_size = match arch {
            Arch::X64 => 240u32, // PE32+ is slightly larger
            Arch::X86 => 240u32,
            Arch::Arm64 => 240u32,
        };
        let _section_header_size = 40u32;

        let file_alignment = 512u32;
        let section_alignment = 4096u32;

        // Section sizes (aligned)
        let code_size = shellcode.len() as u32;
        let code_file_size = align_up(code_size, file_alignment);

        // Section RVAs
        let code_rva = section_alignment;

        // Image size
        let size_of_image = align_up(code_rva + code_size, section_alignment);

        // Entry point RVA
        let entry_point = if entry_rva == 0 {
            code_rva
        } else {
            entry_rva
        };

        // ─── DOS Header ────────────────────────────────────────
        write_dos_header(&mut output);

        // ─── DOS Stub ──────────────────────────────────────────
        write_dos_stub(&mut output);

        // ─── PE Signature ──────────────────────────────────────
        output.extend_from_slice(b"PE\0\0");

        // ─── COFF File Header ──────────────────────────────────
        let machine: u16 = match arch {
            Arch::X64 => 0x8664,   // IMAGE_FILE_MACHINE_AMD64
            Arch::X86 => 0x014c,   // IMAGE_FILE_MACHINE_I386
            Arch::Arm64 => 0xAA64, // IMAGE_FILE_MACHINE_ARM64
        };
        let number_of_sections: u16 = 1;
        let time_date_stamp: u32 = 0x60000000; // Fixed timestamp for reproducibility
        let pointer_to_symbol_table: u32 = 0;
        let number_of_symbols: u32 = 0;
        let size_of_optional_header: u16 = match arch {
            Arch::X64 => 240, // PE32+
            _ => 224,         // PE32
        };
        let characteristics: u16 = 0x0102; // EXECUTABLE_IMAGE | 32BIT_MACHINE

        output.extend_from_slice(&machine.to_le_bytes());
        output.extend_from_slice(&number_of_sections.to_le_bytes());
        output.extend_from_slice(&time_date_stamp.to_le_bytes());
        output.extend_from_slice(&pointer_to_symbol_table.to_le_bytes());
        output.extend_from_slice(&number_of_symbols.to_le_bytes());
        output.extend_from_slice(&size_of_optional_header.to_le_bytes());
        output.extend_from_slice(&characteristics.to_le_bytes());

        // ─── Optional Header ───────────────────────────────────
        let magic: u16 = match arch {
            Arch::X64 => 0x20b, // PE32+
            _ => 0x10b,         // PE32
        };
        let major_linker_version: u8 = 14;
        let minor_linker_version: u8 = 0;
        let size_of_code: u32 = code_file_size;
        let size_of_initialized_data: u32 = 0;
        let size_of_uninitialized_data: u32 = 0;
        let address_of_entry_point: u32 = entry_point;
        let base_of_code: u32 = code_rva;
        let base_of_data: u32 = 0; // PE32+ doesn't have this field
        let image_base: u64 = 0x00400000;
        let section_alignment_val: u32 = section_alignment;
        let file_alignment_val: u32 = file_alignment;
        let major_operating_system_version: u16 = 6;
        let minor_operating_system_version: u16 = 0;
        let major_image_version: u16 = 0;
        let minor_image_version: u16 = 1;
        let major_subsystem_version: u16 = 6;
        let minor_subsystem_version: u16 = 0;
        let win32_version_value: u32 = 0;
        let size_of_image_val: u32 = size_of_image;
        let size_of_headers: u32 = dos_header_size + stub_size + 4 + nt_header_size;
        let check_sum: u32 = 0;
        let subsystem: u16 = 2; // IMAGE_SUBSYSTEM_WINDOWS_GUI
        let dll_characteristics: u16 = 0x8160; // DYNAMIC_BASE | NX_COMPAT | HIGH_ENTROPY_VA | TERMINAL_SERVER_AWARE
        let size_of_stack_reserve: u64 = 0x100000;
        let size_of_stack_commit: u64 = 0x1000;
        let size_of_heap_reserve: u64 = 0x100000;
        let size_of_heap_commit: u64 = 0x1000;
        let loader_flags: u32 = 0;
        let number_of_rva_and_sizes: u32 = 16;

        output.extend_from_slice(&magic.to_le_bytes());
        output.push(major_linker_version);
        output.push(minor_linker_version);
        output.extend_from_slice(&size_of_code.to_le_bytes());
        output.extend_from_slice(&size_of_initialized_data.to_le_bytes());
        output.extend_from_slice(&size_of_uninitialized_data.to_le_bytes());
        output.extend_from_slice(&address_of_entry_point.to_le_bytes());
        output.extend_from_slice(&base_of_code.to_le_bytes());

        if arch != &Arch::X64 {
            output.extend_from_slice(&base_of_data.to_le_bytes());
        }

        // PE32+ uses 64-bit image base
        if arch == &Arch::X64 || arch == &Arch::Arm64 {
            output.extend_from_slice(&image_base.to_le_bytes());
        } else {
            output.extend_from_slice(&(image_base as u32).to_le_bytes());
        }

        output.extend_from_slice(&section_alignment_val.to_le_bytes());
        output.extend_from_slice(&file_alignment_val.to_le_bytes());
        output.extend_from_slice(&major_operating_system_version.to_le_bytes());
        output.extend_from_slice(&minor_operating_system_version.to_le_bytes());
        output.extend_from_slice(&major_image_version.to_le_bytes());
        output.extend_from_slice(&minor_image_version.to_le_bytes());
        output.extend_from_slice(&major_subsystem_version.to_le_bytes());
        output.extend_from_slice(&minor_subsystem_version.to_le_bytes());
        output.extend_from_slice(&win32_version_value.to_le_bytes());
        output.extend_from_slice(&size_of_image_val.to_le_bytes());
        output.extend_from_slice(&size_of_headers.to_le_bytes());
        output.extend_from_slice(&check_sum.to_le_bytes());
        output.extend_from_slice(&subsystem.to_le_bytes());
        output.extend_from_slice(&dll_characteristics.to_le_bytes());

        if arch == &Arch::X64 || arch == &Arch::Arm64 {
            output.extend_from_slice(&size_of_stack_reserve.to_le_bytes());
            output.extend_from_slice(&size_of_stack_commit.to_le_bytes());
            output.extend_from_slice(&size_of_heap_reserve.to_le_bytes());
            output.extend_from_slice(&size_of_heap_commit.to_le_bytes());
        } else {
            output.extend_from_slice(&(size_of_stack_reserve as u32).to_le_bytes());
            output.extend_from_slice(&(size_of_stack_commit as u32).to_le_bytes());
            output.extend_from_slice(&(size_of_heap_reserve as u32).to_le_bytes());
            output.extend_from_slice(&(size_of_heap_commit as u32).to_le_bytes());
        }

        output.extend_from_slice(&loader_flags.to_le_bytes());
        output.extend_from_slice(&number_of_rva_and_sizes.to_le_bytes());

        // ─── Data Directories (16 entries) ─────────────────────
        // All zeros for a minimal PE (no imports, exports, etc.)
        for _ in 0..16 {
            output.extend_from_slice(&0u32.to_le_bytes()); // RVA
            output.extend_from_slice(&0u32.to_le_bytes()); // Size
        }

        // ─── Section Header ────────────────────────────────────
        let section_name = b".code\0\0\0";
        output.extend_from_slice(section_name);
        output.extend_from_slice(&code_size.to_le_bytes()); // VirtualSize
        output.extend_from_slice(&code_rva.to_le_bytes());   // VirtualAddress
        output.extend_from_slice(&code_file_size.to_le_bytes()); // SizeOfRawData
        output.extend_from_slice(&dos_header_size.to_le_bytes()); // PointerToRawData
        output.extend_from_slice(&0u32.to_le_bytes()); // PointerToRelocations
        output.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
        output.extend_from_slice(&0u16.to_le_bytes()); // NumberOfRelocations
        output.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
        output.extend_from_slice(&0x60000020u32.to_le_bytes()); // Characteristics: CODE | EXECUTE | READ

        // ─── Pad to section offset ─────────────────────────────
        while output.len() < dos_header_size as usize {
            output.push(0);
        }

        // ─── Code Section ──────────────────────────────────────
        // Pad to file alignment
        let current_size = output.len() as u32;
        let padding_needed = dos_header_size.saturating_sub(current_size);
        output.resize(output.len() + padding_needed as usize, 0);

        // Write shellcode
        output.extend_from_slice(shellcode);

        // Pad to file alignment
        let current_code_size = (output.len() as u32) - dos_header_size;
        let code_padding = code_file_size.saturating_sub(current_code_size);
        output.resize(output.len() + code_padding as usize, 0);

        output
    }
}

impl Default for PeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Write the DOS MZ header (64 bytes).
fn write_dos_header(output: &mut Vec<u8>) {
    // Ensure we start at 0
    assert!(output.is_empty());

    // e_magic "MZ"
    output.push(b'M');
    output.push(b'Z');
    // e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc (6 words)
    for _ in 0..12 {
        output.push(0x90);
    }
    // e_ss, e_sp (2 words)
    output.extend_from_slice(&0x0000u16.to_le_bytes());
    output.extend_from_slice(&0x0000u16.to_le_bytes());
    // e_csum, e_ip (2 words)
    output.extend_from_slice(&0x0000u16.to_le_bytes());
    output.extend_from_slice(&0x0000u16.to_le_bytes());
    // e_cs, e_lfarlc (2 words)
    output.extend_from_slice(&0x0000u16.to_le_bytes());
    output.extend_from_slice(&0x0040u16.to_le_bytes());
    // e_ovno (1 word)
    output.extend_from_slice(&0x0000u16.to_le_bytes());
    // e_res (4 words = 8 bytes)
    for _ in 0..8 {
        output.push(0);
    }
    // e_oemid, e_oeminfo (2 words = 4 bytes)
    for _ in 0..4 {
        output.push(0);
    }
    // e_res2 (10 words = 20 bytes)
    for _ in 0..20 {
        output.push(0);
    }
    // e_lfanew (offset to PE header = 128)
    let pe_offset: u32 = 128;
    output.extend_from_slice(&pe_offset.to_le_bytes());

    assert_eq!(output.len(), 64, "DOS header must be 64 bytes");
}

/// Write the DOS stub ("This program cannot be run in DOS mode").
fn write_dos_stub(output: &mut Vec<u8>) {
    let stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21";
    output.extend_from_slice(stub);
    let msg = b"This program cannot be run in DOS mode.\r\r\n$";
    output.extend_from_slice(msg);
    // Pad to 64 bytes
    while output.len() < 128 {
        output.push(0);
    }
}

/// Align a value up to the next multiple of alignment.
fn align_up(value: u32, alignment: u32) -> u32 {
    if value == 0 {
        return alignment;
    }
    ((value - 1) / alignment + 1) * alignment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_builder_x64() {
        let builder = PeBuilder::new();
        let shellcode = vec![0x48, 0x31, 0xc0, 0xc3]; // xor rax, rax; ret
        let pe = builder.build(&shellcode, &Arch::X64, 0);

        // Check MZ header
        assert_eq!(&pe[0..2], b"MZ");

        // Check PE signature at offset from e_lfanew
        let e_lfanew = u32::from_le_bytes([pe[60], pe[61], pe[62], pe[63]]);
        assert_eq!(&pe[e_lfanew as usize..e_lfanew as usize + 4], b"PE\0\0");

        // Check machine type (AMD64)
        let machine = u16::from_le_bytes([pe[e_lfanew as usize + 4], pe[e_lfanew as usize + 5]]);
        assert_eq!(machine, 0x8664);

        // Check shellcode is present somewhere in the file
        let found = pe.windows(4).any(|w| w == shellcode.as_slice());
        assert!(found, "shellcode not found in PE file");
    }

    #[test]
    fn test_pe_builder_x86() {
        let builder = PeBuilder::new();
        let shellcode = vec![0x31, 0xc0, 0xc3]; // xor eax, eax; ret
        let pe = builder.build(&shellcode, &Arch::X86, 0);

        // Check MZ header
        assert_eq!(&pe[0..2], b"MZ");

        // Check machine type (I386)
        let e_lfanew = u32::from_le_bytes([pe[60], pe[61], pe[62], pe[63]]);
        let machine = u16::from_le_bytes([pe[e_lfanew as usize + 4], pe[e_lfanew as usize + 5]]);
        assert_eq!(machine, 0x014c);

        // Check shellcode is present somewhere in the file
        let found = pe.windows(3).any(|w| w == shellcode.as_slice());
        assert!(found, "shellcode not found in PE file");
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 512), 512);
        assert_eq!(align_up(1, 512), 512);
        assert_eq!(align_up(512, 512), 512);
        assert_eq!(align_up(513, 512), 1024);
        assert_eq!(align_up(100, 4096), 4096);
    }
}
