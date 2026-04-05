//! Payload output formatting — raw, hex, C, Python, base64, and binary formats.

use crate::generator::PayloadConfig;
use base64::Engine;

/// Output format for generated payloads.
#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    /// Raw bytes (binary file)
    Raw,
    /// Hexadecimal string
    Hex,
    /// C byte array
    C,
    /// Python byte string
    Python,
    /// Base64 encoded
    Base64,
    /// PowerShell byte array
    PowerShell,
    /// Ruby byte array
    Ruby,
    /// JavaScript hex
    JavaScript,
    /// Windows PE executable
    Pe,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "raw" | "bin" | "binary" => Ok(OutputFormat::Raw),
            "hex" | "h" => Ok(OutputFormat::Hex),
            "c" | "char" | "char_array" => Ok(OutputFormat::C),
            "python" | "py" => Ok(OutputFormat::Python),
            "base64" | "b64" => Ok(OutputFormat::Base64),
            "powershell" | "ps1" | "ps" => Ok(OutputFormat::PowerShell),
            "ruby" | "rb" => Ok(OutputFormat::Ruby),
            "javascript" | "js" => Ok(OutputFormat::JavaScript),
            "pe" | "exe" | "windows" => Ok(OutputFormat::Pe),
            other => Err(format!("Unknown output format: {}", other)),
        }
    }
}

/// Final payload output with formatted representation.
#[derive(Debug, Clone)]
pub struct PayloadOutput {
    /// Raw shellcode bytes
    pub shellcode: Vec<u8>,
    /// Formatted output string
    pub formatted: String,
    /// Format used
    pub format: OutputFormat,
    /// Payload size in bytes
    pub size: usize,
    /// Whether the payload is null-free
    pub null_free: bool,
    /// Payload metadata
    pub metadata: String,
}

impl PayloadOutput {
    pub fn new(
        shellcode: &[u8],
        format: &OutputFormat,
        config: &PayloadConfig,
    ) -> Self {
        let formatted = format_shellcode(shellcode, format, &config.arch);
        let null_free = !shellcode.contains(&0x00);
        let metadata = format!(
            "Type: {}\nPlatform: {}/{}\nLHOST: {}\nLPORT: {}\nEncoder: {}\nPolymorphic: {}",
            config.payload_type,
            config.platform,
            config.arch,
            config.lhost,
            config.lport,
            config.encoder.as_ref().map(|e| format!("{:?}", e)).unwrap_or_else(|| "none".to_string()),
            config.polymorphic,
        );

        Self {
            shellcode: shellcode.to_vec(),
            formatted,
            format: format.clone(),
            size: shellcode.len(),
            null_free,
            metadata,
        }
    }

    /// Print the formatted payload with metadata header.
    pub fn display(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Payload Size: {} bytes\n", self.size));
        output.push_str(&format!("Null-Free: {}\n", self.null_free));
        output.push_str(&format!("Format: {:?}\n\n", self.format));
        output.push_str(&self.metadata);
        output.push_str("\n\n");
        output.push_str(&self.formatted);
        output.push('\n');
        output
    }
}

/// Format shellcode into the specified output format.
pub fn format_shellcode(shellcode: &[u8], format: &OutputFormat, arch: &crate::Arch) -> String {
    match format {
        OutputFormat::Raw => String::from_utf8_lossy(shellcode).to_string(),
        OutputFormat::Hex => format_hex(shellcode),
        OutputFormat::C => format_c(shellcode),
        OutputFormat::Python => format_python(shellcode),
        OutputFormat::Base64 => format_base64(shellcode),
        OutputFormat::PowerShell => format_powershell(shellcode),
        OutputFormat::Ruby => format_ruby(shellcode),
        OutputFormat::JavaScript => format_javascript(shellcode),
        OutputFormat::Pe => {
            let builder = crate::pe_builder::PeBuilder::new();
            let pe_data = builder.build(shellcode, arch, 0);
            format!("// Windows PE executable ({} bytes)\n// Save as .exe and run on Windows\n// Raw PE size: {} bytes\n", pe_data.len(), shellcode.len())
        }
    }
}

/// Hex format: 4831c0b03b...
fn format_hex(shellcode: &[u8]) -> String {
    shellcode.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}

/// C format: unsigned char buf[] = "\x48\x31\xc0...";
fn format_c(shellcode: &[u8]) -> String {
    let mut output = String::from("unsigned char shellcode[] =\n");
    for (i, chunk) in shellcode.chunks(16).enumerate() {
        if i > 0 {
            output.push('\n');
        }
        output.push_str("  \"");
        for &b in chunk {
            output.push_str(&format!("\\x{:02x}", b));
        }
        output.push('"');
    }
    output.push_str(";\n");
    output
}

/// Python format: shellcode = b"\x48\x31\xc0..."
fn format_python(shellcode: &[u8]) -> String {
    let mut output = String::from("shellcode = b\"");
    for (i, chunk) in shellcode.chunks(16).enumerate() {
        if i > 0 {
            output.push_str("           b\"");
        }
        for &b in chunk {
            output.push_str(&format!("\\x{:02x}", b));
        }
        output.push_str("\"\n");
    }
    output
}

/// Base64 format
fn format_base64(shellcode: &[u8]) -> String {
    let engine = base64::engine::general_purpose::STANDARD;
    engine.encode(shellcode)
}

/// PowerShell format: $shellcode = @(0x48,0x31,0xc0,...)
fn format_powershell(shellcode: &[u8]) -> String {
    let hex_values: Vec<_> = shellcode.iter().map(|b| format!("0x{:02x}", b)).collect();
    let lines: Vec<_> = hex_values
        .chunks(16)
        .map(|chunk| chunk.join(","))
        .collect();
    format!("$shellcode = @(\n{}\n)", lines.join(",\n"))
}

/// Ruby format: shellcode = "\x48\x31\xc0..."
fn format_ruby(shellcode: &[u8]) -> String {
    let mut output = String::from("shellcode = \"");
    for (i, chunk) in shellcode.chunks(16).enumerate() {
        if i > 0 {
            output.push_str("           \"");
            output.push_str(" + \"");
        }
        for &b in chunk {
            output.push_str(&format!("\\x{:02x}", b));
        }
        output.push_str("\"\n");
    }
    output
}

/// JavaScript hex format
fn format_javascript(shellcode: &[u8]) -> String {
    let hex_values: Vec<_> = shellcode.iter().map(|b| format!("{:02x}", b)).collect();
    format!("var shellcode = \"{}\";", hex_values.join(""))
}
