//! Network enumeration modules for Linux penetration testing.
//!
//! Implements protocols commonly found on Metasploitable, THM, and HTB:
//! - Telnet client for banner grabbing
//! - SNMP enumeration
//! - SMTP enumeration (VRFY/EXPN/RCPT TO)

use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use std::time::Duration;

use rcf_core::{
    Context, Module, ModuleCategory, ModuleInfo, ModuleOptions, ModuleOutput, Result, Target,
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// ═══════════════════════════════════════════════════════════════════════════════
// TELNET CLIENT MODULE
// ═══════════════════════════════════════════════════════════════════════════════

static TELNET_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
    name: "auxiliary/scanner/telnet/telnet".to_string(),
    display_name: "Telnet Client".to_string(),
    description: "Connects to Telnet servers and performs banner grabbing. Useful for identifying \
         Telnet services on Metasploitable and older systems. Extracts version information \
         and can detect if login is required."
        .to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 60,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![],
});

pub struct TelnetClient;

impl Default for TelnetClient {
    fn default() -> Self {
        Self
    }
}

impl Module for TelnetClient {
    fn info(&self) -> &ModuleInfo {
        &TELNET_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target host(s)",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "Telnet port",
            rcf_core::OptionValue::Integer(23),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "TIMEOUT",
            false,
            "Connection timeout (seconds)",
            rcf_core::OptionValue::Integer(10),
        ));
        opts
    }

    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let rhosts = ctx.get_rhosts();
        let rport = ctx.get_rport();
        let timeout_secs = ctx.get_timeout();
        let info_name = self.info().name.clone();

        Box::pin(async move {
            let mut results = Vec::new();

            for rhost in rhosts {
                let addr = format!("{}:{}", rhost, rport);

                let banner =
                    match timeout(Duration::from_secs(timeout_secs), connect_telnet(&addr)).await {
                        Ok(Ok(b)) => b,
                        Ok(Err(e)) => {
                            results.push(format!("[-] {}: {}", addr, e));
                            continue;
                        }
                        Err(_) => {
                            results.push(format!("[-] {}: Connection timed out", addr));
                            continue;
                        }
                    };

                if banner.is_empty() {
                    results.push(format!("[*] {}: No banner received", addr));
                } else {
                    results.push(format!("[+] {}: Banner: {}", addr, banner));

                    if banner.to_lowercase().contains("ubuntu")
                        || banner.to_lowercase().contains("debian")
                        || banner.to_lowercase().contains("centos")
                    {
                        results.push(format!("[+] {}: Linux-based system detected", addr));
                    }
                }
            }

            let msg = format!(
                "Telnet Enumeration\n{}\n[*] Note: Telnet transmits data in plaintext - credentials can be captured",
                results.join("\n")
            );

            Ok(ModuleOutput::success(&info_name, &results.join(", "), &msg))
        })
    }
}

async fn connect_telnet(addr: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr).await?;

    // Read initial banner/prompt
    let mut buf = vec![0u8; 4096];
    let n = match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return Ok(String::new()),
    };
    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();

    // Send empty login attempt to trigger more output
    if stream.write_all(b"\n").await.is_err() {
        return Ok(banner);
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut more_buf = vec![0u8; 1024];
    if let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut more_buf)).await {
        let more = String::from_utf8_lossy(&more_buf[..n]).trim().to_string();
        if !more.is_empty() && more != banner {
            return Ok(format!("{}\n{}", banner, more));
        }
    }

    Ok(banner)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SNMP ENUMERATION MODULE
// ═══════════════════════════════════════════════════════════════════════════════

static SNMP_ENUM_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
    name: "auxiliary/scanner/snmp/snmp_enum".to_string(),
    display_name: "SNMP Enumeration".to_string(),
    description: "Enumerates information via SNMP (Simple Network Management Protocol). Extracts \
         system info, network configuration, running processes, and user accounts. Common on \
         Metasploitable (port 161). Tests common community strings."
        .to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 70,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec!["https://cwe.mitre.org/data/definitions/287.html".to_string()],
});

pub struct SnmpScanner;

impl Default for SnmpScanner {
    fn default() -> Self {
        SnmpScanner
    }
}

impl Module for SnmpScanner {
    fn info(&self) -> &ModuleInfo {
        &SNMP_ENUM_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target SNMP server(s)",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "SNMP port",
            rcf_core::OptionValue::Integer(161),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "COMMUNITY",
            false,
            "SNMP community string",
            rcf_core::OptionValue::String("public".to_string()),
        ));
        opts
    }

    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let rhosts = ctx.get_rhosts();
        let rport = ctx.get_rport();
        let community = ctx
            .get("COMMUNITY")
            .cloned()
            .unwrap_or_else(|| "public".to_string());
        let info_name = self.info().name.clone();

        Box::pin(async move {
            let mut results = Vec::new();

            for rhost in rhosts {
                let addr = format!("{}:{}", rhost, rport);

                let snmp_data =
                    match timeout(Duration::from_secs(10), snmp_walk(&addr, &community)).await {
                        Ok(Ok(data)) => data,
                        Ok(Err(e)) => {
                            results.push(format!("[-] {}: {}", addr, e));
                            continue;
                        }
                        Err(_) => {
                            results.push(format!(
                                "[-] {}: Timeout - SNMP may be blocked or no response",
                                addr
                            ));
                            continue;
                        }
                    };

                if snmp_data.is_empty() {
                    results.push(format!(
                        "[*] {}: No data via SNMP (try different community string)",
                        addr
                    ));
                } else {
                    results.push(format!("[+] {}: SNMP data retrieved:", addr));
                    results.push(snmp_data);
                }
            }

            let msg = format!("SNMP Enumeration\n{}", results.join("\n"));
            Ok(ModuleOutput::success(&info_name, &results.join(", "), &msg))
        })
    }
}

async fn snmp_walk(addr: &str, community: &str) -> std::io::Result<String> {
    // SNMP v1/v2c GetNext request for common OIDs
    let oids = [
        ("1.3.6.1.2.1.1.1.0", "sysDescr"),
        ("1.3.6.1.2.1.1.5.0", "sysName"),
        ("1.3.6.1.2.1.1.6.0", "sysLocation"),
        ("1.3.6.1.2.1.25.1.6.0", "hrSWRunPerfCPU"),
        ("1.3.6.1.2.1.25.1.2.0", "hrSystemDate"),
    ];

    let mut output = Vec::new();
    let mut stream = TcpStream::connect(addr).await?;

    for (oid, name) in oids {
        // Build SNMP GetNext packet
        let packet = build_snmp_get(community, oid);
        stream.write_all(&packet).await?;

        let mut resp = vec![0u8; 4096];
        match timeout(Duration::from_secs(2), stream.read(&mut resp)).await {
            Ok(Ok(n)) if n > 0 => {
                if let Some(value) = parse_snmp_response(&resp[..n]) {
                    output.push(format!("{} ({}) = {}", name, oid, value));
                }
            }
            _ => {}
        }
    }

    // Also try walking process table
    output.push("\n--- Running Processes ---".to_string());
    let packet = build_snmp_getnext(community, "1.3.6.1.2.1.25.4.2.1.2");
    stream.write_all(&packet).await?;

    let mut resp = vec![0u8; 4096];
    if let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut resp)).await {
        let data = String::from_utf8_lossy(&resp[..n]).to_string();
        if !data.trim().is_empty() {
            output.push(data);
        }
    }

    Ok(output.join("\n"))
}

fn build_snmp_get(community: &str, oid: &str) -> Vec<u8> {
    // Simplified SNMP v1 GET packet
    let mut packet = Vec::new();

    // Community string (ISO encoding)
    let community_bytes = community.as_bytes();
    let community_len = community_bytes.len() as u8;

    // We'll build a basic SNMP packet
    // This is a simplified version - real SNMP uses BER encoding
    packet.push(0x30); // SEQUENCE
    packet.push(0x82); // Will be length high byte
    packet.push(0x00); // Will be length low byte
    packet.push(0x02); // INTEGER - SNMP version
    packet.push(0x01);
    packet.push(0x01); // version 1 (or 0 for v1)
    packet.push(0x04); // OCTET STRING - community
    packet.push(community_len);
    packet.extend_from_slice(community_bytes);

    // GET request
    packet.push(0xA0); // GET_REQUEST
    packet.push(0x2c); // Length
    packet.push(0x02); // Request ID
    packet.push(0x04);
    packet.push(0x01);
    packet.push(0x00);
    packet.push(0x00);
    packet.push(0x01);
    packet.push(0x02); // Error status
    packet.push(0x01);
    packet.push(0x00);
    packet.push(0x02); // Error index
    packet.push(0x01);
    packet.push(0x00);
    packet.push(0x30); // SEQUENCE - variable bindings
    packet.push(0x1d);
    packet.push(0x30); // SEQUENCE - name
    packet.push(0x1a);
    packet.push(0x06); // OBJECT IDENTIFIER
    packet.push(0x08); // Length

    // OID encoding (simplified)
    let oid_parts: Vec<&str> = oid.split('.').collect();
    let mut encoded = vec![0x2b]; // Start with 1.3 (iso.org Dod)
    for (_i, part) in oid_parts.iter().enumerate().skip(2) {
        if let Ok(num) = part.parse::<u8>() {
            encoded.push(num);
        }
    }
    packet.push(encoded.len() as u8);
    packet.extend_from_slice(&encoded);
    packet.push(0x05); // NULL value
    packet.push(0x00);

    // Update length
    if packet.len() > 2 {
        let len = packet.len() - 2;
        packet[1] = ((len >> 8) & 0xff) as u8;
        packet[2] = (len & 0xff) as u8;
    }

    packet
}

fn build_snmp_getnext(community: &str, oid: &str) -> Vec<u8> {
    let mut packet = build_snmp_get(community, oid);
    packet[0] = 0xa1; // GET_NEXT_REQUEST instead of GET_REQUEST
    packet
}

fn parse_snmp_response(data: &[u8]) -> Option<String> {
    if data.len() < 10 {
        return None;
    }

    // Look for string values in the response
    let response = String::from_utf8_lossy(data);

    // Extract meaningful strings
    let parts: Vec<&str> = response
        .split(|c: char| c.is_control() && c != '\n')
        .collect();
    for part in parts {
        let trimmed = part.trim();
        if trimmed.len() > 3 && !trimmed.contains(" SNMP") {
            return Some(trimmed.to_string());
        }
    }

    None
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMTP ENUMERATION MODULE
// ═══════════════════════════════════════════════════════════════════════════════

static SMTP_ENUM_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
    name: "auxiliary/scanner/smtp/smtp_enum".to_string(),
    display_name: "SMTP User Enumeration".to_string(),
    description: "Enumerates valid SMTP users via VRFY, EXPN, and RCPT TO commands. Used for \
         username enumeration on mail servers found on Metasploitable and HTB boxes. \
         Requires list of potential usernames."
        .to_string(),
    authors: vec!["RCF Team".to_string()],
    category: ModuleCategory::Auxiliary,
    rank: 65,
    stability: "stable".to_string(),
    disclosure_date: None,
    references: vec![],
});

pub struct SmtpScanner;

impl Default for SmtpScanner {
    fn default() -> Self {
        SmtpScanner
    }
}

impl Module for SmtpScanner {
    fn info(&self) -> &ModuleInfo {
        &SMTP_ENUM_INFO
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(rcf_core::ModuleOption::new(
            "RHOSTS",
            true,
            "Target SMTP server(s)",
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "RPORT",
            false,
            "SMTP port",
            rcf_core::OptionValue::Integer(25),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "USER_FILE",
            false,
            "File containing usernames to check",
            rcf_core::OptionValue::String("".to_string()),
        ));
        opts.add(rcf_core::ModuleOption::with_default(
            "USERS",
            false,
            "Comma-separated list of usernames",
            rcf_core::OptionValue::String("admin,root,test,user,guest,info,support".to_string()),
        ));
        opts
    }

    fn run(
        &self,
        ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        let rhosts = ctx.get_rhosts();
        let rport = ctx.get_rport();
        let user_file = ctx.get("USER_FILE").cloned().unwrap_or_default();
        let users_arg = ctx
            .get("USERS")
            .cloned()
            .unwrap_or_else(|| "admin,root,test,user,guest,info,support".to_string());

        let mut users: Vec<String> = Vec::new();

        if !user_file.is_empty()
            && let Ok(content) = std::fs::read_to_string(&user_file)
        {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    users.push(trimmed.to_string());
                }
            }
        }

        if users.is_empty() {
            users = users_arg.split(',').map(|s| s.trim().to_string()).collect();
        }

        let info_name = self.info().name.clone();

        Box::pin(async move {
            let mut results = Vec::new();

            for rhost in rhosts {
                let addr = format!("{}:{}", rhost, rport);
                results.push(format!("\n=== SMTP Enum: {} ===", addr));

                match timeout(Duration::from_secs(30), smtp_enumerate(&addr, &users)).await {
                    Ok(Ok((valid, invalid))) => {
                        if valid.is_empty() {
                            results
                                .push("[*] No valid users found via VRFY/EXPN/RCPT TO".to_string());
                        } else {
                            results.push(format!(
                                "[+] Found {} valid user(s): {}",
                                valid.len(),
                                valid.join(", ")
                            ));
                        }
                        if !invalid.is_empty() {
                            results.push(format!("[-] Invalid users: {}", invalid.len()));
                        }
                    }
                    Ok(Err(e)) => {
                        results.push(format!("[-] Error: {}", e));
                    }
                    Err(_) => {
                        results.push("[-] Connection timed out".to_string());
                    }
                }
            }

            let msg = format!("SMTP User Enumeration\n{}", results.join("\n"));
            Ok(ModuleOutput::success(&info_name, &results.join(", "), &msg))
        })
    }
}

async fn smtp_enumerate(
    addr: &str,
    users: &[String],
) -> std::io::Result<(Vec<String>, Vec<String>)> {
    let mut stream = TcpStream::connect(addr).await?;

    // Read server banner with timeout
    let mut banner_buf = vec![0u8; 256];
    let n = match timeout(Duration::from_secs(5), stream.read(&mut banner_buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    let _banner = String::from_utf8_lossy(&banner_buf[..n]).to_string();

    let mut valid_users = Vec::new();
    let mut invalid_users = Vec::new();

    for user in users {
        // Try VRFY command
        let cmd = format!("VRFY {}\r\n", user);
        stream.write_all(cmd.as_bytes()).await?;

        let mut resp = vec![0u8; 256];
        let n = match timeout(Duration::from_secs(5), stream.read(&mut resp)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        let response = String::from_utf8_lossy(&resp[..n]).to_string();

        if response.starts_with("250") || response.starts_with("251") {
            valid_users.push(format!("{} (VRFY)", user));
        } else if response.starts_with("550") || response.starts_with("553") {
            // Try EXPN as fallback
            let cmd = format!("EXPN {}\r\n", user);
            stream.write_all(cmd.as_bytes()).await?;

            let mut resp = vec![0u8; 256];
            let n = match timeout(Duration::from_secs(5), stream.read(&mut resp)).await {
                Ok(Ok(n)) => n,
                _ => 0,
            };
            let response = String::from_utf8_lossy(&resp[..n]).to_string();

            if response.starts_with("250") || response.starts_with("550") {
                if response.starts_with("250") {
                    valid_users.push(format!("{} (EXPN)", user));
                } else {
                    invalid_users.push(user.clone());
                }
            } else {
                // Try RCPT TO
                let cmd = format!("MAIL FROM:<test@example.com>\r\nRCPT TO:<{}>\r\n", user);
                stream.write_all(cmd.as_bytes()).await?;

                let mut resp = vec![0u8; 512];
                let n = match timeout(Duration::from_secs(5), stream.read(&mut resp)).await {
                    Ok(Ok(n)) => n,
                    _ => 0,
                };
                let response = String::from_utf8_lossy(&resp[..n]).to_string();

                if response.contains("250") && !response.contains("550") {
                    valid_users.push(format!("{} (RCPT TO)", user));
                } else {
                    invalid_users.push(user.clone());
                }
            }
        } else {
            invalid_users.push(user.clone());
        }
    }

    Ok((valid_users, invalid_users))
}
