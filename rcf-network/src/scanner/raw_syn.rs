//! Raw socket SYN scanner — requires root/admin privileges.
//!
//! Uses raw sockets to send TCP SYN packets and analyze responses:
//! - SYN-ACK → port open
//! - RST → port closed
//! - No response (timeout) → port filtered
//!
//! Platform support:
//! - Linux: Full support via AF_PACKET
//! - macOS: Limited (requires BPF, root)
//! - Windows: Requires WinPcap/Npcap
//!
//! Advantages over TCP Connect scan:
//! - Stealthier (never completes TCP handshake)
//! - Faster (no full connection setup overhead)
//! - Can detect filtered ports (dropped packets)
//!
//! Requirements:
//! - Root/Administrator privileges
//! - Raw socket access

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::scanner::common::{PortRange, ScanResult, PortState};

/// TCP flags
mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

/// A parsed TCP response packet.
#[derive(Debug, Clone)]
struct TcpResponse {
    src_ip: Ipv4Addr,
    src_port: u16,
    flags: u8,
    seq: u32,
    ack_seq: u32,
    ttl: u8,
    window_size: u16,
}

impl TcpResponse {
    fn is_syn_ack(&self) -> bool {
        (self.flags & (tcp_flags::SYN | tcp_flags::ACK)) == (tcp_flags::SYN | tcp_flags::ACK)
    }

    fn is_rst(&self) -> bool {
        (self.flags & tcp_flags::RST) != 0
    }
}

/// Raw socket SYN scanner.
pub struct RawSynScanner {
    /// Whether we have root access
    pub privileged: bool,
    /// Source port for sending SYNs (to match responses)
    source_port: u16,
    /// Expected sequence number base
    seq_base: u32,
}

impl RawSynScanner {
    pub fn new() -> Self {
        Self {
            privileged: Self::check_privileges(),
            source_port: 31337,
            seq_base: 0xDEADBEEF,
        }
    }

    /// Check if we have privileges for raw sockets.
    pub fn check_privileges() -> bool {
        // On Unix, raw sockets typically require CAP_NET_RAW or root (uid 0)
        // This is a simplified check — real implementation would try to create a raw socket
        #[cfg(unix)]
        {
            let uid = unsafe { libc::geteuid() };
            uid == 0
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Check if raw socket scanning is available.
    pub fn is_available() -> bool {
        Self::check_privileges()
    }

    /// Scan a single host using raw SYN packets.
    pub async fn scan(
        &self,
        target_ip: Ipv4Addr,
        ports: &PortRange,
        timeout: Duration,
        concurrency: usize,
    ) -> Vec<ScanResult> {
        if !self.privileged {
            warn!("Raw SYN scanner requires root privileges. Falling back to connect scan.");
            return Vec::new();
        }

        let port_list = ports.to_vec();
        let total = port_list.len();

        debug!(
            target = %target_ip,
            ports = total,
            "Starting raw SYN scan"
        );

        // Shared state for responses
        let responses: Arc<Mutex<HashMap<u16, TcpResponse>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Spawn response listener
        let listener_responses = Arc::clone(&responses);
        let listener_handle = tokio::spawn(async move {
            Self::listen_for_responses(target_ip, listener_responses, timeout).await
        });

        // Send SYN packets
        let semaphore = tokio::sync::Semaphore::new(concurrency);
        let mut send_handles = Vec::with_capacity(total);

        for port in port_list {
            let permit = semaphore.acquire().await
                .map_err(|e| anyhow::anyhow!("Semaphore poisoned: {}", e))?;
            let src_ip = target_ip;
            let resp = Arc::clone(&responses);
            let timeout_dur = timeout;

            let handle = tokio::spawn(async move {
                let result = Self::send_syn_and_check(src_ip, port, &resp, timeout_dur).await;
                drop(permit);
                result
            });
            send_handles.push(handle);
        }

        // Collect results
        let mut results = Vec::with_capacity(total);
        for handle in send_handles {
            if let Ok(result) = handle.await {
                results.push(result);
            }
        }

        // Wait for listener to finish
        let _ = listener_handle.await;

        results.sort_by_key(|r| r.port);
        results
    }

    /// Send a single SYN packet and wait for response.
    async fn send_syn_and_check(
        target_ip: Ipv4Addr,
        port: u16,
        responses: &Arc<Mutex<HashMap<u16, TcpResponse>>>,
        timeout: Duration,
    ) -> ScanResult {
        let start = Instant::now();

        // Build and send SYN packet
        if let Err(e) = Self::send_syn_packet(target_ip, port) {
            debug!("Failed to send SYN to {}:{}: {}", target_ip, port, e);
            return ScanResult::filtered(port);
        }

        // Wait for response
        tokio::time::sleep(Duration::from_millis(50)).await;

        let elapsed = start.elapsed().as_secs_f64() * 1000.0;

        // Check if we got a response
        let resp = {
            let map = responses.lock().await;
            map.get(&port).cloned()
        };

        match resp {
            Some(r) if r.is_syn_ack() => {
                debug!("{}:{} OPEN (SYN-ACK, {:.1}ms)", target_ip, port, elapsed);
                let mut result = ScanResult::open(port, port_to_service(port));
                result.rtt_ms = Some(elapsed);
                // OS detection hints from TTL and window size
                if let Some(os_hint) = guess_os_from_tcp(r.ttl, r.window_size) {
                    result.version = Some(os_hint);
                }
                result
            }
            Some(r) if r.is_rst() => {
                debug!("{}:{} CLOSED (RST)", target_ip, port);
                ScanResult::closed(port)
            }
            _ => {
                debug!("{}:{} FILTERED (no response)", target_ip, port);
                ScanResult::filtered(port)
            }
        }
    }

    /// Build and send a TCP SYN packet.
    fn send_syn_packet(target_ip: Ipv4Addr, port: u16) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;

            // Create raw socket
            // Safety: Requires CAP_NET_RAW (root) to create raw sockets.
            // This is a fundamental requirement for SYN scanning and cannot be avoided.
            #[allow(clippy::missing_safety_doc)]
            let socket = unsafe {
                socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::RAW,
                    Some(socket2::Protocol::from(libc::IPPROTO_TCP)),
                )?
            };

            // Set IP_HDRINCL so we provide our own IP header
            let fd = socket.as_raw_fd();
            let incl: libc::c_int = 1;
            // Safety: fd is a valid file descriptor from socket.as_raw_fd(),
            // incl is a valid c_int, and IP_HDRINCL is a valid socket option.
            // This call is required to send custom IP headers for SYN scanning.
            #[allow(clippy::missing_safety_doc)]
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    &incl as *const _ as *const _,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }

            // Build IP header
            let mut packet = Vec::with_capacity(40);

            // IP header (20 bytes)
            let ip_version_ihl: u8 = 0x45; // IPv4, 5 words (20 bytes)
            packet.push(ip_version_ihl);
            packet.push(0x00); // DSCP/ECN
            let total_len: u16 = 40; // IP header (20) + TCP header (20)
            packet.extend_from_slice(&total_len.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes()); // Identification
            packet.extend_from_slice(&0x4000u16.to_be_bytes()); // Flags: Don't Fragment
            packet.push(64); // TTL
            packet.push(libc::IPPROTO_TCP as u8); // Protocol
            packet.extend_from_slice(&0u16.to_be_bytes()); // Header checksum (filled later)
            packet.extend_from_slice(&[0, 0, 0, 0]); // Source IP (0.0.0.0 = any)
            packet.extend_from_slice(&target_ip.octets()); // Dest IP

            // TCP header (20 bytes)
            packet.extend_from_slice(&Self::source_port.to_be_bytes()); // Source port
            packet.extend_from_slice(&port.to_be_bytes()); // Dest port
            packet.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // Sequence number
            packet.extend_from_slice(&0u32.to_be_bytes()); // Ack number
            let data_offset: u8 = 0x50; // 5 words (20 bytes), no options
            packet.push(data_offset);
            packet.push(tcp_flags::SYN); // Flags: SYN
            packet.extend_from_slice(&65535u16.to_be_bytes()); // Window size
            packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
            packet.extend_from_slice(&0u16.to_be_bytes()); // Urgent pointer

            // Calculate IP header checksum
            let checksum = Self::ip_checksum(&packet[0..20]);
            packet[10] = (checksum >> 8) as u8;
            packet[11] = checksum as u8;

            // Send packet
            let dest_addr: SocketAddr = SocketAddr::new(IpAddr::V4(target_ip), 0);
            let dest_sockaddr = socket2::SockAddr::from(dest_addr);
            let _ = socket.send_to(&packet, &dest_sockaddr)?;

            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            // On macOS/Windows, raw socket implementation differs
            // For now, return an error indicating platform limitation
            Err(anyhow::anyhow!(
                "Raw SYN scanning is only supported on Linux. Use TCP Connect scanner instead."
            ))
        }
    }

    /// Listen for incoming TCP responses.
    async fn listen_for_responses(
        target_ip: Ipv4Addr,
        responses: Arc<Mutex<HashMap<u16, TcpResponse>>>,
        timeout: Duration,
    ) {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;

            // Create raw socket to receive TCP packets
            let socket = match socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::RAW,
                Some(socket2::Protocol::from(libc::IPPROTO_TCP)),
            ) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to create raw socket for listening: {}", e);
                    return;
                }
            };

            let fd = socket.as_raw_fd();
            let timeout_ms = timeout.as_millis() as libc::c_int;
            unsafe {
                let mut tv = libc::timeval {
                    tv_sec: (timeout_ms / 1000) as _,
                    tv_usec: ((timeout_ms % 1000) * 1000) as _,
                };
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const _ as *const _,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }

            let mut buf = [0u8; 1500]; // MTU-sized buffer

            loop {
                let n = match socket.recv(&mut buf) {
                    Ok(n) => n,
                    Err(_) => break, // Timeout or error
                };

                if n < 40 {
                    continue; // Too small for IP + TCP headers
                }

                // Parse IP header
                let ihl = (buf[0] & 0x0F) as usize * 4;
                if buf[9] as i32 != libc::IPPROTO_TCP || ihl < 20 {
                    continue;
                }

                let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                if src_ip != target_ip {
                    continue;
                }

                // Parse TCP header
                let tcp_start = ihl;
                if tcp_start + 20 > n {
                    continue;
                }

                let src_port = u16::from_be_bytes([buf[tcp_start], buf[tcp_start + 1]]);
                let dst_port = u16::from_be_bytes([buf[tcp_start + 2], buf[tcp_start + 3]]);
                let flags = buf[tcp_start + 13];
                let seq = u32::from_be_bytes([
                    buf[tcp_start + 4],
                    buf[tcp_start + 5],
                    buf[tcp_start + 6],
                    buf[tcp_start + 7],
                ]);
                let ack_seq = u32::from_be_bytes([
                    buf[tcp_start + 8],
                    buf[tcp_start + 9],
                    buf[tcp_start + 10],
                    buf[tcp_start + 11],
                ]);
                let window = u16::from_be_bytes([buf[tcp_start + 14], buf[tcp_start + 15]]);
                let ttl = buf[8]; // IP TTL

                let response = TcpResponse {
                    src_ip,
                    src_port: dst_port, // From target's perspective, our source port
                    flags,
                    seq,
                    ack_seq,
                    ttl,
                    window_size: window,
                };

                // Only store responses for ports we scanned
                if response.src_port == Self::source_port {
                    let mut map = responses.lock().await;
                    map.insert(dst_port, response);
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (target_ip, responses, timeout);
            // Platform not supported for raw socket listening
        }
    }

    /// Calculate IP header checksum.
    fn ip_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in header.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += (chunk[0] as u32) << 8;
            }
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }

    /// Get the source port used for SYN packets.
    pub fn source_port(&self) -> u16 {
        self.source_port
    }
}

impl Default for RawSynScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Guess OS from TCP TTL and window size (passive OS fingerprinting).
fn guess_os_from_tcp(ttl: u8, window_size: u16) -> Option<String> {
    match (ttl, window_size) {
        (64, 65535) => Some("Linux (recent)".to_string()),
        (64, 5840) => Some("Linux (older)".to_string()),
        (128, 65535) => Some("Windows 10/11".to_string()),
        (128, 8192) => Some("Windows 7/8".to_string()),
        (64, 65535) => Some("FreeBSD/macOS".to_string()),
        (255, _) => Some("OpenBSD/FreeBSD".to_string()),
        (32, _) => Some("Windows 9x/ME".to_string()),
        _ if ttl <= 64 => Some(format!("Linux/Unix (TTL={})", ttl)),
        _ if ttl <= 128 => Some(format!("Windows (TTL={})", ttl)),
        _ => Some(format!("Unknown (TTL={}, Win={})", ttl, window_size)),
    }
}

/// Map common port numbers to service names.
fn port_to_service(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("domain"),
        80 => Some("http"),
        110 => Some("pop3"),
        111 => Some("rpcbind"),
        135 => Some("msrpc"),
        139 => Some("netbios-ssn"),
        143 => Some("imap"),
        443 => Some("https"),
        445 => Some("microsoft-ds"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("ms-sql-s"),
        1521 => Some("oracle"),
        1723 => Some("pptp"),
        2049 => Some("nfs"),
        3306 => Some("mysql"),
        3389 => Some("ms-wbt-server"),
        5432 => Some("postgresql"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        8080 => Some("http-proxy"),
        8443 => Some("https-alt"),
        9200 => Some("elasticsearch"),
        27017 => Some("mongodb"),
        _ => None,
    }
}
