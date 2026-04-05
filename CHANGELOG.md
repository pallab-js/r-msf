# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Meterpreter command sandboxing with dangerous command blocklist
- `Context::http_client()` for modules to respect `--strict-tls` flag
- Automatic SHA-256 credential hashing in database layer
- `tempfile` crate integration for unpredictable payload filenames
- HTML escaping for all report generation fields
- Path validation for file write operations (payloads, reports, exports)
- VNC authentication bypass detection (real RFB protocol)
- MongoDB unauthorized access detection (real wire protocol)
- Elasticsearch RCE via CVE-2014-3120 and CVE-2015-1427
- Docker API unauthorized access exploitation
- WinRM/PSRemoting login and command execution
- Memcached enumeration via stats command
- NFS share enumeration via portmapper
- BlueKeep (CVE-2019-0708) real RDP protocol implementation
- EternalBlue (MS17-010) real SMBv1 protocol implementation
- Parallel CIDR subnet scanning (`192.168.1.0/24`)
- `--strict-tls` global CLI flag

### Fixed
- Regex compilation panic in SQL injection scanner
- Metasploit module parsing panic in compatibility layer
- Predictable payload temp file paths (symlink attack prevention)
- Missing safety documentation on unsafe blocks

### Security
- Addressed all 6 critical findings from security audit
- Added `SECURITY.md` for responsible disclosure
- Added dangerous command blocklist to C2 server
- Switched default credential storage from plaintext to hashed

## [0.1.0] - 2024-04-05

### Added
- Core architecture with `Module` trait system
- Interactive REPL console with tab completion
- Global context with shared options
- Async TCP Connect scanner
- Protocol handlers (HTTP, SSH, SMB fingerprinting)
- Payload generator with shellcode templates
- XOR encoder with dynamic multi-byte keys
- Polymorphic engine (register substitution, junk blocks)
- NOP sled generator
- Output formats: C, Python, PowerShell, Ruby, JavaScript, hex, base64, raw
- SQLite database layer with Diesel ORM
- Export to JSON, CSV, XML
- C2 server with session management
- Meterpreter-style session commands
- Log analyzer with IOC detection
- Feature flags for minimal builds
- CI/CD pipeline with GitHub Actions
- Cross-compilation support (Linux, macOS, Windows)
- Makefile build automation
- Professional HTML report generation
- Automated attack chain execution
- Lab-focused exploit modules (56 total)
- Command injection, SQLi, XSS, path traversal exploits
- Log4Shell, ProxyShell exploit implementations
- Redis, MySQL, PostgreSQL, Tomcat, Jenkins, WordPress exploits
- Brute force scanners (SSH, FTP, HTTP)
- Kerberos/AD modules (Kerberoasting, AS-REP Roasting)
- Post-exploitation enumeration (Linux, Windows)

[Unreleased]: https://github.com/rcf/rcf/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rcf/rcf/releases/tag/v0.1.0
