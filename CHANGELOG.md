# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-02

### Added
- `ARCHITECTURE.md` — crate dependency graph, module lifecycle, new-module guide, C2 protocol overview
- `From<toml::de::Error>` and `From<toml::ser::Error>` conversions on `RcfError` for ergonomic `?` usage
- `From<reqwest::Error>` conversion on `RcfError` (feature-gated behind `reqwest`)
- `zeroize` dependency — plaintext credential buffer zeroed from memory immediately after Argon2 hashing in `add_credential()`
- Unit tests for `rcf-core`: `Context`, `ModuleOptions`, `AnonymityConfig::validate()`, TOML round-trip (26 tests total)
- Unit tests for `rcf-db`: host CRUD, credential hashing verification, duplicate deduplication, vulnerability save (4 tests, in-memory SQLite)
- Integration tests for `rcf-modules`: registry register/get/search, `Module::check()` lifecycle (5 tests)
- Meterpreter command sandboxing with dangerous command blocklist
- `Context::http_client()` for modules to respect TLS configuration
- Automatic credential hashing (Argon2id + random salt) in database layer
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
- Parallel CIDR subnet scanning (`192.168.1.0/24`) with `--max-targets` cap
- `--dangerous-accept-invalid-certs` flag for lab targets with self-signed certs
- SIGINT/SIGTERM graceful shutdown via `tokio::select!` + `ctrl_c()`
- C2 control port PSK authentication (`AUTH <psk>` handshake)

### Changed
- Split `rcf-core/src/anonymity.rs` (26 KB) into focused sub-modules: `anonymity/{mod,proxy,timing,waf,report,decoy}.rs` — public API unchanged
- Removed 5 `#![allow(...)]` lint suppressions from anonymity module; fixed underlying `collapsible_if` lints
- `config_to_toml` / `config_from_toml` now use `?` operator via new `From` conversions
- Updated credential hashing doc comment to accurately describe Argon2id + `zeroize` behaviour
- C2 control server now always binds to `127.0.0.1` (loopback only) regardless of configured listen address
- CI: replaced `dtolnay/rust-action` with correct `dtolnay/rust-toolchain` action name
- CI: removed `|| true` from `cargo audit` — CVE failures now correctly fail the build

### Fixed
- **SEC-01 (Critical)** — PSK `ct_eq` condition was inverted; unauthenticated connections were accepted and legitimate agents rejected
- **SEC-02 (High)** — Unbounded `read_to_string` on Redis TCP stream; fixed with `take(4MB)` + `timeout(10s)`
- **SEC-03 (High)** — `PRAGMA foreign_keys = ON` never set; FK constraints now enforced on every connection
- **SEC-04 (High)** — Predictable `/tmp/rcf_<ip>.db` path (symlink attack); fixed with `tempfile::Builder` in `~/.rcf/`
- **SEC-05 (High)** — C2 control port had no auth and bound to all interfaces; fixed with loopback-only bind + PSK handshake
- **SEC-06 (High)** — `cargo audit` ran with `|| true`; CVE failures were silently ignored
- **ROB-06 (Medium)** — `delete_host` not atomic; wrapped in transaction to prevent partial deletes
- **CFG-04 (Medium)** — No SIGTERM/SIGINT handler; abrupt shutdown fixed with graceful signal handling
- **CFG-02 (Low)** — Stale `--strict-tls` reference in `SECURITY.md`; updated to `--dangerous-accept-invalid-certs`
- Regex compilation panic in SQL injection scanner
- Metasploit module parsing panic in compatibility layer
- Missing safety documentation on unsafe blocks

### Security
- Addressed all critical and high findings from Phase 1 security audit
- Added `SECURITY.md` for responsible disclosure
- TLS validation now on by default for all HTTP clients
- Added dangerous command blocklist to C2 server
- Switched default credential storage from plaintext to hashed
- Plaintext credential buffer zeroed via `zeroize` after hashing

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

[Unreleased]: https://github.com/pallab-js/r-msf/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/pallab-js/r-msf/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pallab-js/r-msf/releases/tag/v0.1.0
