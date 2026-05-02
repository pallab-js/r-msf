# Rust Cybersecurity Framework (RCF) v0.2.0

[![CI](https://github.com/pallab-js/r-msf/actions/workflows/ci.yml/badge.svg)](https://github.com/pallab-js/r-msf/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/version-0.2.0-green.svg)](CHANGELOG.md)

> **Fast. Memory-Safe. Secure by Default.**

**RCF (Rust Cybersecurity Framework)** is a lightweight, high-performance penetration testing framework written entirely in Rust. Purpose-built for speed and reliability in Linux security assessments, RCF provides 60+ pre-built modules for network scanning, web exploitation, and post-exploitation.

## ⚡ v0.2.0 Highlights

- **Secure by Default** — TLS validation enabled for all modules; secure credential hashing with Argon2id.
- **Improved Evasion** — Centralized HTTP client builder with User-Agent rotation and proxy support.
- **C2 Hardening** — Shell metacharacter filtering and sandboxed command execution.
- **Suppaftp Integration** — Replaced unmaintained FTP engine with modern, async `suppaftp` for reliable scanning.
- **Stability Fixes** — Resolved critical PSK auth inversion and race conditions in session handling.

## 🚀 Quick Start

```bash
# Build release binary
cargo build --release -p rcf-cli

# Start interactive console
./target/release/rcf

# Scan a target (CIDR supported)
rcf scan -t 10.10.10.0/24 --ports common

# Run automated attack chain + report
rcf auto -t 10.129.1.1 -o report.html
```

## 🏗 Architecture

```
rcf/
├── rcf-core/       # Core types, Context, Evasion, TLS security
├── rcf-cli/        # Entry point, automation logic, report templates
├── rcf-console/    # Interactive TUI/REPL with tab completion
├── rcf-modules/    # Registry and dynamic module loader
├── rcf-labs/       # 60+ modules for HTB/THM/Metasploitable
├── rcf-network/    # Async TCP/UDP scanners, protocol handlers
├── rcf-payload/    # Polymorphic payload generator & encoders
├── rcf-db/         # Secure SQLite persistence (Diesel + Argon2)
└── rcf-c2/         # Multi-session C2 server with Metasploit-like handlers
```

## ✨ Core Features

### Discovery & Intelligence
- **High-Speed Scanners** — Parallel CIDR scanning with configurable concurrency and target caps.
- **Deep Fingerprinting** — Protocol-specific probes for HTTP, SSH, SMB, VNC, Redis, and more.
- **Auth Brute Force** — Parallel credential testing for SSH, FTP, HTTP, and SNMP.

### Exploitation & Labs
- **Web Modules** — Log4Shell, SQLi, XSS, SSRF, Deserialization, and Apache Struts RCEs.
- **Service Exploits** — Targeted attacks for Metasploitable 2/3 and common lab vulnerabilities.
- **Custom Payloads** — Generate polymorphic shellcode in C, Python, or Raw formats.

### Post-Exploitation
- **Linux Escalate** — Automatic SUID and capability-based privilege escalation checker.
- **Multi-Shell C2** — Manage multiple reverse shells with a centralized C2 handler.
- **Persistence** — Credential harvesting and automated persistence installation.

## 📦 Installation

```bash
git clone https://github.com/pallab-js/r-msf.git
cd r-msf
cargo build --release -p rcf-cli
```

*Requires Rust 2024 (1.85+).*

## 🔒 Security Policy

This framework is for **authorized testing only**. RCF implements strict security defaults:
- TLS certificates are validated by default (opt-in insecure with `--dangerous-accept-invalid-certs`).
- Sensitive data is zeroed from memory immediately after use via `zeroize`.
- C2 commands are filtered for metacharacter injection.

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for detailed audit findings.

## 📄 License

BSD-3-Clause.

## ⚠️ Disclaimer

Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal. The developers assume no liability for misuse.
