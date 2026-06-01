# Rust Cybersecurity Framework (RCF) v0.3.0

[![CI](https://github.com/pallab-js/r-msf/actions/workflows/ci.yml/badge.svg)](https://github.com/pallab-js/r-msf/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-edition-orange.svg)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/version-0.3.0-green.svg)](CHANGELOG.md)

> **Fast. Memory-Safe. Secure by Default. OpenSec Compliant.**

**RCF** is a lightweight, high-performance penetration testing framework written in Rust. Purpose-built for Linux security assessments, it provides 60+ pre-built modules for network reconnaissance, exploitation, and post-exploitation — with cryptographic integrity guarantees and policy-driven execution controls aligned with OpenSec principles.

---

## v0.3.0 Highlights

- **OpenSec Policy Engine** — TOML-defined allow/deny rules for module execution with target CIDR, time window, and operator identity constraints. Default-deny posture enforced before every `module.run()`. See `rcf policy init` to get started.
- **Ed25519 C2 Authentication** — Replaced PSK-only auth with agent-keyed Ed25519 handshake. Nonce challenge-response protocol with HKDF-derived session tokens. Backward-compatible `--legacy-psk` flag for v0.2 agents.
- **Binary Integrity Verification** — Release binaries verified against an Ed25519 signature on startup. Tampered binaries are rejected with a clear error. Sign with `scripts/sign-release.sh`.
- **Audit Logging** — Every policy decision, authentication attempt, and module execution is logged with structured JSON entries via `AuditLogger`.

## Quick Start

```bash
# Build the release binary
cargo build --release -p rcf-cli

# Initialize a policy (creates ~/.rcf/opensec/policies.toml)
./target/release/rcf policy init

# Start the interactive console
./target/release/rcf

# Run a module non-interactively
rcf run -m auxiliary/scanner/port/tcp_syn -t 10.10.10.0/24 -p 80

# Check if a module is permitted by policy
rcf policy check -m exploit/log4shell -t 10.0.0.5

# Generate an automated attack chain report
rcf auto -t 10.129.1.1 -o report.html
```

## Architecture

```
rcf/
├── rcf-core/       # Core traits, Context, Crypto (Ed25519, HKDF), Policy Engine,
│                   # Integrity verification, Anonymity system, Audit logging
├── rcf-cli/        # CLI entry point, subcommand dispatch, report generation,
│                   # policy management commands
├── rcf-console/    # Interactive TUI/REPL with rustyline tab completion
├── rcf-modules/    # Module registry, manager, builtin registration
├── rcf-labs/       # 60+ modules for HTB, THM, Metasploitable, PortSwigger labs
├── rcf-network/    # Async TCP/UDP scanners (connect, SYN, raw SYN), protocol
│                   # fingerprinting (HTTP, SSH, SMB)
├── rcf-payload/    # Polymorphic payload generator (RCF-Venom), XOR encoders,
│                   # NASM stager assembly, output formatters
├── rcf-db/         # SQLite persistence via Diesel ORM, WAL mode, Argon2-hashed
│                   # credentials, upsert semantics
├── rcf-c2/         # Multi-session C2 server, Ed25519 agent auth, sliding-window
│                   # rate limiting, meterpreter-style command handlers
└── rcf-agent/      # Standalone C2 agent, command allowlist enforcement,
                    # base64 protocol, minimal dependency footprint
```

## Features

### Reconnaissance & Discovery
- **High-Speed Scanning** — Parallel CIDR scanning with configurable concurrency and target caps (`--max-targets`).
- **Protocol Fingerprinting** — Banner grab and fingerprint HTTP, SSH, SMB, VNC, Redis, MySQL, PostgreSQL, and more.
- **Credential Testing** — Parallel authentication brute force for SSH, FTP, HTTP Basic, and SNMP.

### Exploitation
- **Web Exploits** — Log4Shell (CVE-2021-44228), ProxyShell, SQLi, XSS, SSRF, Deserialization, Struts RCE.
- **Service Exploits** — Redis unauthorized access, MySQL weak auth, Jenkins script console, Tomcat manager deploy, WordPress admin upload.
- **Payload Generation** — Polymorphic shellcode with XOR/NOP-sled encoders, staged/stageless payloads, C/Python/Raw output.

### Post-Exploitation
- **C2 Framework** — Centralized multi-session handler with Ed25517 key authentication and sliding-window rate limiting.
- **Linux Enumeration** — SUID/Capability escalation checkers, reverse shell listeners, webshell handlers.
- **Persistence** — Credential harvesting and automated persistence mechanisms.

### Security & Compliance
- **OpenSec Policy Engine** — Enforce pre-execution rules with module glob patterns, target CIDR scoping, time windows, and operator identity. Default: **deny**.
- **Binary Integrity** — Ed25519-signed release binaries; startup verification prevents execution of tampered builds.
- **Cryptographic Identity** — C2 agents identified by Ed25519 public keys; session tokens via HKDF-SHA256.
- **Audit Trail** — All operations logged with structured JSON; policy decisions, auth events, module executions.

## Installation

```bash
git clone https://github.com/pallab-js/r-msf.git
cd r-msf
cargo build --release -p rcf-cli
```

**Requirements:** Rust edition 2024 (toolchain 1.85+), Linux x86_64.

Optional runtime dependencies for advanced features:
- `nasm` — Payload stager assembly (build.rs fallback to placeholder if absent)
- `tor` — Anonymity system proxy chain (planned for v0.4)

## Security

RCF is designed for **authorized security assessments only**. The framework enforces multiple security layers:

| Layer | Mechanism | Status |
|-------|-----------|--------|
| Integrity | Ed25519 binary signature verification | v0.3 |
| Authentication | C2 agent key pairs via Ed25519 challenge-response | v0.3 |
| Authorization | OpenSec policy engine (module allow/deny rules) | v0.3 |
| Audit | Structured JSON logging of all operations | v0.2 |
| Transport | TLS with certificate validation enabled by default | v0.2 |
| Credentials | Argon2id hashing for stored secrets | v0.2 |
| Memory | `zeroize` trait for secret cleanup | v0.2 |
| C2 | Command allowlisting + metacharacter filtering | v0.2 |

## License

BSD-3-Clause. See [LICENSE](LICENSE).

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have explicit written permission to test is illegal. The authors assume no liability for misuse or damage.
