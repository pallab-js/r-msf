# Rust Cybersecurity Framework (RCF) — Context

## Project Overview

The **Rust Cybersecurity Framework (RCF)** is a modular, async-first Rust cybersecurity framework designed as a modern, memory-safe alternative to Metasploit. It compiles to a single ~4.7MB binary containing 56+ modules covering exploitation, scanning, post-exploitation, and payload generation.

**Key Features:**
- **Interactive REPL** — msfconsole-like console with tab completion and history
- **Parallel CIDR scanning** — Scan entire subnets concurrently (`192.168.1.0/24`)
- **Real protocol exploits** — BlueKeep (RDP), EternalBlue (SMBv1), MongoDB, VNC, WinRM, Elasticsearch, Docker API, and more
- **Payload engine** — Generates ELF/Mach-O binaries, raw shellcode with XOR/Polymorphic encoding
- **C2 Server** — Meterpreter-style session management with command sandboxing
- **Reporting** — Automated HTML reports with risk scoring and HTML escaping
- **Database** — SQLite + Diesel with automatic credential hashing (SHA-256 + salt)

**Architecture (10 Crates):**

| Crate | Purpose |
|-------|---------|
| `rcf-core` | Core types: `Module` trait, `Context`, `Target`, `Evasion`, `Jobs` |
| `rcf-cli` | CLI entry point: `clap` subcommands, report generation, automation |
| `rcf-console` | Interactive REPL: msfconsole-like interface with `rustyline` |
| `rcf-modules` | Registry: Loads and registers all builtin/lab modules |
| `rcf-labs` | Exploits/Scanners: 56+ modules for HTB/THM/OffSec labs |
| `rcf-network` | Scanners: TCP Connect/SYN scanners, protocol handlers |
| `rcf-payload` | Payloads: Generators, encoders, polymorphic engine, PE builder, executor |
| `rcf-db` | Database: SQLite + Diesel for hosts, creds, vulns |
| `rcf-c2` | C2: Server, session manager, meterpreter commands with sandboxing |

## Building & Running

### Prerequisites
- Rust 2024 Edition
- `cargo`

### Build Commands
```bash
# Quick check (no full compile)
cargo check --workspace

# Debug build
cargo build -p rcf-cli

# Release build (optimized, ~4.7MB)
cargo build --release -p rcf-cli

# Minimal build (no DB/C2)
cargo build --release -p rcf-cli --no-default-features
```

### Makefile Targets
```bash
make release          # Build release binary
make test             # Run all tests
make lint             # Clippy with -D warnings
make run              # Start interactive console
make scan             # Quick scan localhost
make venom            # Generate test payload
make bloat            # Analyze binary size
make linux-x64        # Cross-compile for Linux x86_64
make windows-x64      # Cross-compile for Windows (requires MinGW)
```

### CLI Usage
```bash
# Interactive Console
./target/release/rcf

# Search Modules
./target/release/rcf search log4j

# Port Scanning (supports CIDR)
./target/release/rcf scan -t 192.168.1.0/24 --ports common --threads 100
./target/release/rcf scan -t 10.0.0.1 --ports 80,443 --strict-tls

# Payload Generation
./target/release/rcf venom -p reverse_tcp --lhost 10.0.0.1 -f c
./target/release/rcf venom -p reverse_tcp --lhost 10.0.0.1 -f pe -o shell.exe

# Automation & Reporting
./target/release/rcf auto -t 192.168.1.1 -o report.html
./target/release/rcf report generate -o report.html

# Database Operations
./target/release/rcf db stats
./target/release/rcf db creds
./target/release/rcf db export -o data.json
```

### Console Commands
```
help            Show help
show modules    List all modules
search <kw>     Search modules
use <module>    Select module
set RHOSTS x    Set option
run             Execute module
jobs            List background jobs
exit            Quit
```

## Security Posture

A comprehensive security audit has been performed. See `SECURITY_AUDIT.md` for details.

**All 6 Critical Security Fixes Implemented:**

1. **Meterpreter Command Sandboxing** — Blocklist of dangerous commands (`rm -rf /`, fork bombs, `mkfs`, `dd`, etc.) prevents accidental system destruction.
2. **Strict TLS Propagation** — `--strict-tls` flag available; `Context::http_client()` method enables modules to respect TLS validation settings.
3. **Secure Temp Files** — Payloads use `tempfile` crate with 16 random bytes for unpredictable filenames, preventing symlink attacks.
4. **Production unwrap() Fixed** — Regex compilation and Metasploit parsing use proper error handling instead of panic-prone `unwrap()`.
5. **Unsafe Block Documentation** — All `unsafe` blocks have inline safety comments explaining invariants.
6. **Automatic Credential Hashing** — All passwords are hashed with SHA-256 + per-host/per-user salt before database storage.

## Development Conventions

### Module Trait
All exploits/scanners must implement `Module`:
```rust
pub trait Module: Send + Sync {
    fn info(&self) -> &ModuleInfo;
    fn options(&self) -> ModuleOptions;
    fn run(&self, ctx: &mut Context, target: &Target) 
        -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>>;
}
```

**Rules:**
- Use `LazyLock<ModuleInfo>` for static metadata.
- Return `Pin<Box<dyn Future<...>>>` (not `async fn`) for dyn-compatibility.
- Move all context variables into the async block before `Box::pin(async move { ... })`.

### Security Requirements
- **NO raw HTML insertion:** Always use `html_escape()` for report generation.
- **Path Validation:** Validate output paths against system directories.
- **Error Handling:** Avoid `unwrap()` on I/O or network operations; use `?` or `map_err`.
- **Credential Storage:** Passwords are automatically hashed with SHA-256 + salt.
- **Temp Files:** Use `tempfile` crate for unpredictable filenames.
- **Command Execution:** Blocklist dangerous patterns; document with `#[allow(clippy::disallowed_methods)]`.

### Testing
- Unit tests in `#[cfg(test)]` modules.
- Run with `cargo test --workspace`.
- Current status: 12/12 passing.

### Release Profile
```toml
[profile.release]
opt-level = "z"      # Size optimization
lto = "fat"          # Full link-time optimization
panic = "abort"      # Smaller panic paths
strip = true         # Remove debug symbols
codegen-units = 1    # Better cross-unit optimization
```

| Configuration | Size |
|--------------|------|
| Default (db + c2) | ~4.7MB |
| `--no-default-features` | ~3.5MB |

### Feature Flags
```toml
[features]
default = ["db", "c2"]
db = ["rcf-db", "chrono"]      # SQLite database + reporting
c2 = ["rcf-c2"]                 # C2 server + session management
```

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`):
- Lint & Test on push/PR
- Build matrix: Linux x86_64, macOS ARM64, Windows x64, Linux ARM64
- Release artifact upload on tag

## Key Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Workspace definition, dependencies, release profile |
| `Makefile` | Build automation, cross-compilation, PGO |
| `.cargo/config.toml` | Cross-compilation linker config |
| `rcf-cli/src/main.rs` | CLI entry point, report generation, path validation, HTML escaping |
| `rcf-core/src/module.rs` | `Module` trait definition |
| `rcf-core/src/context.rs` | Global context, options, `http_client()` for TLS config |
| `rcf-core/src/evasion.rs` | User-Agent rotation, timing jitter, proxy chains, TLS config |
| `rcf-c2/src/meterpreter.rs` | C2 commands with sandboxing blocklist |
| `rcf-payload/src/executor.rs` | Payload execution with `tempfile` for secure filenames |
| `rcf-db/src/connection.rs` | Database layer with automatic credential hashing |
| `rcf-labs/src/` | All exploit and scanner modules (56+) |
| `SECURITY_AUDIT.md` | Comprehensive security audit report |

## Remaining Work (Future Releases)

1. **Dependency Auditing** — Add `cargo audit` to CI pipeline
2. **SQLCipher Integration** — Encrypt SQLite database at rest
3. **Full TLS Propagation** — Update all HTTP modules to use `ctx.http_client()`
4. **Seccomp-bpf** — Restrict syscalls in Meterpreter command execution
5. **Plugin System** — Allow community-contributed modules via dynamic loading
6. **Web UI** — Browser-based interface alternative to CLI

## License & Disclaimer

**BSD-3-Clause**

Designed for **authorized security testing** and **research purposes only**. Always obtain proper authorization before testing systems you do not own.
