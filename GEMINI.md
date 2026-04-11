# Rust Cybersecurity Framework (RCF) — Gemini Context

## Project Overview
**RCF (Rust Cybersecurity Framework)** is a modular, async-first cybersecurity framework written in Rust (Edition 2024). It is designed as a memory-safe, high-performance alternative to Metasploit, compiling into a single ~4.7MB binary.

### Key Architecture
The project is organized into a Rust workspace with the following crates:
- **`rcf-core`**: The foundational crate. Defines the `Module` trait, `Context`, `Target`, `JobManager`, and audit logging.
- **`rcf-cli`**: The main entry point. Handles CLI subcommands (using `clap`), report generation, and automation.
- **`rcf-console`**: An interactive REPL (using `rustyline`) providing an `msfconsole`-like experience. Supports resource scripts (`.rc`).
- **`rcf-modules`**: The registry that manages the loading and registration of all modules.
- **`rcf-labs`**: Contains 56+ exploit and scanner modules targeting environments like HTB, THM, and OSCP labs.
- **`rcf-network`**: Implements network-level functionality, including TCP scanners and protocol fingerprinting.
- **`rcf-payload`**: Generates shellcode for Linux. Includes a polymorphic engine and a staged payload system (stagers in NASM).
- **`rcf-db`**: Database layer using SQLite and Diesel. Handles credential storage with Argon2 hashing and vulnerability tracking.
- **`rcf-c2`**: Command and Control server with PSK authentication, session management, and a sandboxed Meterpreter-style environment.
- **`rcf-agent`**: A standalone, lightweight C2 agent that connects back to the server.

**Platform: Linux x86_64 only**

## Building and Running

### Prerequisites
- **Rust 2024 Edition** (1.75+)
- **NASM** (Optional: for assembling real Linux x64 shellcode; otherwise, safe placeholders are used).

### Core Commands
- **Build Release**: `cargo build --release -p rcf-cli` (or `make release`)
- **Run Console**: `./target/release/rcf` (or `make run`)
- **Run Tests**: `cargo test --workspace` (or `make test`)
- **Lint**: `cargo clippy --workspace -- -D warnings` (or `make lint`)
- **Format**: `cargo fmt`

### CLI Usage Examples
- **Scan Subnet**: `rcf scan -t 192.168.1.0/24 --ports common --threads 100`
- **Generate Payload**: `rcf venom -p reverse_tcp --lhost 10.0.0.1 -f c`
- **Start C2**: `rcf c2 listen`
- **Automated Attack**: `rcf auto -t 10.0.0.5 -o report.html`

## Development Conventions

### The Module System
All exploits, scanners, and post-ex tools must implement the `Module` trait found in `rcf-core/src/module.rs`:
```rust
pub trait Module: Send + Sync {
    fn info(&self) -> &ModuleInfo;
    fn options(&self) -> ModuleOptions;
    fn run(&self, ctx: &mut Context, target: &Target) 
        -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>>;
}
```
- Modules are typically defined in `rcf-labs/src/`.
- Use `LazyLock<ModuleInfo>` for metadata to ensure efficient initialization.
- Async execution requires returning a `Pin<Box<dyn Future>>`.

### Security & Safety (Critical)
- **C2 Sandboxing**: The C2 server uses a blocklist for dangerous commands (`rm -rf`, `mkfs`, etc.).
- **SSRF Protection**: `SsrfProtection` blocks localhost/private IP scanning by default in certain modules.
- **Credential Hashing**: Passwords MUST be hashed with **Argon2** (handled automatically by `rcf-db`).
- **Path Validation**: Always validate file paths to prevent traversal vulnerabilities.
- **TLS**: Defaults to strict certificate validation (`TlsConfig::default()`). Use `--strict-tls` flag where available.
- **Temp Files**: Use the `tempfile` crate for secure, unpredictable filename generation for payloads.

### Coding Style
- **Edition 2024**: Strictly adhere to Rust 2024 idioms.
- **Error Handling**: Prefer `Result` and `anyhow`/`thiserror` over `unwrap()` or `expect()`, especially in I/O or network paths.
- **Dependencies**: Add new dependencies to the root `[workspace.dependencies]` in `Cargo.toml`.
- **Database**: Migrations are embedded (`embed_migrations!`); do not add external SQL migration files.

## Known Quirks
- **`rand` Versioning**: `argon2` uses an older `rand_core`, while the workspace uses `rand 0.9`. Use `rand::rng()` or explicit trait imports to resolve conflicts.
- **Clippy Warnings**: `rcf-labs` currently contains ~98 pre-existing clippy warnings; core crates (`rcf-core`, `rcf-c2`) must remain warning-free.
- **NASM Fallback**: If `nasm` is missing during build, the framework falls back to safe placeholder shellcode.

## Key Files
- `rcf-core/src/lib.rs`: Entry point for core traits and types.
- `rcf-cli/src/main.rs`: CLI subcommand logic and report generation.
- `rcf-c2/src/meterpreter.rs`: Command sandboxing logic.
- `rcf-payload/src/windows_shellcode.asm`: Real x64 reverse TCP assembly.
- `scripts/*.rc`: Example automation scripts.
