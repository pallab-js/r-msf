# RCF — OpenCode Agent Notes

## Build & Test Commands

```bash
# Build the main binary
cargo build --release -p rcf-cli

# Dev build (faster)
cargo build -p rcf-cli

# Test core crates only (faster than full workspace)
cargo test -p rcf-core && cargo test -p rcf-network && cargo test -p rcf-labs

# Test all crates (~3+ minutes)
cargo test --workspace

# Lint & format check
cargo fmt
cargo fmt --check
cargo check --workspace

# Full clippy lint (core crates must pass with -D warnings)
cargo clippy --workspace -- -D warnings
```

CI order: `fmt --check` → `check` → `test` → `build`

## Architecture

- **Entry point**: `rcf-cli/src/main.rs`
- **Core traits**: `rcf-core/src/lib.rs` — `Module` trait, `Context`, `Target`, `JobManager`
- **Module system**: Modules in `rcf-labs/` implement `Module` trait from `rcf-core`
- **CLI**: `clap` with subcommands (`scan`, `venom`, `c2`, `db`, `auto`, `search`)
- **Console**: `rcf-console` — interactive REPL with resource scripts (`.rc` files in `scripts/`)
- **Database**: SQLite + Diesel in `rcf-db`; migrations are **embedded** (`embed_migrations!`)

## CTF/Hackathon Features

```bash
# Quick CTF start with resource script
rcf -r scripts/ctf_start.rc --set RHOSTS=10.10.10.10

# CTF timer
rcf run -m auxiliary/ctf/timer -t 127.0.0.1 -- ACTION=start

# Quick port scan (top 30 CTF ports)
rcf run -m auxiliary/scanner/ctf/quick_scan -t 10.10.10.10

# Hash identification
rcf run -m auxiliary/ctf/hashid -t 127.0.0.1 -- HASH=5d41402abc4b2a76b9719d911017c592

# Directory fuzzing
rcf run -m auxiliary/scanner/http/dirbust -t 10.10.10.10
```

## Anonymity Features (NEW)

```bash
# Set anonymity level
rcf anon --level ghost       # 3-8s delay, max stealth
rcf anon --level stealthy   # 1-3s delay, balanced
rcf anon --level moderate  # 0.5-1.5s delay
rcf anon --level standard  # default
rcf anon --level aggressive  # 0-50ms delay, no anonymity

# Add proxy chain (multiple = chain)
rcf anon --proxy socks5://127.0.0.1:1080
rcf anon --add-proxy http://proxy:8080 --add-proxy socks4://proxy:1081

# Custom jitter timing
rcf anon --jitter 1000:5000

# Show config
rcf anon --show

# Export/import config
rcf anon --export config.toml
rcf anon --import config.toml
```

**Levels**: ghost → stealthy → moderate → standard → aggressive
**Proxy types**: `socks5://`, `socks4://`, `http://`, `https://`
**Features**: User-Agent rotation, WAF detection (8+ WAFs), silent mode, decoy traffic, report anonymizer

## Module Development

Every module must implement `Module` trait:

```rust
fn run(&self, ctx: &mut Context, target: &Target) 
    -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>>;
```

- Use `LazyLock<ModuleInfo>` for static metadata
- Return `Pin<Box<dyn Future...>>`, **not** `async fn`
- Move context variables into the async block before `Box::pin(async move { ... })`
- All structs with `pub fn new() -> Self` should implement `Default` for consistency
- **Critical**: `fn options()` must return `opts` at the end:
  ```rust
  fn options(&self) -> ModuleOptions {
      let mut opts = ModuleOptions::new();
      opts.add(ModuleOption::new("RHOSTS", true, "Target"));
      opts  // ← MUST return opts, not ()
  }
  ```

### Module Registration

To add a new module:
1. Create module struct in `rcf-labs/src/` (e.g., `ctf_modules.rs`)
2. Export from `rcf-labs/src/lib.rs`: `pub mod ctf_modules; pub use ctf_modules::*;`
3. Register in `rcf-modules/src/builtin.rs`:
   ```rust
   pub mod ctf_modules {
       pub use rcf_labs::ctf_modules::{NewModule, AnotherModule};
   }
   registry.register(crate::builtin::ctf_modules::NewModule {});
   ```

### TCP Socket I/O in Modules

**Use tokio async I/O**, not sync `std::net`:

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Connecting with timeout
let mut stream = match tokio::time::timeout(
    Duration::from_secs(5),
    TcpStream::connect(&addr),
).await {
    Ok(Ok(s)) => s,
    Ok(Err(e)) => { /* handle error */ }
    Err(_) => { /* timeout */ }
};

// Reading (NOT BufReader with tokio stream)
let mut buf = vec![0u8; 1024];
if let Ok(n) = stream.read(&mut buf).await { ... }

// Writing
stream.write_all(b"DATA\r\n").await.ok();
```

**Common mistakes to avoid:**
- Don't use `std::io::BufReader` with `tokio::net::TcpStream` — doesn't implement sync `Read`
- Don't use `stream.read_line()` — use `read()` with a buffer instead
- Don't use `connect_timeout` — use `tokio::time::timeout` wrapper

### socket2 Raw Sockets

For raw socket scanning in `rcf-network`:
```toml
# rcf-network/Cargo.toml
socket2 = { workspace = true, features = ["all"] }
```

`recv()` requires `&mut [MaybeUninit<u8>]`:
```rust
let mut buf = [0u8; 1500];
let uninit_buf: &mut [std::mem::MaybeUninit<u8>] = unsafe {
    std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut _, buf.len())
};
socket.recv(uninit_buf)?;
```

## Security Module

`rcf-labs/src/security.rs` provides input validation for exploit modules:

- `validate_command_safety(cmd)` — checks for shell metacharacters, length limits
- `sanitize_command_input(cmd)` — strips dangerous characters, returns empty string on invalid
- `validate_host()`, `validate_port()`, `validate_url_path()` — input validation helpers

**All command-taking modules must use these functions** to prevent command injection:
- `protocol_exploits.rs` — PostgreSQL RCE
- `more_protocol_exploits.rs` — Elasticsearch RCE, Docker API
- `post_exploit.rs` — IRC backdoor, Samba usermap_script

```rust
use crate::security::{sanitize_command_input, validate_command_safety};

let cmd_raw = ctx.get("CMD").cloned().unwrap_or_else(|| "id".to_string());
let safety = validate_command_safety(&cmd_raw);
if !safety.safe {
    return Box::pin(async move {
        Ok(ModuleOutput::failure(&info_name, &addr, &format!("Invalid command: {}\n", safety.reason)))
    });
}
let cmd = sanitize_command_input(&cmd_raw);
```

## Workspace Conventions

- Add dependencies to `[workspace.dependencies]` in root `Cargo.toml`
- New crates: add to `members` array in workspace `Cargo.toml`
- All crates must pass `cargo check --workspace` and `cargo fmt --check`
- Core crates (`rcf-core`, `rcf-network`, `rcf-labs`) must pass clippy with `-D warnings`
- Use `#[allow(dead_code)]` for intentionally unused code (constants, patterns)
- Prefix unused function parameters with `_` (e.g., `_ctx`, `_timeout`)

## Dependencies & Tools

- **Rust 2024 Edition** (1.75+)
- **NASM** (optional): required for real Linux x64 shellcode; fallback to safe placeholders if missing
- **ssh2 crate**: For SSH brute force (`auxiliary/scanner/ssh/ssh_login`)
- **ftp crate**: For FTP operations
- **once_cell**: For `LazyLock` in module state
- **regex**: For pattern matching in CTF modules

## Platform

**Linux x86_64 only** — CLI-only, no GUI/TUI

- `rcf-core/src/module.rs:61` — `Module` trait definition
- `rcf-c2/src/meterpreter.rs` — command sandboxing
- `scripts/*.rc` — automation resource scripts

## Related Docs

- `GEMINI.md` — comprehensive project context
- `CONTRIBUTING.md` — commit conventions (conventional commits)
- `SECURITY.md` — vulnerability reporting
