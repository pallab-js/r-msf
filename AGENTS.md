# AGENTS.md — RCF (Rust Cybersecurity Framework)

## Build Commands

```bash
# Verify compilation (fastest)
cargo check --workspace

# Lint (required before PRs)
cargo clippy --workspace -- -D warnings

# Format check
cargo fmt -- --check

# Format code
cargo fmt

# Run tests
cargo test --workspace

# Build release binary (rcf-cli package)
cargo build --release -p rcf-cli
```

CI runs in order: `fmt check` → `clippy` → `test` → `build`

## Package Structure

```
rcf-cli/        # CLI entry point (binary), main user-facing command
rcf-core/       # Core types, Module trait, Context, audit logging
rcf-console/    # Interactive REPL
rcf-modules/    # Module registry and plugin system
rcf-labs/       # 56+ exploit/scanner modules
rcf-network/    # TCP scanners, protocol handlers
rcf-payload/    # Shellcode generator, encoders, PE builder
rcf-db/         # SQLite/Diesel database layer
rcf-c2/         # C2 server with session management
```

Main binary: `rcf-cli/src/main.rs`

## Important Conventions

- **Rust Edition 2024** — Uses `edition = "2024"` in workspace
- **Workspace resolver v2** — Dependencies shared via `[workspace.dependencies]`
- **No external migrations** — Database uses embedded migrations (`embed_migrations!`)
- **Cryptography**: Passwords hashed with Argon2 (in `rcf-db`), NOT SHA-256
- **TLS default is STRICT** — `TlsConfig::default()` enforces certificate validation

## Security Constraints (Enforced)

- **C2 commands use allowlist** — Only read-only commands permitted (`uname`, `whoami`, `ps`, etc.)
- **SSRF protection** — `SsrfProtection` struct blocks localhost/private IPs in scanners
- **Path traversal safe mode** — Blocks SSH keys, AWS creds, Docker secrets by default
- **Payload IP validation** — `ConnectionValidator` rejects private/reserved IPs
- **Rate limiting** — C2 server throttles connections above 1000/minute

## Adding New Modules

Modules live in `rcf-labs/src/`. Implement the `Module` trait:

```rust
use rcf_core::{Context, Module, ModuleCategory, ModuleInfo, ModuleOptions};

static MY_MODULE_INFO: LazyLock<ModuleInfo> = LazyLock::new(|| ModuleInfo {
    name: "auxiliary/scanner/http/my_scanner".to_string(),
    // ...
});

pub struct MyModule;

impl Module for MyModule {
    fn info(&self) -> &ModuleInfo { &MY_MODULE_INFO }
    fn options(&self) -> ModuleOptions { /* ... */ }
    fn run(&self, ctx: &mut Context, _target: &Target) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        Box::pin(async move { /* ... */ })
    }
}
```

Then export in `rcf-labs/src/lib.rs`.

## Adding Dependencies

Add to `[workspace.dependencies]` in root `Cargo.toml`. Individual crates reference workspace deps without version.

## Cross-Compilation

```bash
# Linux x86_64
rustup target add x86_64-unknown-linux-gnu
cargo build --release -p rcf-cli --target x86_64-unknown-linux-gnu

# Windows (requires MinGW)
rustup target add x86_64-pc-windows-gnu
cargo build --release -p rcf-cli --target x86_64-pc-windows-gnu

# Linux ARM64
rustup target add aarch64-unknown-linux-gnu
cargo build --release -p rcf-cli --target aarch64-unknown-linux-gnu
```

## Testing Locally

```bash
# Quick compile check
cargo check -p rcf-cli

# Test single package
cargo test -p rcf-core

# Test specific module (if unit tests exist)
cargo test -p rcf-labs -- module_name
```

## Known Quirks

- **`rand` crate version mismatch**: `argon2` depends on `rand_core 0.6.x`, workspace uses `rand 0.9`. Import OsRng via `rand::rng()` or use `rand::Rng` trait.
- **`is_v4_mapped()` deprecated**: Use `ip.to_ipv4_mapped()` directly with `if let Some(v4) = ip.to_ipv4_mapped()`.
- **`to_lowercase()` in hot paths**: Avoid in tight loops (e.g., port scanning). Use case-insensitive comparisons instead.
- **Diesel migrations**: Migrations embedded at compile time; no external migration files needed.
