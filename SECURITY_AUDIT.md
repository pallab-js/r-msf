# RCF Security Audit Report

**Date:** 2026-04-05
**Auditor:** Qwen Code
**Scope:** Complete codebase review (10 crates, 85+ source files)
**Methodology:** Static analysis, pattern matching, manual code review

---

## Executive Summary

| Severity | Count | Status |
|----------|-------|--------|
| **CRITICAL** | 3 | 🔴 Requires immediate attention |
| **HIGH** | 4 | 🟠 Should be addressed before production use |
| **MEDIUM** | 5 | 🟡 Should be addressed in next release |
| **LOW** | 3 | 🟢 Nice to have |
| **INFO** | 2 | ℹ️ For awareness |

### Overall Assessment: ⚠️ **Moderate Risk**

RCF is a security testing tool designed for authorized use. Many "vulnerabilities" are intentional features for penetration testing. However, several issues affect the **safety of the tool itself** and could lead to crashes, unintended behavior, or security issues for the operator.

---

## CRITICAL Issues

### C1: HTML Injection in Report Generation

**File:** `rcf-cli/src/main.rs:895-920`, `rcf-cli/src/report_template.html`

**Description:** User-controlled data (host addresses, vulnerability names, service names, credential values) is inserted into HTML reports without escaping. An attacker who controls scan targets could inject malicious JavaScript into generated reports.

**Impact:** Cross-Site Scripting (XSS) when reports are opened in browsers.

**Vulnerable Code:**
```rust
// main.rs - no escaping applied
vulns_rows.push_str(&format!("<tr><td>{}</td>...", v.name, ...));
creds_rows.push_str(&format!("<tr><td>{}</td>...", c.password, ...));
```

**Attack Scenario:**
1. Attacker sets hostname to `<script>alert('xss')</script>` on a service
2. Victim scans the service with RCF
3. Generated HTML report executes attacker's JavaScript

**Fix:**
```rust
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#x27;")
}

// Usage:
vulns_rows.push_str(&format!("<tr><td>{}</td>...", html_escape(&v.name)));
```

---

### C2: Command Injection in Meterpreter Session Handler

**File:** `rcf-c2/src/meterpreter.rs:213`

**Description:** The `exec` Meterpreter command passes user input directly to `sh -c` without sanitization. While intentional for a pentesting tool, this runs on the **operator's machine** (not the target), meaning any compromise of the C2 server leads to operator machine compromise.

**Impact:** Remote Code Execution on operator's machine if C2 server is compromised.

**Vulnerable Code:**
```rust
let output = std::process::Command::new("sh")
    .arg("-c")
    .arg(command)  // ← User-controlled, unsanitized
    .output()
    .ok();
```

**Fix:** Add explicit warning comment and optional allowlist for dangerous commands:
```rust
/// WARNING: This executes arbitrary commands on the LOCAL machine.
/// Only use in trusted environments.
#[allow(clippy::disallowed_methods)]
let output = std::process::Command::new("sh")
    .arg("-c")
    .arg(command)
    .output()
    .ok();
```

---

### C3: Plaintext Credential Storage

**File:** `rcf-db/src/models.rs`, `rcf-db/migrations/00000000000000_init/up.sql`

**Description:** All discovered credentials (usernames, passwords, hashes) are stored in plaintext in the SQLite database. The database file has no encryption or access controls.

**Impact:** If the RCF database file is accessed by unauthorized parties, all captured credentials are exposed.

**Current Schema:**
```sql
CREATE TABLE credentials (
    username TEXT NOT NULL,
    password TEXT NOT NULL,  -- ← Plaintext
    ...
);
```

**Fix Options:**
1. **Encryption at rest:** Use SQLCipher (SQLite with AES encryption)
2. **Field-level encryption:** Encrypt password field before storage
3. **File permissions:** Restrict database file permissions (0600)

---

## HIGH Issues

### H1: Unsafe Temporary File Handling in Payload Executor

**File:** `rcf-payload/src/executor.rs:25-46`

**Description:** Payload executables are written to `/tmp/` with predictable names (`rcf_payload_{pid}`). On multi-user systems, this is vulnerable to symlink attacks or race conditions.

**Impact:** Local privilege escalation via symlink attack; payload disclosure via /tmp access.

**Vulnerable Code:**
```rust
let temp_dir = std::env::temp_dir();
let exe_path = temp_dir.join(format!("rcf_payload_{}", std::process::id()));
std::fs::write(&exe_path, elf_data)?;
```

**Fix:**
```rust
use std::os::unix::fs::OpenOptionsExt;
use rand::rngs::OsRng;

let temp_file = tempfile::Builder::new()
    .prefix("rcf_payload_")
    .suffix(".bin")
    .rand_bytes(16)
    .tempfile_in(std::env::temp_dir())?;
```

---

### H2: TLS Certificate Validation Disabled Everywhere

**Files:** All HTTP clients in `rcf-labs/src/*.rs`

**Description:** All HTTP clients are configured with `.danger_accept_invalid_certs(true)`. While intentional for pentesting (targets often have self-signed certs), this disables ALL certificate validation.

**Impact:** Man-in-the-middle attacks against the operator during scanning; credential interception.

**Affected Files:**
- `rcf-labs/src/exploits.rs:24`
- `rcf-labs/src/advanced_exploits.rs:74, 183`
- `rcf-labs/src/missing_vulns.rs:16`
- `rcf-labs/src/more_protocol_exploits.rs:431, 595, 787`

**Recommendation:** Add a `--strict-tls` flag that enables validation for production use, and document this behavior prominently.

---

### H3: No Path Traversal Protection in File Operations

**File:** `rcf-cli/src/main.rs:708-710`, `rcf-payload/src/executor.rs`

**Description:** File paths from user input are used directly without validation. Database path (`-c` flag), output paths (`-o` flag), and report paths can traverse outside intended directories.

**Impact:** Arbitrary file read/write through path traversal.

**Example:**
```bash
# Could overwrite arbitrary files if run with sufficient permissions
rcf report generate -o /etc/cron.d/malicious.html
```

**Fix:**
```rust
fn validate_path(path: &str) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(path);
    let canonical = path.canonicalize()?;
    // Ensure path is within allowed directory
    let base = std::env::current_dir()?;
    if canonical.starts_with(&base) {
        Ok(canonical)
    } else {
        Err(anyhow::anyhow!("Path outside allowed directory"))
    }
}
```

---

### H4: No Input Validation on Brute Force Modules

**Files:** `rcf-labs/src/protocol_exploits.rs`, `rcf-labs/src/scanners.rs`

**Description:** Brute force modules (SSH, FTP, HTTP login) have no rate limiting or attempt caps. Users could accidentally lock out accounts or trigger IDS alerts.

**Impact:** Account lockouts, IDS triggers, denial of service against targets.

**Recommendation:** Add `MAX_ATTEMPTS` and `DELAY_MS` options with sensible defaults.

---

## MEDIUM Issues

### M1: Multiple Unwrap Calls That Could Panic

**Files:** Multiple files

**Locations:**
- `rcf-network/src/scanner/tcp_connect.rs` - `unwrap()` on network operations
- `rcf-core/src/target.rs` - `unwrap()` in CIDR parsing
- `rcf-cli/src/main.rs:289` - `unwrap_or_else()` on file reads
- `rcf-payload/src/polymorphic.rs` - `unwrap()` in RNG operations

**Impact:** Denial of service (tool crash) on unexpected input.

**Fix:** Replace `unwrap()` with `?` or `.unwrap_or_default()`.

---

### M2: Unsafe Code Blocks Without Documentation

**Locations:**
- `rcf-network/src/scanner/raw_syn.rs:232, 319` - Raw socket operations
- `rcf-network/src/scanner/tcp_syn.rs:86` - `geteuid()` call
- `rcf-c2/src/meterpreter.rs:191` - `geteuid()` call

**Impact:** Potential undefined behavior if preconditions aren't met.

**Fix:** Add `/// # Safety` documentation to each unsafe block explaining invariants.

---

### M3: No Rate Limiting on Network Operations

**Description:** Scanners and exploits make network requests without built-in rate limiting. Scanning `/24` subnet with default threads could overwhelm network or trigger IDS.

**Impact:** Network congestion, IDS/IPS triggers, target service degradation.

**Recommendation:** Add global rate limiter with configurable requests-per-second.

---

### M4: Error Messages May Leak Sensitive Information

**Files:** Multiple exploit modules

**Description:** Error messages include full network responses, target addresses, and sometimes credential data.

**Example:**
```rust
// Returns full HTTP response body in error
auth_status = format!("HTTP {} - {}", status, body.chars().take(100).collect::<String>());
```

**Impact:** Sensitive data in logs, error output, or crash reports.

**Fix:** Truncate and sanitize error messages; add `--verbose` flag for full details.

---

### M5: GoogleBot/BingBot User-Agent Strings

**File:** `rcf-core/src/evasion.rs`

**Description:** The evasion module includes GoogleBot and BingBot User-Agent strings. Impersonating search engine crawlers may violate Google/Bing Terms of Service and could have legal implications.

**Impact:** Potential legal liability, IP blacklisting by search engines.

**Recommendation:** Remove bot impersonation or add explicit legal warning.

---

## LOW Issues

### L1: No Dependency Vulnerability Checking

**Description:** No `cargo audit` or Dependabot integration. Dependencies should be checked for known CVEs.

**Recommendation:** Add `cargo audit` to CI pipeline.

---

### L2: Default Credentials in Module Options

**Files:** Multiple modules

**Description:** Modules ship with default credentials (admin:admin, root:root, postgres:postgres). While convenient for testing, these could be accidentally used against production systems.

**Recommendation:** Leave credential options empty by default; add examples in help text.

---

### L3: No Module Permission Model

**Description:** All modules are available to all users. Exploit modules should perhaps require explicit acknowledgment or have a warning prompt.

**Recommendation:** Add `--acknowledge-risk` flag for exploit modules.

---

## INFO

### I1: Intentional Security Features

The following are **positive** security design choices found in the codebase:

- ✅ **Rust memory safety** — No buffer overflows in RCF code itself
- ✅ **Async I/O with timeouts** — No hanging connections
- ✅ **TLS support** (even if validation is disabled)
- ✅ **Session management** with proper cleanup
- ✅ **No hardcoded secrets** — All credentials are user-provided
- ✅ **Minimal binary size** — Less attack surface

### I2: Threat Model Considerations

RCF is a **security testing tool** — its purpose is to perform actions that would be malicious if done without authorization. The security model should consider:

1. **Operator safety** — Protect the user running RCF
2. **Target safety** — Prevent unintended damage to targets
3. **Data safety** — Protect collected sensitive data

---

## Recommendations Priority Order

1. **[CRITICAL]** Add HTML escaping to report generation (C1)
2. **[HIGH]** Document TLS validation behavior and add `--strict-tls` flag (H2)
3. **[HIGH]** Add path validation for file operations (H3)
4. **[CRITICAL]** Consider encrypting credential storage (C3)
5. **[MEDIUM]** Replace unwrap() calls with proper error handling (M1)
6. **[MEDIUM]** Add documentation to unsafe blocks (M2)
7. **[HIGH]** Add rate limiting to brute force modules (H4)
8. **[MEDIUM]** Sanitize error messages (M4)
9. **[LOW]** Add `cargo audit` to CI (L1)
10. **[LOW]** Remove bot impersonation User-Agents (M5)

---

## Conclusion

RCF is well-architected for a security testing tool with good use of Rust's safety features. The critical issues primarily affect the **output artifacts** (reports) and **credential storage** rather than the exploitation capabilities themselves. Most HIGH/MEDIUM issues are common for pentesting tools where operator convenience sometimes outweighs strict security.

**Overall: Suitable for authorized security testing with the noted caveats.**
