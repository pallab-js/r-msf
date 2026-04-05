# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

**⚠️ Important: This is a security testing tool. Please be responsible when reporting vulnerabilities.**

If you discover a security vulnerability within RCF itself (not the vulnerabilities it detects in targets), please send a report to the project maintainers via GitHub Issues with the "security" label, or contact us directly through GitHub Discussions.

### What to Include

- A clear description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if you have one)

### Response Timeline

- **Initial response:** Within 48 hours
- **Severity assessment:** Within 1 week
- **Fix timeline:** Within 30 days for critical issues, 90 days for others
- **Public disclosure:** Coordinated release after fix is available

### Scope

**In Scope:**
- Buffer overflows or memory safety issues in RCF code
- Command injection in the C2 server component
- Authentication bypasses in the C2 server
- Credential storage issues in the database layer
- Path traversal in file operations

**Out of Scope:**
- Vulnerabilities detected by RCF in target systems (these are features, not bugs)
- Issues in third-party dependencies (report to those projects directly)
- Issues only exploitable with root/administrator privileges on the operator's machine

### Responsible Disclosure

We follow a coordinated disclosure model. Please do not publicly disclose security vulnerabilities until we have had time to assess, fix, and release an update.

## Security Best Practices for Users

1. **Never run RCF as root** unless absolutely necessary (e.g., SYN scanning requires raw sockets)
2. **Use a sandboxed environment** — Run RCF in a VM or container when testing untrusted targets
3. **Enable `--strict-tls`** when scanning production or sensitive systems
4. **Regularly update** — Keep your RCF installation up to date with the latest security patches
5. **Review generated reports** — HTML reports are escaped, but always verify before sharing
6. **Protect your database** — The SQLite file (`rcf.db`) may contain discovered credentials

## Security Audit

A comprehensive security audit was performed on this codebase. See `SECURITY_AUDIT.md` for details. All critical findings have been addressed.

## Acknowledgments

We thank all security researchers who have responsibly disclosed vulnerabilities to this project.
