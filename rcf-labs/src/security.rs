//! Security utilities for exploit modules.
//!
//! Provides input sanitization and validation helpers to reduce
//! command injection and other security risks in exploit modules.

use regex::Regex;
use std::sync::LazyLock;

#[allow(dead_code)]
static DANGEROUS_CHARS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[;&|`$(){}\[\]\\'\"!<>]|[0-9]{2,}"#).unwrap());

#[allow(dead_code)]
static SQL_INJECTION_PATTERNS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(union\s+select|exec\s*\(|xp_cmdshell|--\s*$) "#).unwrap());

static SHELL_METACHAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[;|`$\(\){}\[\]\\'\"!<>|#]|\|\||&&"#).unwrap());

pub fn sanitize_command_input(input: &str) -> String {
    if input.is_empty() {
        return input.to_string();
    }
    if validate_command_safety(input).safe {
        let sanitized: String = input
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_' || *c == '.')
            .collect();
        sanitized
    } else {
        String::new()
    }
}

pub fn sanitize_for_shell(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let sanitized: String = input
        .chars()
        .filter(|c| {
            c.is_alphanumeric()
                || *c == ' '
                || *c == '-'
                || *c == '_'
                || *c == '.'
                || *c == '/'
                || *c == ':'
        })
        .collect();
    sanitized
}

pub fn validate_command_safety(cmd: &str) -> CommandSafetyResult {
    if cmd.is_empty() {
        return CommandSafetyResult {
            safe: false,
            reason: "Empty command".to_string(),
        };
    }

    if cmd.len() > 500 {
        return CommandSafetyResult {
            safe: false,
            reason: "Command exceeds maximum length".to_string(),
        };
    }

    if SHELL_METACHAR.is_match(cmd) {
        return CommandSafetyResult {
            safe: false,
            reason: "Detected command injection patterns".to_string(),
        };
    }

    let whitespace_count = cmd.chars().filter(|c| *c == ' ').count();
    if whitespace_count > 20 {
        return CommandSafetyResult {
            safe: false,
            reason: "Too many arguments".to_string(),
        };
    }

    CommandSafetyResult {
        safe: true,
        reason: String::new(),
    }
}

pub fn sanitize_sql_identifier(identifier: &str) -> String {
    identifier
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .take(64)
        .collect()
}

pub fn validate_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
}

pub fn validate_port(port: u16) -> bool {
    port > 0
}

pub fn validate_url_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 4096 {
        return false;
    }
    path.starts_with('/')
        && !path.contains("..")
        && !path.contains("//")
        && path.chars().all(|c| {
            c.is_alphanumeric() || c == '/' || c == '_' || c == '-' || c == '.' || c == '='
        })
}

pub struct CommandSafetyResult {
    pub safe: bool,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_command_input() {
        assert_eq!(sanitize_command_input("id"), "id");
        assert_eq!(sanitize_command_input("cat /etc/passwd"), "cat etcpasswd");
        assert_eq!(sanitize_command_input(";rm -rf /"), "");
        assert_eq!(sanitize_command_input(""), "");
    }

    #[test]
    fn test_validate_command_safety() {
        let result = validate_command_safety("id");
        assert!(result.safe);

        let result = validate_command_safety("; rm -rf /");
        assert!(!result.safe);

        let result = validate_command_safety("");
        assert!(!result.safe);
    }

    #[test]
    fn test_validate_host() {
        assert!(validate_host("localhost"));
        assert!(validate_host("192.168.1.1"));
        assert!(validate_host("example.com"));
        assert!(!validate_host(""));
        assert!(!validate_host("../etc/passwd"));
    }
}
