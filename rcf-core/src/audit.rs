//! Audit logging for security-relevant events.
//!
//! This module provides structured audit logging for:
//! - Module execution
//! - Credential discovery
//! - C2 session management
//! - Report generation
//! - Security-sensitive operations

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error, Level};

/// Audit event severity levels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditLevel {
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for AuditLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditLevel::Info => write!(f, "INFO"),
            AuditLevel::Warning => write!(f, "WARNING"),
            AuditLevel::Error => write!(f, "ERROR"),
            AuditLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Categories of audit events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditCategory {
    ModuleExecution,
    CredentialDiscovery,
    VulnerabilityFound,
    C2Session,
    ReportGeneration,
    SecurityViolation,
    NetworkScan,
    PayloadGeneration,
}

/// An audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub level: AuditLevel,
    pub category: AuditCategory,
    pub message: String,
    pub target: Option<String>,
    pub user: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl AuditEntry {
    pub fn new(level: AuditLevel, category: AuditCategory, message: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            category,
            message: message.into(),
            target: None,
            user: None,
            metadata: None,
        }
    }
    
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }
    
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }
    
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
    
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| String::from("{}"))
    }
}

/// Global audit logger.
pub struct AuditLogger {
    entries: Arc<Mutex<Vec<AuditEntry>>>,
    max_entries: usize,
    file_path: Option<String>,
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            max_entries: 10000,
            file_path: None,
        }
    }
    
    /// Set the audit log file path.
    pub fn with_file(mut self, path: impl Into<String>) -> Self {
        self.file_path = Some(path.into());
        self
    }
    
    /// Set the maximum number of entries to keep in memory.
    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }
    
    /// Log an audit entry.
    pub async fn log(&self, entry: AuditEntry) {
        // Log to tracing with security level
        let log_level = match entry.level {
            AuditLevel::Info => Level::INFO,
            AuditLevel::Warning => Level::WARN,
            AuditLevel::Error => Level::ERROR,
            AuditLevel::Critical => Level::ERROR,
        };
        
        let target_str = entry.target.as_deref().unwrap_or("-");
        let user_str = entry.user.as_deref().unwrap_or("-");
        
        // Use tracing to log (can be captured by tracing-subscriber)
        match log_level {
            Level::INFO => info!(
                target: "audit",
                category = ?entry.category,
                level = %entry.level,
                target = %target_str,
                user = %user_str,
                "{}", entry.message
            ),
            Level::WARN => warn!(
                target: "audit",
                category = ?entry.category,
                level = %entry.level,
                target = %target_str,
                user = %user_str,
                "{}", entry.message
            ),
            _ => error!(
                target: "audit",
                category = ?entry.category,
                level = %entry.level,
                target = %target_str,
                user = %user_str,
                "{}", entry.message
            ),
        }
        
        // Store in memory
        let mut entries = self.entries.lock().await;
        entries.push(entry);
        
        // Trim if necessary
        if entries.len() > self.max_entries {
            entries.drain(0..1000);
        }
        
        // Write to file if configured
        if let Some(ref path) = self.file_path
            && let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                use std::io::Write;
                if let Some(entry) = entries.last() {
                    let line = format!("{}\n", entry.to_json());
                    let _ = file.write_all(line.as_bytes());
                }
            }
    }
    
    /// Get all audit entries.
    pub async fn get_entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().await.clone()
    }
    
    /// Get entries by category.
    pub async fn get_by_category(&self, category: &AuditCategory) -> Vec<AuditEntry> {
        self.entries.lock().await
            .iter()
            .filter(|e| &e.category == category)
            .cloned()
            .collect()
    }
    
    /// Get entries by level.
    pub async fn get_by_level(&self, level: &AuditLevel) -> Vec<AuditEntry> {
        self.entries.lock().await
            .iter()
            .filter(|e| &e.level == level)
            .cloned()
            .collect()
    }
    
    /// Clear all entries.
    pub async fn clear(&self) {
        self.entries.lock().await.clear();
    }
}

// Convenience functions for common audit events

/// Log a module execution event.
pub async fn audit_module_execution(
    logger: &AuditLogger,
    module_name: &str,
    target: &str,
    success: bool,
) {
    let level = if success { AuditLevel::Info } else { AuditLevel::Warning };
    let message = format!(
        "Module {} executed on {}: {}",
        module_name,
        target,
        if success { "SUCCESS" } else { "FAILED" }
    );
    
    let entry = AuditEntry::new(level, AuditCategory::ModuleExecution, message)
        .with_target(target);
    
    logger.log(entry).await;
}

/// Log credential discovery.
pub async fn audit_credential_discovered(
    logger: &AuditLogger,
    target: &str,
    username: &str,
    service: &str,
) {
    let entry = AuditEntry::new(
        AuditLevel::Warning,
        AuditCategory::CredentialDiscovery,
        format!("Credential discovered: {}@{} (service: {})", username, target, service),
    )
    .with_target(target)
    .with_metadata(serde_json::json!({
        "username": username,
        "service": service
    }));
    
    logger.log(entry).await;
}

/// Log vulnerability discovery.
pub async fn audit_vulnerability_found(
    logger: &AuditLogger,
    target: &str,
    vuln_name: &str,
    severity: &str,
    cve: Option<&str>,
) {
    let level = match severity.to_lowercase().as_str() {
        "critical" => AuditLevel::Critical,
        "high" => AuditLevel::Error,
        "medium" => AuditLevel::Warning,
        _ => AuditLevel::Info,
    };
    
    let entry = AuditEntry::new(
        level,
        AuditCategory::VulnerabilityFound,
        format!("Vulnerability found on {}: {} (severity: {}, cve: {:?})", target, vuln_name, severity, cve),
    )
    .with_target(target)
    .with_metadata(serde_json::json!({
        "vulnerability": vuln_name,
        "severity": severity,
        "cve": cve
    }));
    
    logger.log(entry).await;
}

/// Log C2 session events.
pub async fn audit_c2_session(
    logger: &AuditLogger,
    peer_addr: &str,
    event: &str,
) {
    let level = match event {
        "connected" => AuditLevel::Info,
        "disconnected" => AuditLevel::Info,
        "command_executed" => AuditLevel::Warning,
        "auth_failed" => AuditLevel::Error,
        _ => AuditLevel::Info,
    };
    
    let entry = AuditEntry::new(
        level,
        AuditCategory::C2Session,
        format!("C2 session event: {} from {}", event, peer_addr),
    )
    .with_target(peer_addr);
    
    logger.log(entry).await;
}

/// Log security violations.
pub async fn audit_security_violation(
    logger: &AuditLogger,
    violation_type: &str,
    details: &str,
    source: Option<&str>,
) {
    let mut entry = AuditEntry::new(
        AuditLevel::Critical,
        AuditCategory::SecurityViolation,
        format!("Security violation: {} - {}", violation_type, details),
    )
    .with_metadata(serde_json::json!({
        "type": violation_type,
        "details": details,
        "source": source
    }));
    
    if let Some(s) = source {
        entry = entry.with_target(s);
    }
    
    logger.log(entry).await;
}
