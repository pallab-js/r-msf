//! Module output and result formatting.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The result of a module execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleOutput {
    /// Module that produced this output
    pub module: String,
    /// Target that was scanned/exploited
    pub target: String,
    /// Whether execution was successful
    pub success: bool,
    /// Human-readable message
    pub message: String,
    /// Structured data output
    pub data: Option<serde_json::Value>,
    /// Output format preference
    pub format: OutputFormat,
}

impl ModuleOutput {
    pub fn success(module: &str, target: &str, message: &str) -> Self {
        Self {
            module: module.to_string(),
            target: target.to_string(),
            success: true,
            message: message.to_string(),
            data: None,
            format: OutputFormat::Text,
        }
    }

    pub fn failure(module: &str, target: &str, message: &str) -> Self {
        Self {
            module: module.to_string(),
            target: target.to_string(),
            success: false,
            message: message.to_string(),
            data: None,
            format: OutputFormat::Text,
        }
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.format = format;
        self
    }

    /// Render the output for display.
    pub fn render(&self) -> String {
        match self.format {
            OutputFormat::Text => self.render_text(),
            OutputFormat::Json => self.render_json(),
            OutputFormat::Table => self.render_table(),
        }
    }

    fn render_text(&self) -> String {
        let status = if self.success { "[+]" } else { "[-]" };
        format!("{} {}: {}", status, self.module, self.message)
    }

    fn render_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "Error serializing output".to_string())
    }

    fn render_table(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("\nModule: {}", self.module));
        lines.push(format!("Target: {}", self.target));
        lines.push(format!("Status: {}", if self.success { "SUCCESS" } else { "FAILED" }));
        lines.push(format!("Message: {}", self.message));

        if let Some(data) = &self.data {
            lines.push("\nData:".to_string());
            lines.push(serde_json::to_string_pretty(data).unwrap_or_default());
        }

        lines.join("\n")
    }
}

impl fmt::Display for ModuleOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

/// Output format preference.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Table,
}
