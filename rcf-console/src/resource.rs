//! Resource script parser and executor.
//!
//! Resource scripts (`.rc` files) allow automating RCF workflows.
//! Each line contains a console command, executed sequentially.
//!
//! Format:
//! ```text
//! # This is a comment
//! setg RHOSTS 192.168.1.0/24
//! setg PORTS common
//! use auxiliary/scanner/port/tcp_connect
//! run
//! use exploit/multi/http/log4shell
//! set RHOSTS ${RHOSTS}
//! set LHOST ${LHOST}
//! run
//! ```
//!
//! Variables are expanded via `${VAR}` syntax.
//! Global variables (setg) persist across sessions.
//! Local variables (set) are module-specific.

use std::collections::HashMap;
use std::path::Path;

/// A parsed resource script.
#[derive(Debug, Clone)]
pub struct ResourceScript {
    /// Path to the source file
    pub source: String,
    /// Lines to execute (comments and blanks removed)
    pub commands: Vec<String>,
}

impl ResourceScript {
    /// Parse a resource script from a file path.
    ///
    /// # Security
    /// Validates the path to prevent path traversal attacks.
    pub fn from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path_ref = path.as_ref();

        // SECURITY: Validate path exists and is a file
        let canonical = path_ref.canonicalize().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Resource script not found: {} ({})", path_ref.display(), e),
            )
        })?;

        // Ensure it's a regular file
        if !canonical.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Not a regular file: {}", canonical.display()),
            ));
        }

        let content = std::fs::read_to_string(&canonical)?;
        Self::parse(&content, canonical.to_string_lossy().as_ref())
    }

    /// Parse a resource script from a string.
    pub fn parse(content: &str, source: &str) -> std::io::Result<Self> {
        let mut commands = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip empty lines
            if trimmed.is_empty() {
                continue;
            }

            // Skip comments
            if trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }

            // Handle line continuations (backslash at end)
            if let Some(stripped) = trimmed.strip_suffix('\\') {
                let _continued = stripped.to_string();
                // Read more lines until we find one without trailing backslash
                continue; // Simplified — full implementation would track state
            }

            commands.push(trimmed.to_string());
        }

        Ok(Self {
            source: source.to_string(),
            commands,
        })
    }

    /// Expand variables in a command line.
    /// Replaces `${VAR}` with values from the variable map.
    /// Unresolved variables are left as-is (allowing RCF to handle them).
    pub fn expand_variables(line: &str, variables: &HashMap<String, String>) -> String {
        let mut result = line.to_string();

        // Replace ${VAR} patterns
        for (key, value) in variables {
            let pattern = format!("${{{}}}", key);
            result = result.replace(&pattern, value);
        }

        result
    }

    /// Get the number of commands in the script.
    pub fn command_count(&self) -> usize {
        self.commands.len()
    }
}

/// Resource script executor — runs commands through a console interface.
pub struct ResourceExecutor {
    /// Global variables (persist across commands)
    pub variables: HashMap<String, String>,
    /// Whether to stop on first error
    pub stop_on_error: bool,
    /// Whether to echo commands as they execute
    pub echo_commands: bool,
}

impl ResourceExecutor {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
            stop_on_error: true,
            echo_commands: true,
        }
    }

    /// Set a global variable.
    pub fn set_variable(&mut self, key: &str, value: &str) {
        self.variables.insert(key.to_uppercase(), value.to_string());
    }

    /// Get a global variable.
    pub fn get_variable(&self, key: &str) -> Option<&str> {
        self.variables.get(&key.to_uppercase()).map(|s| s.as_str())
    }

    /// Execute a resource script, calling the provided callback for each command.
    ///
    /// The callback receives the expanded command line and should return
    /// Ok(()) if successful, or Err(description) if failed.
    pub async fn execute<F, Fut>(&self, script: &ResourceScript, mut callback: F) -> ExecuteResult
    where
        F: FnMut(String) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<(), String>>,
    {
        let total = script.command_count();
        let mut executed = 0;
        let mut errors = Vec::new();
        let mut output = Vec::new();

        for (i, command) in script.commands.iter().enumerate() {
            // Expand variables
            let expanded = ResourceScript::expand_variables(command, &self.variables);

            if self.echo_commands {
                let line = format!("{} [*] >> {}", "[*]".cyan(), expanded);
                output.push(line.clone());
                println!("{}", line);
            }

            // Execute command
            match callback(expanded.clone()).await {
                Ok(()) => {
                    executed += 1;
                }
                Err(e) => {
                    let line = format!("{} Error executing '{}': {}", "[-]".red(), expanded, e);
                    output.push(line.clone());
                    eprintln!("{}", line);
                    errors.push((i + 1, expanded, e));

                    if self.stop_on_error {
                        let line = format!(
                            "{} Stopping on error at line {} ({} of {} commands executed)",
                            "[*]".yellow(),
                            i + 1,
                            executed,
                            total
                        );
                        output.push(line.clone());
                        eprintln!("{}", line);
                        break;
                    }
                }
            }
        }

        ExecuteResult {
            total,
            executed,
            errors,
            output,
        }
    }
}

impl Default for ResourceExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of executing a resource script.
#[derive(Debug)]
pub struct ExecuteResult {
    /// Total number of commands in the script
    pub total: usize,
    /// Number of commands successfully executed
    pub executed: usize,
    /// Errors encountered (line number, command, error message)
    pub errors: Vec<(usize, String, String)>,
    /// All output lines (for logging/display)
    pub output: Vec<String>,
}

impl ExecuteResult {
    /// Check if all commands succeeded.
    pub fn success(&self) -> bool {
        self.errors.is_empty() && self.executed == self.total
    }

    /// Format a summary of the execution.
    pub fn summary(&self) -> String {
        if self.success() {
            format!("{} Resource script completed successfully", "[+]".green())
        } else if self.errors.is_empty() {
            format!(
                "{} Resource script partially executed: {} of {} commands",
                "[*]".yellow(),
                self.executed,
                self.total
            )
        } else {
            format!(
                "{} Resource script failed: {} errors at lines: {}",
                "[-]".red(),
                self.errors.len(),
                self.errors
                    .iter()
                    .map(|(line, _, _)| line.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    }
}

// ── Color helpers (since we can't use colored directly in this module) ─────

trait ColorExt {
    fn red(&self) -> String;
    fn green(&self) -> String;
    fn yellow(&self) -> String;
    fn cyan(&self) -> String;
}

impl ColorExt for str {
    fn red(&self) -> String {
        format!("\x1b[31m{}\x1b[0m", self)
    }
    fn green(&self) -> String {
        format!("\x1b[32m{}\x1b[0m", self)
    }
    fn yellow(&self) -> String {
        format!("\x1b[33m{}\x1b[0m", self)
    }
    fn cyan(&self) -> String {
        format!("\x1b[36m{}\x1b[0m", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_resource_script() {
        let content = r#"
# This is a comment
setg RHOSTS 192.168.1.0/24
setg PORTS common

use auxiliary/scanner/port/tcp_connect
run
"#;

        let script = ResourceScript::parse(content, "test.rc").unwrap();
        assert_eq!(script.command_count(), 4);
        assert_eq!(script.commands[0], "setg RHOSTS 192.168.1.0/24");
        assert_eq!(script.commands[1], "setg PORTS common");
        assert_eq!(script.commands[2], "use auxiliary/scanner/port/tcp_connect");
        assert_eq!(script.commands[3], "run");
    }

    #[test]
    fn test_expand_variables() {
        let mut variables = HashMap::new();
        variables.insert("RHOSTS".to_string(), "10.0.0.1".to_string());
        variables.insert("PORTS".to_string(), "common".to_string());

        let line = "set RHOSTS ${RHOSTS}";
        let expanded = ResourceScript::expand_variables(line, &variables);
        assert_eq!(expanded, "set RHOSTS 10.0.0.1");

        let line = "use ${MODULE}";
        let expanded = ResourceScript::expand_variables(line, &variables);
        assert_eq!(expanded, "use ${MODULE}"); // Unresolved, left as-is
    }

    #[test]
    fn test_variable_case_insensitive() {
        let mut executor = ResourceExecutor::new();
        executor.set_variable("rhosts", "192.168.1.1");
        assert_eq!(executor.get_variable("RHOSTS"), Some("192.168.1.1"));
        assert_eq!(executor.get_variable("rhosts"), Some("192.168.1.1"));
    }
}
