//! Tab completion for the RCF console.

use rustyline::Context;
use rustyline::Helper;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;

use rcf_modules::ModuleRegistry;

/// Completer that provides tab-completion for module names, commands, and options.
pub struct RcfCompleter {
    filename_completer: FilenameCompleter,
    commands: Vec<&'static str>,
    module_names: Vec<String>,
    option_keys: Vec<&'static str>,
}

impl RcfCompleter {
    pub fn new(registry: &ModuleRegistry) -> Self {
        // Collect all module names
        let module_names: Vec<String> = registry
            .list(None)
            .iter()
            .map(|info| info.name.clone())
            .collect();

        Self {
            filename_completer: FilenameCompleter::new(),
            commands: vec![
                "help", "exit", "quit", "version", "show", "search", "info", "use", "back", "set",
                "unset", "options", "run", "exploit", "check", "targets", "sessions", "jobs",
                "reload", "save", "load",
            ],
            module_names,
            option_keys: vec![
                "RHOSTS", "RPORT", "LHOST", "LPORT", "TARGET", "PAYLOAD", "THREADS", "TIMEOUT",
                "VERBOSE", "SSL", "PROXIES",
            ],
        }
    }

    fn complete_command(&self, word: &str) -> Vec<Pair> {
        self.commands
            .iter()
            .filter(|cmd| cmd.starts_with(word))
            .map(|cmd| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect()
    }

    fn complete_module(&self, word: &str) -> Vec<Pair> {
        self.module_names
            .iter()
            .filter(|name| name.starts_with(word))
            .map(|name| Pair {
                display: name.clone(),
                replacement: name.clone(),
            })
            .collect()
    }

    fn complete_option(&self, word: &str) -> Vec<Pair> {
        let upper = word.to_uppercase();
        self.option_keys
            .iter()
            .filter(|key| key.starts_with(&upper))
            .map(|key| Pair {
                display: key.to_string(),
                replacement: key.to_string(),
            })
            .collect()
    }
}

impl Completer for RcfCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let start = line[..pos].rfind(' ').map(|p| p + 1).unwrap_or(0);
        let word = &line[start..pos];

        let mut candidates = Vec::new();

        if start == 0 {
            // First word — complete commands
            candidates = self.complete_command(word);
        } else {
            let first_word = line.split_whitespace().next().unwrap_or("");
            match first_word.to_lowercase().as_str() {
                "use" | "info" => {
                    candidates = self.complete_module(word);
                }
                "set" | "unset" => {
                    let parts: Vec<&str> = line[..pos].split_whitespace().collect();
                    if parts.len() <= 2 {
                        candidates = self.complete_option(word);
                    } else {
                        // Filename completion for values
                        return self.filename_completer.complete(line, pos, _ctx);
                    }
                }
                "show" | "search" => {
                    // Could complete categories — leave for now
                }
                _ => {
                    // Try filename completion
                    return self.filename_completer.complete(line, pos, _ctx);
                }
            }
        }

        if candidates.is_empty() {
            // Fallback to filename completion
            return self.filename_completer.complete(line, pos, _ctx);
        }

        Ok((start, candidates))
    }
}

impl Hinter for RcfCompleter {
    type Hint = String;
}

impl Highlighter for RcfCompleter {}

impl Validator for RcfCompleter {}

impl Helper for RcfCompleter {}
