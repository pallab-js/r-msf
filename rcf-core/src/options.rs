//! Module option definitions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The value type for a module option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptionValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    List(Vec<String>),
}

impl OptionValue {
    pub fn as_string(&self) -> String {
        match self {
            OptionValue::String(s) => s.clone(),
            OptionValue::Integer(i) => i.to_string(),
            OptionValue::Boolean(b) => b.to_string(),
            OptionValue::List(items) => items.join(", "),
        }
    }
}

/// A single option definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleOption {
    /// Display name
    pub name: String,
    /// Whether this option must be set before running
    pub required: bool,
    /// Current value
    pub value: Option<OptionValue>,
    /// Help text
    pub description: String,
}

impl ModuleOption {
    pub fn new(name: &str, required: bool, description: &str) -> Self {
        Self {
            name: name.to_string(),
            required,
            value: None,
            description: description.to_string(),
        }
    }

    pub fn with_default(
        name: &str,
        required: bool,
        description: &str,
        default: OptionValue,
    ) -> Self {
        Self {
            name: name.to_string(),
            required,
            value: Some(default),
            description: description.to_string(),
        }
    }

    pub fn set_value(&mut self, value: OptionValue) {
        self.value = Some(value);
    }
}

/// Collection of options for a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleOptions {
    pub options: HashMap<String, ModuleOption>,
}

impl ModuleOptions {
    pub fn new() -> Self {
        Self {
            options: HashMap::new(),
        }
    }

    /// Add an option.
    pub fn add(&mut self, opt: ModuleOption) {
        self.options.insert(opt.name.clone(), opt);
    }

    /// Get an option's current value.
    pub fn get(&self, key: &str) -> Option<&OptionValue> {
        self.options.get(key).and_then(|o| o.value.as_ref())
    }

    /// Set an option's value.
    pub fn set(&mut self, key: &str, value: OptionValue) -> Result<(), String> {
        match self.options.get_mut(key) {
            Some(opt) => {
                opt.set_value(value);
                Ok(())
            }
            None => Err(format!("unknown option: {}", key)),
        }
    }

    /// Check if all required options are set.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let missing: Vec<String> = self
            .options
            .iter()
            .filter(|(_, opt)| opt.required && opt.value.is_none())
            .map(|(key, _)| key.clone())
            .collect();

        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }

    /// Pretty-print options in a table format.
    pub fn format_table(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "  {:<20} {:<10} {:<15}  {}",
            "Name", "Required", "Value", "Description"
        ));
        lines.push(format!(
            "  {:<20} {:<10} {:<15}  {}",
            "----", "--------", "-----", "-----------"
        ));

        let mut items: Vec<_> = self.options.iter().collect();
        items.sort_by(|a, b| a.0.cmp(b.0));

        for (key, opt) in items {
            let value = opt
                .value
                .as_ref()
                .map(|v| v.as_string())
                .unwrap_or_default();
            let req = if opt.required { "yes" } else { "no" };
            lines.push(format!(
                "  {:<20} {:<10} {:<15}  {}",
                key, req, value, opt.description
            ));
        }

        lines.join("\n")
    }
}

impl Default for ModuleOptions {
    fn default() -> Self {
        Self::new()
    }
}
