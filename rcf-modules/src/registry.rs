//! Module registry — stores and retrieves modules by path.

use std::collections::HashMap;
use std::sync::Arc;

use rcf_core::{Module, ModuleCategory, ModuleInfo};
use tracing::{info, warn};

/// The central registry of all available modules.
///
/// Modules are keyed by their path-like name (e.g. "scanner/port/tcp_syn").
pub struct ModuleRegistry {
    modules: HashMap<String, Arc<dyn Module>>,
    aliases: HashMap<String, String>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            aliases: HashMap::new(),
        }
    }

    /// Register an internal module.
    pub fn register(&mut self, module: impl Module + 'static) {
        let info = module.info();
        let name = info.name.clone();
        info!(name = %name, category = %info.category, "Registering module");
        self.modules.insert(name, Arc::new(module));
    }

    /// Get a module by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Module>> {
        // Try direct lookup first
        if let Some(module) = self.modules.get(name) {
            return Some(Arc::clone(module));
        }
        // Try alias lookup
        if let Some(real_name) = self.aliases.get(name) {
            return self.modules.get(real_name).map(Arc::clone);
        }
        None
    }

    /// Search modules by keyword (matches name, description, category).
    pub fn search(&self, keyword: &str) -> Vec<&ModuleInfo> {
        let keyword_lower = keyword.to_lowercase();
        self.modules
            .values()
            .map(|m| m.info())
            .filter(|info| {
                info.name.to_lowercase().contains(&keyword_lower)
                    || info.display_name.to_lowercase().contains(&keyword_lower)
                    || info.description.to_lowercase().contains(&keyword_lower)
                    || format!("{}", info.category)
                        .to_lowercase()
                        .contains(&keyword_lower)
            })
            .collect()
    }

    /// List all modules, optionally filtered by category.
    pub fn list(&self, category: Option<&ModuleCategory>) -> Vec<&ModuleInfo> {
        self.modules
            .values()
            .map(|m| m.info())
            .filter(|info| {
                if let Some(cat) = category {
                    &info.category == cat
                } else {
                    true
                }
            })
            .collect()
    }

    /// List all categories and their module counts.
    pub fn categories(&self) -> HashMap<ModuleCategory, usize> {
        let mut counts = HashMap::new();
        for module in self.modules.values() {
            let cat = module.info().category.clone();
            *counts.entry(cat).or_insert(0) += 1;
        }
        counts
    }

    /// Add an alias (e.g. "scanner" -> "auxiliary/scanner/port/tcp_syn").
    pub fn add_alias(&mut self, alias: &str, target: &str) {
        if self.modules.contains_key(target) {
            self.aliases.insert(alias.to_string(), target.to_string());
        } else {
            warn!(alias = %alias, target = %target, "Cannot add alias: target module not found");
        }
    }

    /// Get the total number of registered modules.
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}
