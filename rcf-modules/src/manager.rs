//! Module manager — handles lifecycle, search, and display.

use colored::Colorize;
use rcf_core::ModuleCategory;

use crate::registry::ModuleRegistry;

/// High-level manager for module operations.
pub struct ModuleManager {
    registry: ModuleRegistry,
}

impl ModuleManager {
    pub fn new(registry: ModuleRegistry) -> Self {
        Self { registry }
    }

    /// Get a reference to the registry.
    pub fn registry(&self) -> &ModuleRegistry {
        &self.registry
    }

    /// Get a mutable reference to the registry.
    pub fn registry_mut(&mut self) -> &mut ModuleRegistry {
        &mut self.registry
    }

    /// Display search results in a formatted table.
    pub fn format_search_results(&self, keyword: &str) -> String {
        let results = self.registry.search(keyword);
        if results.is_empty() {
            return format!("No modules found matching '{}'", keyword);
        }

        let mut lines = Vec::new();
        lines.push(format!(
            "\n{} matching modules ({})\n",
            format!("Matching '{}'", keyword).bold().green(),
            results.len()
        ));
        lines.push(format!(
            "  {:<45} {:<12} {:<8}  {}",
            "Name".bold(),
            "Category".bold(),
            "Rank".bold(),
            "Description".bold()
        ));
        lines.push(format!(
            "  {:<45} {:<12} {:<8}  {}",
            "----".bold(),
            "--------".bold(),
            "----".bold(),
            "-----------".bold()
        ));

        for info in results {
            lines.push(format!(
                "  {:<45} {:<12} {:<8}  {}",
                info.name,
                format!("{}", info.category),
                info.rank,
                info.description
            ));
        }

        lines.join("\n")
    }

    /// Display module info in detail.
    pub fn format_module_info(&self, name: &str) -> String {
        match self.registry.get(name) {
            Some(module) => {
                let info = module.info();
                let mut lines = Vec::new();

                lines.push(format!("\n{}", info.display_name.bold().cyan()));
                lines.push(format!("  {:<20} {}", "Name:", info.name));
                lines.push(format!("  {:<20} {}", "Category:", info.category));
                lines.push(format!("  {:<20} {}", "Rank:", self.format_rank(info.rank)));
                lines.push(format!("  {:<20} {}", "Stability:", info.stability));
                if let Some(date) = &info.disclosure_date {
                    lines.push(format!("  {:<20} {}", "Disclosure:", date));
                }
                lines.push(format!("  {:<20} {}", "Authors:", info.authors.join(", ")));
                lines.push(format!("\n  {}", "Description:".bold().yellow()));
                lines.push(format!("    {}", info.description));

                if !info.references.is_empty() {
                    lines.push(format!("\n  {}", "References:".bold().yellow()));
                    for r in &info.references {
                        lines.push(format!("    {}", r));
                    }
                }

                lines.push(format!("\n  {}", "Options:".bold().yellow()));
                lines.push(module.options().format_table());

                lines.join("\n")
            }
            None => format!("Module '{}' not found", name),
        }
    }

    /// Display all modules grouped by category.
    pub fn format_all_modules(&self) -> String {
        let categories = [
            ModuleCategory::Exploit,
            ModuleCategory::Auxiliary,
            ModuleCategory::Payload,
            ModuleCategory::Encoder,
            ModuleCategory::Nop,
            ModuleCategory::Post,
        ];

        let mut lines = Vec::new();
        lines.push(format!("\n{}", "RCF Modules".bold().green()));
        lines.push(format!("  {} modules loaded\n", self.registry.len()));

        for cat in &categories {
            let modules = self.registry.list(Some(cat));
            if modules.is_empty() {
                continue;
            }

            lines.push(format!(
                "  {} ({})",
                format!("{}", cat).bold().yellow(),
                modules.len()
            ));

            for info in modules {
                lines.push(format!("    {:<45} {}", info.name, info.description));
            }
            lines.push(String::new());
        }

        lines.join("\n")
    }

    fn format_rank(&self, rank: u8) -> String {
        match rank {
            0 => "Manual".to_string(),
            1..=50 => "Low".to_string(),
            51..=74 => "Average".to_string(),
            75..=99 => "Good".to_string(),
            100 => "Excellent".to_string(),
            _ => "Unknown".to_string(),
        }
    }
}
