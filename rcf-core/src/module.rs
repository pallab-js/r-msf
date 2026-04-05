//! Module trait and related types.

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

use crate::context::Context;
use crate::error::Result;
use crate::options::ModuleOptions;
use crate::output::ModuleOutput;
use crate::target::Target;

/// Categories for organizing modules.
#[derive(Debug, Clone, Display, EnumString, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[strum(serialize_all = "snake_case")]
pub enum ModuleCategory {
    Exploit,
    Auxiliary,
    Payload,
    Encoder,
    Nop,
    Post,
}

/// Types of modules in the registry.
#[derive(Debug, Clone, Display, EnumString, Serialize, Deserialize, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub enum ModuleType {
    Internal,
    Dynamic,
}

/// Metadata about a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// Full path-like name, e.g. "scanner/port/tcp_syn"
    pub name: String,
    /// Human-readable display name
    pub display_name: String,
    /// Detailed description
    pub description: String,
    /// Author(s) of the module
    pub authors: Vec<String>,
    /// Module category
    pub category: ModuleCategory,
    /// Risk level (1–5)
    pub rank: u8,
    /// Whether this module is stable
    pub stability: String,
    /// Year of creation
    pub disclosure_date: Option<String>,
    /// References (CVE, URLs, etc.)
    pub references: Vec<String>,
}

/// The core trait every module in RCF must implement.
///
/// Modules can be exploits, scanners, payloads, auxiliary tools, or post-exploitation tools.
pub trait Module: Send + Sync {
    /// Returns static metadata about this module.
    fn info(&self) -> &ModuleInfo;

    /// Returns the configurable options for this module.
    fn options(&self) -> ModuleOptions;

    /// Validate that required options are set before execution.
    fn check(&self, ctx: &Context) -> crate::error::Result<()> {
        let opts = self.options();
        for (key, opt) in &opts.options {
            if opt.required && !ctx.has_option(key) {
                return Err(crate::error::RcfError::InvalidOption {
                    name: key.clone(),
                    reason: format!("required option '{}' is not set", key),
                });
            }
        }
        Ok(())
    }

    /// Execute the module with the given context and target.
    fn run(
        &self,
        ctx: &mut Context,
        target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>>;

    /// Optional: check if the target is vulnerable without full exploitation.
    /// Default implementation returns "not implemented".
    fn exploit_check(
        &self,
        _ctx: &Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        Box::pin(async { Ok(false) })
    }
}
