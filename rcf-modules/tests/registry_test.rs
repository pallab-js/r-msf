//! Integration tests for the module registry and module lifecycle.

use std::future::Future;
use std::pin::Pin;

use rcf_core::error::Result;
use rcf_core::output::ModuleOutput;
use rcf_core::{Context, Module, ModuleCategory, ModuleInfo, ModuleOption, ModuleOptions, Target};
use rcf_modules::ModuleRegistry;

// ─── Minimal mock module ────────────────────────────────────────────────────

struct MockModule {
    name: &'static str,
    description: &'static str,
}

impl Module for MockModule {
    fn info(&self) -> &ModuleInfo {
        // SAFETY: We leak a Box to get a 'static ref — acceptable in tests.
        Box::leak(Box::new(ModuleInfo {
            name: self.name.to_string(),
            display_name: self.name.to_string(),
            description: self.description.to_string(),
            authors: vec!["test".to_string()],
            category: ModuleCategory::Auxiliary,
            rank: 1,
            stability: "stable".to_string(),
            disclosure_date: None,
            references: vec![],
        }))
    }

    fn options(&self) -> ModuleOptions {
        let mut opts = ModuleOptions::new();
        opts.add(ModuleOption::new("RHOSTS", true, "Target host"));
        opts
    }

    fn run(
        &self,
        _ctx: &mut Context,
        _target: &Target,
    ) -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>> {
        Box::pin(async { Ok(ModuleOutput::success("test/mock", "127.0.0.1", "ok\n")) })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn test_register_and_get() {
    let mut registry = ModuleRegistry::new();
    registry.register(MockModule {
        name: "test/mock",
        description: "A mock module",
    });

    let module = registry.get("test/mock");
    assert!(module.is_some());
    assert_eq!(module.unwrap().info().name, "test/mock");
}

#[test]
fn test_get_nonexistent_returns_none() {
    let registry = ModuleRegistry::new();
    assert!(registry.get("does/not/exist").is_none());
}

#[test]
fn test_search_by_keyword_matches_only_relevant() {
    let mut registry = ModuleRegistry::new();
    registry.register(MockModule {
        name: "scanner/ssh/login",
        description: "SSH brute force",
    });
    registry.register(MockModule {
        name: "exploit/http/sqli",
        description: "SQL injection",
    });

    let results = registry.search("ssh");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "scanner/ssh/login");
}

#[test]
fn test_module_check_missing_required_option_errors() {
    let module = MockModule {
        name: "test/check",
        description: "check test",
    };
    let ctx = Context::new(); // RHOSTS not set
    let result = module.check(&ctx);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("RHOSTS"));
}

#[test]
fn test_module_check_passes_with_required_option_set() {
    let module = MockModule {
        name: "test/check2",
        description: "check test 2",
    };
    let mut ctx = Context::new();
    ctx.set("RHOSTS", "10.0.0.1");
    assert!(module.check(&ctx).is_ok());
}
