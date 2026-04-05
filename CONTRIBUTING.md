# Contributing to RCF

Thank you for your interest in contributing to the Rust Cybersecurity Framework! This document provides guidelines for contributing to the project.

## 🚨 Important Legal Notice

**By contributing to this project, you agree that:**
- Your contributions are for authorized security testing and research purposes only
- You will not use this project or its derivatives for unauthorized access to computer systems
- You have obtained proper authorization before testing any systems you do not own
- You understand and accept the BSD-3-Clause license

## Code of Conduct

This project adheres to a code of conduct that promotes respectful and inclusive communication. Please:
- Be respectful in all interactions
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy to newcomers

## How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check the [issue tracker](https://github.com/rcf/rcf/issues) for existing reports
2. Test with the latest `main` branch
3. Gather information: OS, Rust version, steps to reproduce, expected/actual behavior

When submitting a bug report, include:
- **Title:** Clear, concise description
- **Environment:** OS, Rust version, RCF version/commit
- **Steps to Reproduce:** Numbered, minimal steps
- **Expected Behavior:** What should happen
- **Actual Behavior:** What actually happens
- **Additional Context:** Logs, screenshots, if applicable

### Suggesting Features

Feature suggestions are welcome! Please include:
- **Problem Statement:** What problem does this solve?
- **Proposed Solution:** How should it work?
- **Alternatives Considered:** What other approaches exist?
- **Additional Context:** Examples, mockups, references

### Pull Requests

1. **Fork** the repository
2. **Create a branch** (`feature/my-awesome-feature`)
3. **Make your changes** following the coding conventions below
4. **Test thoroughly** — all tests must pass
5. **Update documentation** if your change affects behavior
6. **Submit the PR** with a clear title and description

#### Pull Request Guidelines

- **Title:** `feat: Add Redis protocol scanner` (use conventional commits style)
- **Description:** What, why, and how
- **Testing:** Confirm tests pass (`cargo test --workspace`)
- **Linting:** Confirm clean clippy run (`cargo clippy --workspace -- -D warnings`)
- **Documentation:** Update `QWEN.md`, `README.md`, or inline docs as needed

## Coding Conventions

### General Style

- Use `cargo fmt` before committing
- Use `cargo clippy --workspace -- -D warnings` for linting
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Prefer `Result` over panicking (`unwrap()`) in production code
- Use `#[cfg(test)]` modules for test code

### Module Development

All exploits/scanners must implement the `Module` trait:

```rust
pub trait Module: Send + Sync {
    fn info(&self) -> &ModuleInfo;
    fn options(&self) -> ModuleOptions;
    fn run(&self, ctx: &mut Context, target: &Target) 
        -> Pin<Box<dyn Future<Output = Result<ModuleOutput>> + Send + '_>>;
}
```

**Rules:**
- Use `LazyLock<ModuleInfo>` for static metadata
- Return `Pin<Box<dyn Future<...>>>` (not `async fn`) for dyn-compatibility
- Move all context variables into the async block before `Box::pin(async move { ... })`

### Security Requirements

- **NO raw HTML insertion** — Use `html_escape()` for report generation
- **Path Validation** — Validate output paths against system directories
- **Error Handling** — Avoid `unwrap()` on I/O or network operations
- **Unsafe Code** — Document with `#[allow(clippy::missing_safety_doc)]` and inline comments
- **Temp Files** — Use `tempfile` crate for unpredictable filenames

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `refactor:` Code refactoring
- `test:` Test additions/changes
- `chore:` Maintenance tasks

**Examples:**
```
feat(network): Add parallel CIDR scanning support
fix(exploits): Resolve TLS validation in MongoDB module
docs(readme): Update architecture diagram
refactor(core): Replace unwrap() with proper error handling
test(payload): Add XOR encoder integration tests
chore(deps): Update tokio to 1.41
```

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/rcf.git
cd rcf

# Create a branch
git checkout -b feature/my-feature

# Build and test
cargo build --release -p rcf-cli
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

## Review Process

1. **Automated Checks** — CI must pass (tests, linting, formatting)
2. **Code Review** — At least one maintainer must approve
3. **Security Review** — Changes affecting security components get extra scrutiny
4. **Merge** — Squash merge to keep history clean

## Release Process

Releases follow semantic versioning (0.1.0, 0.2.0, etc.):

1. Update `CHANGELOG.md` with all changes
2. Bump version in `Cargo.toml` workspace
3. Create a GitHub release with release notes
4. Upload binaries as release artifacts

## Getting Help

- **GitHub Issues:** Bug reports, feature requests
- **GitHub Discussions:** Questions, ideas, community chat
- **QWEN.md:** Project documentation and context

## Recognition

Contributors will be acknowledged in:
- `README.md` (significant contributions)
- Release notes
- `CHANGELOG.md`

Thank you for contributing to RCF! 🦀
