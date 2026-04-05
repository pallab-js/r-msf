## Description

<!-- Describe your changes in detail. Include the motivation and context. -->

## Type of Change

<!-- Check the boxes that apply -->

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📝 Documentation update
- [ ] ♻️ Code refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] 🔒 Security fix

## Testing

<!-- Describe the tests you ran and how to reproduce them. -->

```bash
# Commands you ran
cargo build --release -p rcf-cli
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

- [ ] All tests pass (`cargo test --workspace`)
- [ ] Clippy passes with no warnings (`cargo clippy --workspace -- -D warnings`)
- [ ] Code is formatted (`cargo fmt`)
- [ ] Manual testing completed (if applicable)

## Checklist

- [ ] My code follows the project's coding conventions
- [ ] I have added comments to my code where necessary
- [ ] I have updated the documentation (QWEN.md, README.md, etc.) if needed
- [ ] I have added tests that prove my fix/feature works
- [ ] All new and existing tests pass
- [ ] My changes do not introduce new security vulnerabilities

## Screenshots/Output

<!-- If applicable, add screenshots or command output to help explain your changes. -->

## Related Issues

<!-- Link any related issues here -->

Closes #

## Additional Notes

<!-- Any additional information that reviewers should know -->
