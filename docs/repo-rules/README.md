# Repository Rules

> Core principles and standards for maintaining the Security Header Analyzer project

---

## Quick Links

🐍 [Python Code Standards](python-code-standards.md) - Type hints, patterns, conventions  
🧪 [Testing Standards](testing-standards.md) - 97%+ coverage, fixtures, patterns  
🔧 [Git Practices](git-practices.md) - Commits, branches, releases  
🐛 [Debugging Practices](debugging-practices.md) - Tools, workflows, troubleshooting  
📝 [Documentation Standards](documentation-standards.md) - Templates, cross-linking, quality  
🔒 [Security Headers Best Practices](security-headers-best-practices.md) - All 15 headers

---

## Introduction

This directory contains the **authoritative standards** for the Security Header Analyzer project. These guides ensure:

- ✅ **Consistency** across all code and documentation
- ✅ **Quality** through automated checks and best practices
- ✅ **Maintainability** for solo developer workflow
- ✅ **Professionalism** in every commit

**For Solo Developers:** These rules are optimized for efficiency. Use pre-commit hooks and automation to enforce standards without manual effort.

---

## Core Principles

### 1. Quality Over Quantity
- 97%+ test coverage maintained
- MyPy strict mode (100% typed)
- Comprehensive documentation for all features

### 2. Consistency
- Black formatting (automated)
- isort import sorting (automated)  
- Standardized Finding structure across all analyzers
- Template-driven documentation

### 3. Automation First
- Pre-commit hooks catch issues before CI
- Let tools handle formatting/linting
- Focus on logic, not style

### 4. Solo Developer Efficiency
- Single main branch workflow
- Sprint-based organization for multi-step work
- Documentation updated during development (not after)
- Quick feedback loops (run tests locally first)

---

## File Overview

### [python-code-standards.md](python-code-standards.md)

**Purpose:** Python coding conventions specific to THIS project

**Key Topics:**
- Type Hints (MyPy strict mode)
- Code Organization (Registry pattern, Finding structure)
- Naming Conventions
- Docstring Standards
- Import Organization (isort)
- Code Style (Black)
- Error Handling
- **Analyzer Implementation Guide** (step-by-step)

**When to Reference:**
- Adding new analyzer
- Writing new Python modules
- Resolving type errors
- Understanding project patterns

**Length:** ~1,004 lines | **Completeness:** ⭐⭐⭐⭐⭐

---

### [testing-standards.md](testing-standards.md)

**Purpose:** Testing requirements and patterns for THIS project

**Key Topics:**
- Test Organization (class-based structure)
- Fixture Patterns (conftest.py, factories, real-world)
- Naming Conventions
- Coverage Requirements (97%+ overall, 100% for new analyzers)
- Assertion Patterns
- Mocking Strategy
- **Adding Tests for New Analyzers** (step-by-step)

**When to Reference:**
- Writing tests for new code
- Debugging test failures
- Understanding fixture usage
- Checking coverage gaps

**Length:** ~861 lines | **Completeness:** ⭐⭐⭐⭐⭐

---

### [git-practices.md](git-practices.md)

**Purpose:** Git workflow and commit standards for THIS project

**Key Topics:**
- Branch Strategy (single main branch)
- Commit Message Format (imperative mood, descriptive)
- Sprint-Based Organization
- Co-Authoring with Claude
- Release Process
- Recovery Patterns (no force push)

**When to Reference:**
- Before every commit
- Planning multi-step features (sprints)
- Creating releases
- Fixing commit mistakes

**Length:** ~589 lines | **Completeness:** ⭐⭐⭐⭐⭐

---

### [debugging-practices.md](debugging-practices.md)

**Purpose:** Debugging strategies for THIS project

**Key Topics:**
- Debugging Tools (pytest verbosity, tracebacks, coverage)
- Analyzer Debugging (testing in isolation)
- Type Error Resolution (common MyPy errors)
- Test Failures (reading pytest output)
- Coverage Gaps (finding untested code)
- **Common Issues & Solutions** (project-specific)

**When to Reference:**
- Tests failing
- Type errors from MyPy
- Coverage below target
- Debugging analyzer logic
- CLI not working as expected

**Length:** ~590 lines | **Completeness:** ⭐⭐⭐⭐⭐

---

### [documentation-standards.md](documentation-standards.md)

**Purpose:** Documentation management for THIS project

**Key Topics:**
- Documentation Philosophy (Brevity, Conciseness, Accuracy)
- File Organization
- **Documentation Types** (header docs, architecture, Python docstrings)
- Cross-Linking Strategy
- Updating Documentation (when code changes)
- Quality Checklist
- **Knowledge Extraction** (from ENHANCEMENT_PLAN.md, DOCUMENTATION_IMPLEMENTATION_PLAN.md)

**When to Reference:**
- Creating new documentation
- Updating docs for code changes
- Understanding doc structure
- Writing Python docstrings

**Length:** ~789 lines | **Completeness:** ⭐⭐⭐⭐⭐

---

### [security-headers-best-practices.md](security-headers-best-practices.md)

**Purpose:** Configuration guide for all 15 security headers

**Key Topics:**
- All 15 Headers (HSTS, CSP, X-Frame-Options, Referrer-Policy, etc.)
- Best Practice configurations
- Acceptable configurations
- Bad/Missing patterns
- Severity levels
- **Summary Table** (quick reference)

**When to Reference:**
- Understanding header security
- Configuring web applications
- Writing analyzer validation logic
- Explaining security impacts to users

**Length:** ~533 lines | **Completeness:** ⭐⭐⭐⭐⭐

---

## Enforcement

### Automated Checks (Pre-Commit Hooks)

**Installed:** `.pre-commit-config.yaml`

**Hooks:**
1. **black** - Code formatting (auto-fix)
2. **isort** - Import sorting (auto-fix)
3. **flake8** - Linting (errors only)
4. **mypy** - Type checking (strict mode)
5. **bandit** - Security scanning
6. **File checks** - Trailing whitespace, merge conflicts, etc.

**Setup:**
```bash
pip install pre-commit
pre-commit install
```

**Run Manually:**
```bash
pre-commit run --all-files
```

### CI/CD Checks (GitHub Actions)

**Workflow:** `.github/workflows/test.yml`

**Jobs:**
1. **test** - Multi-version pytest (Python 3.8-3.12)
2. **pre-commit** - All code quality checks
3. **lint** - Black, isort, flake8, mypy, bandit
4. **build** - Package building and validation
5. **security** - Dependency vulnerability scanning

---

## For Solo Developers

### Daily Workflow

```bash
# 1. Make changes
vim sha/analyzers/new_feature.py

# 2. Run tests
pytest --cov=sha

# 3. Pre-commit checks (auto-run on commit)
git add .
git commit -m "Add new feature"  # Hooks run automatically

# 4. Push
git push origin main
```

### Time-Saving Tips

**Let Automation Work:**
- Don't manually format code (Black does it)
- Don't manually sort imports (isort does it)
- Don't manually check types (MyPy does it)
- Pre-commit hooks catch issues before CI

**Focus on What Matters:**
- Writing correct logic
- Comprehensive tests
- Clear documentation
- Descriptive commit messages

**When to Skip Rules:**
- Experimental branches (clean up before merging)
- Quick local experiments (don't commit)
- POC code (document as such)

---

## Updating Rules

### When to Modify Standards

**Do Update When:**
- New patterns emerge from multiple uses
- Tools get new features we should adopt
- Standards prove inefficient in practice
- Project scope changes significantly

**Don't Update For:**
- One-off situations
- Personal preference without clear benefit
- Following trends without evaluation
- Reducing quality for convenience

### How to Update

1. **Propose change** (document rationale)
2. **Test change** (try it on actual code)
3. **Update standard** (edit relevant .md file)
4. **Update tooling** (pyproject.toml, .pre-commit-config.yaml, etc.)
5. **Apply retroactively** (update existing code if needed)
6. **Commit** (with clear explanation of change)

---

## Summary

**These guides ensure:**
- 🎯 Consistent code quality
- 🚀 Fast development (automation handles details)
- 📚 Comprehensive documentation
- 🛡️ High test coverage
- 🤝 Easy collaboration (including with AI)

**Quick Start:**
1. Install pre-commit hooks: `pre-commit install`
2. Read relevant guide before working in that area
3. Let tools enforce standards automatically
4. Commit often, push when tests pass

**Most Important:**
- [Python Code Standards](python-code-standards.md) - Start here for code
- [Testing Standards](testing-standards.md) - Before writing tests
- [Git Practices](git-practices.md) - Before every commit

---

**Last Updated:** 2026-01-01  
**Total Guidelines:** 6 comprehensive guides  
**Total Lines:** ~4,366 lines of standards and best practices

**See Also:**
- [Main Documentation Index](../README.md)
- [Contributing Guidelines](../../CONTRIBUTING.md)
- [Architecture Documentation](../architecture/README.md)
