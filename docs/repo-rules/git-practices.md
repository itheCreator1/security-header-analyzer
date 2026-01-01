# Git Practices

> Git workflow and commit standards for the Security Header Analyzer project

---

## Quick Reference

**Commit Message Template:**
```
<Verb> <what> (<scope>): <brief description>

<Optional: Extended explanation if needed>

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

**Branch Strategy:** Single main branch (no feature branches)

**Before Commit:**
```bash
# Run pre-commit hooks
pre-commit run --all-files

# Run tests
pytest --cov=sha

# Format code
black sha/ tests/ && isort sha/ tests/
```

---

## Branch Strategy

### Single Main Branch Workflow

**Philosophy:** Simple, linear history for solo developer

**Structure:**
- `main` - Production-ready code
- Remote: `origin/main`
- No feature branches (work directly on main)
- Tag releases: `v1.0.0`, `v1.1.0`, etc.

**Rationale:**
- Solo developer = no merge conflicts
- Linear history easier to understand
- Simpler workflow, less overhead
- Can always revert specific commits

### When to Branch (Rare)

**Only create branches for:**
- Experimental features (might be abandoned)
- Major refactoring (want to preserve stable main)
- Hotfixes for tagged releases

**Example:**
```bash
# Experimental work
git checkout -b experiment/new-approach
# ... work ...
git checkout main  # Return to main if abandoned

# If successful, merge back
git merge experiment/new-approach
git branch -d experiment/new-approach
```

---

## Commit Message Format

### Structure

**Imperative Mood (Required):**
```
✅ Add CSP bypass detection
✅ Fix HSTS max-age validation
✅ Update documentation for new headers
✅ Remove deprecated planning files

❌ Added CSP bypass detection
❌ Fixed bug
❌ Updates
```

**Descriptive Subject (50-60 chars):**
```
✅ Sprint 5: Enhance Permissions-Policy with risk categorization
✅ Add comprehensive tests for COEP/COOP interaction (23 tests)
✅ Fix broken documentation links in architecture directory

❌ Update code
❌ Fix bug
❌ Changes
```

### Real Examples from This Repository

**Sprint-Based Commits:**
```
Mark Sprint 5 as COMPLETED - All enhancement sprints finished (100%)

Sprint 5 (Part 1): Enhance Permissions-Policy analyzer with risk categorization

Sprint 4: Add cross-origin isolation validator (COEP + COOP interaction)

Add Cache-Control analyzer enhancements (Sprint 3): 3 new security features

Add Set-Cookie analyzer enhancements (Sprint 2): 4 new security features
```

**Feature Additions:**
```
Add CSP bypass detection and enhancement planning documentation

Add pytest fixtures and comprehensive real-world header tests

Enable multiple Set-Cookie header capture and analysis

Add Priority 1 & 2 security headers: Set-Cookie, Cache-Control, Expect-CT + Enhanced CSP
```

**Documentation:**
```
Add comprehensive documentation for Cache-Control Sprint 3 enhancements

Complete documentation enhancement: Phases 4-6 implementation & accuracy fixes

Fix broken documentation links in architecture directory
```

**Improvements:**
```
Add comprehensive robustness fixes and new features (14 improvements)

Perfect GitHub Actions with security and performance improvements
```

### Message Components

**Subject Line:**
- Verb (Add, Fix, Update, Remove, Refactor, etc.)
- What was changed
- Optional scope in parentheses: (Sprint N), (Phase N)
- Numbered improvements: "14 improvements", "23 tests"

**Body (Optional):**
- Extended explanation if subject isn't sufficient
- Why the change was made
- What problem it solves
- Breaking changes noted

**Footer:**
```
🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

---

## Sprint-Based Organization

### Pattern for Multi-Step Work

**Sprint Tracking:**
```
Sprint N: <Primary Goal>

Deliverables:
- Feature 1
- Feature 2
- Feature 3

Files Modified:
- path/to/file1.py
- path/to/file2.py
```

**Examples from This Project:**

**Sprint 5 (Permissions-Policy):**
```
Sprint 5 (Part 1): Enhance Permissions-Policy analyzer with risk categorization

- Expanded feature tracking from 7 to 19 features (+171%)
- 3-tier risk categorization (HIGH/MEDIUM/LOW)
- Deprecated Feature-Policy name detection
- 100% test compatibility maintained
```

**Sprint 4 (Cross-Origin Isolation):**
```
Sprint 4: Add cross-origin isolation validator (COEP + COOP interaction)

- Cross-header interaction validator for COEP + COOP
- SharedArrayBuffer eligibility detection
- Full isolation vs credentialless detection
- 23 new tests (100% coverage)
```

### Sprint Completion Commits

```
Mark Sprint N as COMPLETED - <Achievement summary>

Examples:
- Mark Sprint 5 as COMPLETED - All enhancement sprints finished (100%)
- Complete Sprint 3 - Cache-Control security features fully implemented
```

---

## Co-Authoring with Claude

### Format for AI-Assisted Commits

**When to Use:**
- Code written/suggested by Claude
- Documentation created with Claude
- Features designed collaboratively

**Footer Format:**
```
🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

**Full Example:**
```bash
git commit -m "$(cat <<'EOF'
Add comprehensive tests for new security headers (Permissions-Policy, COEP, COOP, CORP)

This commit adds 45 tests covering the four headers added in Phase 2:
- Permissions-Policy: 16 tests (parsing and analysis)
- Cross-Origin-Embedder-Policy: 9 tests
- Cross-Origin-Opener-Policy: 10 tests
- Cross-Origin-Resource-Policy: 10 tests

Tests cover:
- Missing header scenarios
- Valid and invalid values
- Case-insensitive parsing
- All status levels (good/acceptable/bad/missing)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Commit Scope

### When to Commit

**Commit Frequency:**
- ✅ After completing a logical unit of work
- ✅ When all tests pass
- ✅ After documentation updates for code changes
- ❌ Don't commit broken code
- ❌ Don't commit commented-out code
- ❌ Don't batch unrelated changes

**Logical Units:**
```
✅ Good: Add new analyzer (implementation + tests + docs)
✅ Good: Fix bug (code fix + test for bug + docs if needed)
✅ Good: Sprint completion (all features for sprint)

❌ Bad: Half-implemented feature
❌ Bad: Multiple unrelated fixes in one commit
❌ Bad: Code changes without updating related docs
```

### What to Include

**Single Commit Should Include:**
1. Code changes
2. Related test updates
3. Documentation updates
4. Configuration changes (if needed)

**Example:**
```
Add HSTS analyzer
├── sha/analyzers/hsts.py           # Implementation
├── sha/analyzers/__init__.py       # Registration
├── tests/analyzers/test_hsts.py    # Tests
├── docs/headers/hsts.md            # Documentation
└── docs/analyzer-reference.md      # Reference update
```

---

## Git Hooks (Pre-Commit)

### Configuration (.pre-commit-config.yaml)

**Hooks Run Before Every Commit:**
1. **black** - Code formatting
2. **isort** - Import sorting
3. **flake8** - Linting
4. **mypy** - Type checking (excludes tests)
5. **bandit** - Security scanning
6. **File checks** - Trailing whitespace, line endings, merge conflicts

### Installation

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

### Bypassing Hooks (Emergency Only)

```bash
# Skip hooks (NOT RECOMMENDED)
git commit --no-verify -m "Emergency hotfix"

# Better: Fix the issues hooks caught
pre-commit run --all-files
# Fix reported issues
git add .
git commit -m "Fix linting and formatting issues"
```

---

## Release Process

### Versioning (Semantic Versioning)

**Format:** `vMAJOR.MINOR.PATCH`

**Examples:**
- `v1.0.0` - Initial release
- `v1.1.0` - New features (backward compatible)
- `v1.0.1` - Bug fixes
- `v2.0.0` - Breaking changes

### Creating a Release

**1. Update Version:**
```python
# sha/__init__.py
__version__ = "1.1.0"
```

**2. Update CHANGELOG.md:**
```markdown
## [1.1.0] - 2026-01-01

### Added
- Permissions-Policy risk categorization
- Cross-origin isolation validator

### Changed
- Improved CSP bypass detection

### Fixed
- HSTS max-age validation edge case
```

**3. Commit and Tag:**
```bash
git add sha/__init__.py CHANGELOG.md
git commit -m "Release v1.1.0"
git tag -a v1.1.0 -m "Release v1.1.0: Enhanced Permissions-Policy and cross-origin isolation"
git push origin main --tags
```

**4. GitHub Release:**
- Create release from tag on GitHub
- Include CHANGELOG excerpt
- Attach built package (optional)

---

## Recovery Patterns

### Fixing Mistakes (Without Force Push)

**Wrong Commit Message:**
```bash
# If commit not pushed yet
git commit --amend -m "Corrected message"

# If already pushed (create new commit)
git revert HEAD
git commit -m "Fix: Correct implementation of X"
```

**Forgot to Add Files:**
```bash
# If commit not pushed
git add forgotten-file.py
git commit --amend --no-edit

# If already pushed
git add forgotten-file.py
git commit -m "Add missing file for previous commit"
```

**Want to Undo Last Commit:**
```bash
# Keep changes, undo commit
git reset --soft HEAD~1

# Discard changes entirely (DANGEROUS)
git reset --hard HEAD~1  # Only if not pushed!
```

### Never Force Push to Main

**❌ NEVER:**
```bash
git push --force origin main
git push -f origin main
```

**Why:** Destroys history for collaborators (including future you)

**Instead:** Use `git revert` to create new commits that undo changes

---

## Common Workflows

### Daily Development

```bash
# Start work
git pull origin main

# Make changes
# ... edit files ...

# Check status
git status

# Run tests and checks
pytest --cov=sha
pre-commit run --all-files

# Stage changes
git add sha/analyzers/new_feature.py
git add tests/analyzers/test_new_feature.py
git add docs/headers/new-feature.md

# Commit
git commit -m "Add new feature analyzer with comprehensive tests"

# Push
git push origin main
```

### Sprint Workflow

```bash
# Plan sprint (create TODO)
echo "Sprint N: <goals>" > TODO.md

# Work on sprint items
# ... implement features ...
git commit -m "Sprint N (Part 1): <feature>"

# ... more work ...
git commit -m "Sprint N (Part 2): <feature>"

# Complete sprint
git commit -m "Mark Sprint N as COMPLETED - <summary>"
rm TODO.md  # Or archive
```

### Hotfix Workflow

```bash
# Create hotfix branch from tag
git checkout -b hotfix/v1.0.1 v1.0.0

# Fix bug
# ... edit files ...
git commit -m "Fix critical security issue in HSTS validator"

# Update version
# Edit sha/__init__.py: __version__ = "1.0.1"
git commit -m "Bump version to 1.0.1"

# Tag release
git tag -a v1.0.1 -m "Hotfix: HSTS validation issue"

# Merge back to main
git checkout main
git merge hotfix/v1.0.1

# Push everything
git push origin main --tags
git branch -d hotfix/v1.0.1
```

---

## Solo Developer Best Practices

### Efficient Git Usage

**Time-Savers:**
- Commit early, commit often (easy to revert)
- Use descriptive messages (future you will thank you)
- Let pre-commit hooks catch issues (don't waste time on formatting)
- Keep commits focused (easier to understand history)

**When to Skip Rules:**
- Experimental branches (commit however you want, squash before merging)
- Local-only commits (clean up before pushing)

### Commit Message Quality

**Good Enough > Perfect:**
```
✅ Acceptable: "Add CSP bypass detection"
✅ Better: "Add CSP bypass detection (15 patterns identified)"
✅ Best: "Add CSP bypass detection and vulnerability documentation

Implements detection for 15 common CSP bypass patterns including:
- Base tag injection
- Unsafe-inline with nonces
- JSONP endpoints
- Angular template injection

Includes comprehensive tests and attack scenario documentation."
```

---

## Summary

**Key Principles:**

1. **Imperative Mood:** "Add" not "Added"
2. **Descriptive:** Explain what and why
3. **Sprint-Based:** Group related work with clear completion markers
4. **Single Main Branch:** Keep it simple
5. **Pre-Commit Hooks:** Let automation catch issues
6. **Co-Author Claude:** Credit AI assistance appropriately
7. **Never Force Push:** Use revert instead

**Quick Commands:**
```bash
# Before commit
pre-commit run --all-files
pytest --cov=sha

# Commit with message
git commit -m "Add feature X with tests and docs"

# Push
git push origin main

# Tag release
git tag -a v1.1.0 -m "Release 1.1.0"
git push origin main --tags
```

**See Also:**
- [python-code-standards.md](python-code-standards.md) - What to commit
- [testing-standards.md](testing-standards.md) - Tests before commit
- [documentation-standards.md](documentation-standards.md) - Docs with code changes

---

**Last Updated:** 2026-01-01
**Current Branch:** main
**Latest Tag:** v1.0.0
