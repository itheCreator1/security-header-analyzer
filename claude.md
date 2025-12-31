# Claude Code Development Guide

This document contains prompts and guidance for working with Claude Code on the Security Header Analyzer project.

---

## 📋 Current Enhancement Plan

**Status:** Planning Complete
**Plan File:** [ENHANCEMENT_PLAN.md](ENHANCEMENT_PLAN.md)
**Strategy:** Sharpen existing analyzers (quality over quantity)

### Quick Reference: Priority Enhancements

**🔴 Phase 1A - High Impact (Start Here):**
1. **CSP Analyzer** - Add bypass detection, report validation, directive syntax
2. **Set-Cookie Analyzer** - Add prefix validation (`__Secure-`, `__Host-`), scope analysis
3. **Cache-Control Analyzer** - Add conflict detection, response-type awareness

**🟡 Phase 1B - Secondary:**
4. **COEP/COOP/CORP** - Cross-header interaction validation
5. **Permissions-Policy** - Expand feature tracking

**🟢 Phase 1C - Refinement:**
6. HSTS, X-Frame-Options, Referrer-Policy minor improvements

---

## 🚀 Ready-to-Use Prompts

### Starting a New Enhancement

```
I want to start implementing [CSP/Set-Cookie/Cache-Control] analyzer enhancements
from ENHANCEMENT_PLAN.md. Please:

1. Review the current implementation in sha/analyzers/[analyzer].py
2. Identify the specific enhancements from the plan
3. Create a detailed implementation plan with:
   - Code changes required
   - New helper functions needed
   - Test cases to add
   - Documentation updates needed

Let's start with [specific enhancement, e.g., "CSP bypass detection"].
```

### Implementing CSP Bypass Detection

```
Implement CSP bypass detection for the CSP analyzer following ENHANCEMENT_PLAN.md:

Requirements:
- Detect 10+ common CSP bypass patterns
- Add helper function check_csp_bypasses()
- Return findings with HIGH severity for bypasses
- Add comprehensive tests (15+ test cases)
- Update docs/analyzer-reference.md
- Update docs/headers/content-security-policy.md

Reference existing CSP analyzer patterns in sha/analyzers/csp.py.
Maintain 97%+ test coverage.
```

### Implementing Set-Cookie Prefix Validation

```
Implement cookie prefix validation for Set-Cookie analyzer per ENHANCEMENT_PLAN.md:

Requirements:
- Validate __Secure- prefix (must have Secure attribute)
- Validate __Host- prefix (must have Secure, no Domain, Path=/)
- Add helper function _validate_cookie_prefix()
- Integration with existing _analyze_single_cookie()
- Add 10+ test cases covering all prefix scenarios
- Update documentation

Follow existing Set-Cookie patterns in sha/analyzers/set_cookie.py.
```

### Implementing Cache-Control Conflict Detection

```
Add directive conflict detection to Cache-Control analyzer per ENHANCEMENT_PLAN.md:

Requirements:
- Detect conflicting directive pairs:
  - public + private
  - no-store + max-age
  - no-cache + immutable
- Add helper function _detect_directive_conflicts()
- Return BAD status with clear conflict messages
- Add 8+ test cases for all conflict combinations
- Create docs/headers/cache-control.md

Reference existing cache_control.py structure.
```

### Cross-Origin Isolation Validation

```
Implement cross-header interaction validation for COEP/COOP/CORP per ENHANCEMENT_PLAN.md:

Requirements:
- Create sha/analyzers/cross_origin_validator.py
- Implement validate_cross_origin_isolation() function
- Detect SharedArrayBuffer eligibility (COEP: require-corp + COOP: same-origin)
- Detect credentialless isolation
- Integrate into sha/analyzer.py after individual analyzers
- Add 12+ integration tests
- Update all three header docs

This is a new cross-analyzer coordination pattern.
```

### Testing Strategy

```
Create comprehensive tests for [enhancement name] following these guidelines:

Test Coverage:
- Happy path tests (valid configurations)
- Edge case tests (boundary conditions)
- Negative tests (invalid/malformed input)
- Integration tests (cross-header interactions if applicable)

Requirements:
- Use pytest fixtures for common test data
- Parametrize tests where appropriate
- Maintain 100% coverage for new code
- Follow existing test patterns in tests/test_*.py

Add tests to tests/test_[analyzer].py.
```

### Documentation Updates

```
Update documentation for [enhancement name] following the existing framework:

Files to update:
1. docs/analyzer-reference.md (quick reference)
   - Update "How It Works" section
   - Add new validation examples
   - Keep concise

2. docs/headers/[header-name].md (detailed guide)
   - Add "Enhanced Validation" section
   - Include attack scenarios
   - Add configuration examples with ✅ ⚠️ ❌ markers

3. CHANGELOG.md
   - Add to [Unreleased] section
   - Format: "**[Header]:** [Enhancement description]"

Follow existing documentation patterns and use consistent terminology.
```

---

## 🏗️ Architecture Context

### Project Structure
```
sha/
├── analyzers/           # 15 security header analyzers
│   ├── __init__.py      # ANALYZER_REGISTRY, CONFIG_REGISTRY
│   ├── csp.py           # Content-Security-Policy (500+ lines)
│   ├── set_cookie.py    # Set-Cookie (460 lines, multi-instance)
│   ├── cache_control.py # Cache-Control (simple parser)
│   ├── coep.py          # Cross-Origin-Embedder-Policy
│   ├── coop.py          # Cross-Origin-Opener-Policy
│   ├── corp.py          # Cross-Origin-Resource-Policy
│   └── ...              # 9 other analyzers
├── analyzer.py          # Analysis orchestration
├── fetcher.py           # HTTP header fetching (SSRF protection)
├── reporter.py          # Report generation (text/JSON)
├── config.py            # Configuration & exceptions
└── main.py              # CLI entry point

tests/                   # 494 tests, 97% coverage
docs/
├── analyzer-reference.md       # Quick reference
├── headers/                    # Individual header guides (15 files)
├── architecture/               # Architecture documentation (8 files)
└── [guides]                    # Usage, testing, deployment
```

### Key Patterns

**Registry Pattern:**
- All analyzers registered in `ANALYZER_REGISTRY`
- All configs in `CONFIG_REGISTRY`
- Dynamic dispatch in `analyzer.py`

**Analyzer Contract:**
```python
def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Returns Finding dictionary with:
    - header_name: str
    - status: "good" | "acceptable" | "bad" | "missing"
    - severity: "critical" | "high" | "medium" | "low" | "info"
    - message: str
    - actual_value: Optional[str]
    - recommendation: Optional[str]
    """
```

**Helper Function Pattern:**
```python
def _parse_header_value(value: str) -> Dict[str, Any]:
    """Internal helper for parsing."""

def _validate_specific_aspect(parsed_data: Dict) -> bool:
    """Specific validation check."""
```

---

## 📊 Quality Metrics

**Current State (from ENHANCEMENT_PLAN.md):**
- CSP: 9/10 (target: 10/10)
- Set-Cookie: 8/10 (target: 9/10)
- Cache-Control: 6/10 (target: 8/10)
- COEP/COOP/CORP: 4/10 each (target: 7/10)
- Permissions-Policy: 7/10 (target: 8/10)

**Test Coverage:**
- Current: 97% (494 tests)
- Target: Maintain 97%+
- Add 100+ tests across all enhancements

---

## 🎯 Implementation Guidelines

### Code Style
- Follow existing patterns in each analyzer
- Use type hints throughout
- Document attack scenarios in comments
- Normalize values (lowercase, strip whitespace)
- Use helper functions for complex logic

### Testing Requirements
- 100% coverage for new code
- Parametrized tests for multiple scenarios
- Test fixtures for complex data
- Integration tests for cross-header features

### Documentation Standards
- Update analyzer-reference.md (concise)
- Create/update detailed header docs
- Use consistent markers: ✅ ⚠️ ❌
- Include attack scenarios
- Add configuration examples
- Update CHANGELOG.md

### Backward Compatibility
- ✅ No changes to CONFIG structure
- ✅ No changes to Finding schema
- ✅ No breaking API changes
- ✅ Only additive changes

---

## 🔧 Development Commands

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_csp.py -v

# Run with coverage
pytest --cov=sha --cov-report=html

# Run specific test
pytest tests/test_csp.py::TestCSPAnalyzer::test_bypass_detection -v

# Type checking
mypy sha/

# Code formatting
black sha/ tests/
isort sha/ tests/

# Linting
flake8 sha/ tests/
```

---

## 📝 Sprint Planning

### Sprint 1: CSP Deep Dive (Weeks 1-2)
- [ ] Implement bypass detection (10+ patterns)
- [ ] Add report endpoint validation
- [ ] Add directive syntax validation
- [ ] Add nonce/hash quality warnings
- [ ] Add frame-ancestors conflict detection
- [ ] Add data URI detection
- [ ] Write 30+ new test cases
- [ ] Update documentation

### Sprint 2: Cookie Security (Week 3)
- [ ] Implement __Secure- prefix validation
- [ ] Implement __Host- prefix validation
- [ ] Add domain/path scope analysis
- [ ] Add cookie name pattern analysis
- [ ] Add SameSite=None frequency warnings
- [ ] Write 15+ test cases
- [ ] Update documentation

### Sprint 3: Cache Security (Week 4)
- [ ] Implement directive conflict detection
- [ ] Add response-type awareness
- [ ] Add privacy leak detection
- [ ] Add stale-while-revalidate support
- [ ] Create docs/headers/cache-control.md
- [ ] Write 12+ test cases
- [ ] Update documentation

### Sprint 4: Cross-Origin (Weeks 5-6)
- [ ] Create cross_origin_validator.py
- [ ] Implement SharedArrayBuffer eligibility
- [ ] Add isolation level detection
- [ ] Integrate into analyzer.py
- [ ] Write 12+ integration tests
- [ ] Update all 3 header docs

### Sprint 5: Polish (Week 7)
- [ ] Enhance Permissions-Policy
- [ ] Refine HSTS/X-Frame-Options/Referrer-Policy
- [ ] Documentation consistency pass
- [ ] Final testing
- [ ] Update README.md with new features

---

## 🤝 Collaboration Tips

### When Working with Claude

**Be specific about scope:**
```
"Implement just the CSP bypass detection, not the full CSP enhancement"
```

**Request incremental changes:**
```
"First, add the helper function _detect_csp_bypasses().
We'll add the integration and tests in the next step."
```

**Ask for test-first approach:**
```
"Write the tests for cookie prefix validation first,
then implement the validation logic to make them pass."
```

**Request documentation updates:**
```
"Now update the documentation for this enhancement,
following the existing patterns in docs/analyzer-reference.md"
```

---

## 📚 Reference Documentation

- [ENHANCEMENT_PLAN.md](ENHANCEMENT_PLAN.md) - Full enhancement strategy
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development workflow
- [docs/architecture/README.md](docs/architecture/README.md) - Architecture overview
- [docs/architecture/extensibility-guide.md](docs/architecture/extensibility-guide.md) - Adding analyzers
- [docs/analyzer-reference.md](docs/analyzer-reference.md) - Analyzer specifications

---

## ⚡ Quick Wins (If Time Constrained)

If you need to deliver value quickly, implement these in order:

**Week 1: CSP Bypass Detection**
- 10 common CSP bypasses
- Highest security value
- ~80% of CSP enhancement value

**Week 2: Set-Cookie Prefix Validation**
- __Secure- and __Host- validation
- High visibility feature
- Simple to implement

**Week 3: Cache-Control Conflicts**
- Detect directive conflicts
- Clear security value
- Low complexity

---

## 🎓 Learning Resources

**CSP Bypass Research:**
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [CSP Bypass Techniques](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass)

**Cookie Security:**
- [Cookie Prefixes RFC](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cookie-prefixes)
- [SameSite Cookie Specification](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)

**Cross-Origin Isolation:**
- [SharedArrayBuffer Requirements](https://web.dev/cross-origin-isolation-guide/)
- [COOP/COEP Explained](https://web.dev/why-coop-coep/)

---

**Last Updated:** 2025-12-31
**Plan Version:** 1.0
**Project Version:** 1.0.0
