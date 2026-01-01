# Testing Standards

> Testing requirements and patterns for the Security Header Analyzer project

---

## Quick Reference

**Coverage Requirements:**
- Overall: **97%+** maintained
- New analyzers: **100%** required
- Tests run before every commit

**Naming Convention:**
- Files: `test_*.py`
- Classes: `Test*` (e.g., `TestParseHSTS`, `TestAnalyzeHSTS`)
- Functions: `test_*` (e.g., `test_analyze_missing`, `test_parse_full`)

**Test Organization:**
- Unit tests: `tests/analyzers/test_<analyzer>.py`
- Integration tests: `tests/test_integration.py`
- Real-world tests: `tests/test_real_world_headers.py`

**Run Tests:**
```bash
# All tests with coverage
pytest --cov=sha --cov-report=term-missing

# Specific test file
pytest tests/analyzers/test_hsts.py -v

# Single test function
pytest tests/analyzers/test_hsts.py::TestAnalyzeHSTS::test_analyze_missing -v
```

---

## Test Organization

### Directory Structure

```
tests/
├── conftest.py                      # Shared fixtures (220 lines)
├── fixtures/
│   └── headers/                     # Real-world header JSON files
│       ├── github_headers.json
│       ├── google_headers.json
│       └── ...
│
├── analyzers/                       # Analyzer unit tests
│   ├── __init__.py
│   ├── test_hsts.py                # HSTS analyzer tests
│   ├── test_csp.py                 # CSP analyzer tests (780 lines!)
│   ├── test_set_cookie.py          # Set-Cookie tests (705 lines)
│   └── ... (12 total analyzer test files)
│
├── test_integration.py              # CLI workflow tests (407 lines)
├── test_edge_cases.py               # Edge cases (521 lines)
├── test_fetcher.py                  # HTTP fetching (525 lines)
├── test_reporter.py                 # Report generation (470 lines)
├── test_config.py                   # Configuration (296 lines)
├── test_cross_origin_validator.py   # Cross-origin isolation (374 lines)
├── test_analyze_headers.py          # Header analysis pipeline (111 lines)
└── test_real_world_headers.py       # Production headers (223 lines)
```

**Total:** 582 tests across 19 files, 6,266+ lines of test code

---

## Class-Based Test Organization

### Pattern: Separate Classes for Parsing vs Analysis

**Example** ([tests/analyzers/test_hsts.py](../../tests/analyzers/test_hsts.py)):

```python
class TestParseHSTS:
    """Test HSTS header parsing logic."""

    def test_parse_hsts_full(self):
        """Test parsing HSTS with all directives."""
        result = parse_hsts("max-age=31536000; includeSubDomains; preload")

        assert result["max_age"] == 31536000
        assert result["include_subdomains"] is True
        assert result["preload"] is True

    def test_parse_hsts_minimal(self):
        """Test parsing HSTS with only max-age."""
        result = parse_hsts("max-age=31536000")

        assert result["max_age"] == 31536000
        assert result["include_subdomains"] is False
        assert result["preload"] is False

    def test_parse_hsts_case_insensitive(self):
        """Test that parsing is case-insensitive."""
        result = parse_hsts("MAX-AGE=31536000; INCLUDESUBDOMAINS")

        assert result["max_age"] == 31536000
        assert result["include_subdomains"] is True


class TestAnalyzeHSTS:
    """Test HSTS header analysis and validation."""

    def test_analyze_missing(self):
        """Test analysis when HSTS header is missing."""
        result = analyze(None)

        assert result["header_name"] == "Strict-Transport-Security"
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == "critical"
        assert result["actual_value"] is None
        assert result["recommendation"] is not None

    def test_analyze_perfect(self):
        """Test analysis with perfect HSTS configuration."""
        result = analyze("max-age=31536000; includeSubDomains; preload")

        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"
        assert result["recommendation"] is None

    def test_analyze_too_short_max_age(self):
        """Test analysis with max-age below threshold."""
        result = analyze("max-age=86400")  # 1 day, too short

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "high"
        assert "max-age" in result["message"].lower()
```

**Benefits:**
- Clear separation: parsing logic vs validation logic
- Easy to locate specific test types
- Logical grouping of related tests

---

## Fixture Patterns

### Central Fixture Hub ([tests/conftest.py](../../tests/conftest.py))

**Basic Finding Fixtures:**
```python
@pytest.fixture
def sample_finding_good():
    """Sample finding with GOOD status."""
    return {
        "header_name": "Test-Header",
        "status": STATUS_GOOD,
        "severity": "info",
        "message": "Header properly configured",
        "actual_value": "test-value",
        "recommendation": None,
    }

@pytest.fixture
def sample_finding_missing():
    """Sample finding with MISSING status."""
    return {
        "header_name": "Test-Header",
        "status": STATUS_MISSING,
        "severity": "critical",
        "message": "Header is missing",
        "actual_value": None,
        "recommendation": "Add the header",
    }
```

**Real-World Header Fixtures:**
```python
@pytest.fixture
def github_headers():
    """Actual headers from GitHub.com (known for excellent security)."""
    # Loaded from tests/fixtures/headers/github_headers.json
    return {
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "content-security-policy": "default-src 'none'; ...",
        "x-frame-options": "deny",
        # ... actual GitHub headers
    }

@pytest.fixture
def weak_headers():
    """Headers with weak security posture."""
    return {
        "strict-transport-security": "max-age=300",  # Too short
        # Missing critical headers
    }
```

**Factory Fixtures:**
```python
@pytest.fixture
def mock_response_factory():
    """Factory for creating mock HTTP responses."""
    def _create(status_code=200, headers=None, url="https://example.com"):
        response = Mock()
        response.status_code = status_code
        response.headers = headers or {}
        response.url = url
        response.history = []
        return response
    return _create

# Usage in tests:
def test_something(mock_response_factory):
    response = mock_response_factory(status_code=404, headers={"x-frame-options": "DENY"})
    # ... test logic
```

**Fixture Export:**
```python
# At end of conftest.py - explicit exports for IDE support
__all__ = [
    "sample_finding_good",
    "sample_finding_missing",
    "github_headers",
    "mock_response_factory",
    # ... all fixtures
]
```

---

## Naming Conventions

### Test Function Names

**Pattern:** `test_<component>_<condition>_<expected_result>`

**Examples:**
```python
# ✅ Good: Descriptive, clear intent
def test_analyze_hsts_missing():
    """Test HSTS analysis when header is missing."""

def test_parse_csp_multiple_directives():
    """Test CSP parsing with multiple directives."""

def test_main_network_error_exit_code_1():
    """Test CLI exits with code 1 on network error."""

# ❌ Avoid: Too vague
def test_hsts():
    pass

def test_error():
    pass
```

### Test Docstrings

**Required:** Every test function needs a docstring explaining what's being tested

**Pattern:**
```python
def test_analyze_hsts_max_age_too_short(self):
    """
    Test HSTS analysis flags max-age below 126 days as insecure.

    Max-age values below 10886400 seconds (126 days) should return
    STATUS_BAD with high severity.
    """
    result = analyze("max-age=86400")  # 1 day
    assert result["status"] == STATUS_BAD
```

---

## Test Categories

### 1. Unit Tests (Analyzer-Specific)

**Location:** `tests/analyzers/test_<analyzer>.py`

**Purpose:** Test individual analyzer parsing and validation logic

**Coverage:**
- Missing header scenarios
- Valid configurations (good, acceptable)
- Invalid configurations (bad)
- Edge cases (empty, whitespace, malformed)
- Case insensitivity
- All directive combinations

**Example Structure:**
```python
class TestParseHSTS:
    def test_parse_hsts_full(self): ...
    def test_parse_hsts_minimal(self): ...
    def test_parse_hsts_case_insensitive(self): ...
    def test_parse_hsts_whitespace(self): ...
    def test_parse_hsts_invalid_max_age(self): ...

class TestAnalyzeHSTS:
    def test_analyze_missing(self): ...
    def test_analyze_perfect(self): ...
    def test_analyze_acceptable(self): ...
    def test_analyze_bad(self): ...
    def test_analyze_edge_cases(self): ...
```

### 2. Integration Tests

**Location:** `tests/test_integration.py`

**Purpose:** Test CLI workflows end-to-end

**Coverage:**
- Argument parsing
- Exit codes for different scenarios
- Output formatting (text vs JSON)
- Error handling flows

**Example:**
```python
def test_main_success_all_headers_present(capsys, mock_session_factory):
    """Test successful analysis with all headers present."""
    with patch("sys.argv", ["sha", "https://example.com"]), \
         patch("requests.Session") as mock_session_class:

        mock_response = mock_session_factory(
            status_code=200,
            headers={
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "x-frame-options": "DENY",
                # ... all headers
            }
        )
        mock_session = Mock()
        mock_session.head.return_value = mock_response
        mock_session_class.return_value = mock_session

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0
```

### 3. Real-World Tests

**Location:** `tests/test_real_world_headers.py`

**Purpose:** Validate against actual production headers

**Coverage:**
- GitHub.com (excellent security)
- Google.com (strong security)
- Cloudflare.com
- Mozilla.org
- AWS
- Weak security sites

**Example:**
```python
def test_github_headers_analysis(github_headers):
    """
    Test analysis of GitHub's actual security headers.

    GitHub is known for excellent security headers, so we expect
    minimal critical/high severity findings.
    """
    findings = analyze_headers(github_headers)

    # GitHub should have all critical headers
    hsts_finding = next(f for f in findings if "HSTS" in f["header_name"])
    assert hsts_finding["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]

    # Count critical issues (should be zero for GitHub)
    critical_findings = [f for f in findings if f["severity"] == "critical"]
    assert len(critical_findings) == 0
```

### 4. Edge Case Tests

**Location:** `tests/test_edge_cases.py`

**Purpose:** Boundary conditions and unusual inputs

**Coverage:**
- Empty strings
- Very long values
- Unicode characters
- Special characters
- Duplicate headers
- Malformed values

**Example:**
```python
def test_analyze_empty_string():
    """Test analysis with empty string (not None)."""
    result = analyze("")
    # Should handle gracefully

def test_analyze_very_long_value():
    """Test analysis with extremely long header value."""
    long_value = "x" * 100000
    result = analyze(long_value)
    # Should not crash

def test_analyze_unicode():
    """Test analysis with Unicode characters."""
    result = analyze("max-age=31536000; 你好")
    # Should handle or reject gracefully
```

---

## Coverage Requirements

### Targets

**Overall Coverage:** 97%+ (currently maintained)
**New Analyzers:** 100% required

**Check Coverage:**
```bash
# Generate coverage report
pytest --cov=sha --cov-report=html --cov-report=term-missing

# View HTML report
open htmlcov/index.html

# Terminal output shows missing lines
```

### Coverage by Module Type

**Analyzers:** 100% (no exceptions)
```python
# Every code path must be tested
def analyze(value: Optional[str]) -> Finding:
    if value is None:           # ← Test this
        return missing_finding

    normalized = value.lower()

    if "good" in normalized:    # ← Test this
        return good_finding

    return bad_finding          # ← Test this
```

**Core Modules:** 95%+ acceptable
- `main.py`, `analyzer.py`, `fetcher.py`, `reporter.py`
- Some error handling paths may be hard to reach

**Utilities:** 90%+ acceptable
- Edge cases may be impractical to test

---

## Assertion Patterns

### Dictionary Assertions (Common for Findings)

```python
# ✅ Specific assertions on dict keys
result = analyze("max-age=31536000")

assert result["header_name"] == "Strict-Transport-Security"
assert result["status"] == STATUS_GOOD
assert result["severity"] == "info"
assert result["actual_value"] == "max-age=31536000"
assert result["recommendation"] is None

# ✅ Check for key presence
assert "message" in result

# ✅ Check substring in message
assert "properly configured" in result["message"].lower()
```

### List Assertions

```python
# ✅ Length check
findings = analyze_headers(headers)
assert len(findings) == 15  # All 15 headers analyzed

# ✅ Check for specific item
critical_findings = [f for f in findings if f["severity"] == "critical"]
assert len(critical_findings) > 0

# ✅ All items match condition
assert all(f["header_name"] for f in findings)  # All have header_name
```

### Boolean Assertions

```python
# ✅ Explicit boolean checks
assert result["include_subdomains"] is True   # Not == True
assert result["preload"] is False             # Not == False
```

---

## Mocking Strategy

### When to Mock

**DO Mock:**
- Network calls (`requests.Session`, `requests.get`)
- System calls (`socket.getaddrinfo`)
- File I/O (if not using temp files)
- `sys.exit`, `sys.argv` in CLI tests
- Time-dependent operations

**DON'T Mock:**
- Analyzer logic (test the real thing)
- Simple utility functions
- Data structures (use real dicts/lists)

### Mocking Patterns

**HTTP Requests (using `unittest.mock`):**
```python
from unittest.mock import Mock, patch

def test_fetch_headers_success():
    """Test successful header fetching."""
    with patch("requests.Session") as mock_session_class:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"x-frame-options": "DENY"}

        mock_session = Mock()
        mock_session.head.return_value = mock_response
        mock_session_class.return_value = mock_session

        headers = fetch_headers("https://example.com")

        assert headers["x-frame-options"] == "DENY"
        mock_session.head.assert_called_once()
```

**CLI Arguments:**
```python
def test_main_with_verbose_flag():
    """Test CLI with --verbose flag."""
    test_args = ["sha", "https://example.com", "--verbose"]

    with patch("sys.argv", test_args):
        # ... test logic
```

**Exit Codes:**
```python
def test_main_network_error_exit_code():
    """Test CLI exits with code 1 on network error."""
    with patch("sys.exit") as mock_exit:
        # ... simulate network error
        main()
        mock_exit.assert_called_once_with(1)
```

---

## Pytest Configuration

### pytest.ini

```ini
[pytest]
python_files = test_*.py
python_classes = Test*
python_functions = test_*
testpaths = tests
addopts = -v --strict-markers --tb=short --disable-warnings

markers =
    slow: marks tests as slow
    integration: marks tests as integration tests
    unit: marks tests as unit tests

minversion = 7.0
```

### Running Tests

**All tests:**
```bash
pytest
```

**With coverage:**
```bash
pytest --cov=sha --cov-report=term-missing
```

**Specific markers:**
```bash
pytest -m unit          # Only unit tests
pytest -m integration   # Only integration tests
pytest -m "not slow"    # Skip slow tests
```

**Verbose output:**
```bash
pytest -v               # Verbose
pytest -vv              # Extra verbose
pytest --tb=long        # Full tracebacks
```

**Stop on first failure:**
```bash
pytest -x
```

**Run last failed:**
```bash
pytest --lf
```

---

## Adding Tests for New Analyzers

### Step-by-Step Guide

**1. Create Test File** (`tests/analyzers/test_new_header.py`):

```python
"""Tests for New-Header analyzer."""

import pytest
from sha.analyzers.new_header import analyze, parse_new_header, HEADER_KEY, CONFIG
from sha.config import STATUS_GOOD, STATUS_BAD, STATUS_MISSING

class TestParseNewHeader:
    """Test New-Header parsing logic."""

    def test_parse_valid_value(self):
        """Test parsing valid header value."""
        result = parse_new_header("expected-value")
        assert result["parsed_field"] == "expected-value"

    def test_parse_empty(self):
        """Test parsing empty value."""
        result = parse_new_header("")
        assert result is not None

class TestAnalyzeNewHeader:
    """Test New-Header analysis."""

    def test_analyze_missing(self):
        """Test analysis when header is missing."""
        result = analyze(None)

        assert result["header_name"] == CONFIG["display_name"]
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == CONFIG["severity_missing"]
        assert result["actual_value"] is None
        assert result["recommendation"] is not None

    def test_analyze_good(self):
        """Test analysis with good configuration."""
        result = analyze("expected-value")

        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"
        assert result["recommendation"] is None

    def test_analyze_bad(self):
        """Test analysis with bad configuration."""
        result = analyze("wrong-value")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "high"
        assert result["recommendation"] is not None

    def test_analyze_edge_case_empty(self):
        """Test analysis with empty string."""
        result = analyze("")
        assert result["status"] in [STATUS_BAD, STATUS_MISSING]

    def test_analyze_case_insensitive(self):
        """Test that analysis is case-insensitive."""
        result_lower = analyze("expected-value")
        result_upper = analyze("EXPECTED-VALUE")
        assert result_lower["status"] == result_upper["status"]
```

**2. Run Tests:**
```bash
# Run new test file
pytest tests/analyzers/test_new_header.py -v

# Check coverage
pytest tests/analyzers/test_new_header.py --cov=sha.analyzers.new_header --cov-report=term-missing
```

**3. Verify 100% Coverage:**
- All branches covered
- All code paths tested
- Edge cases included

---

## Real-World Validation

### Creating Fixtures from Production Sites

**1. Capture Real Headers:**
```bash
# Using curl
curl -I https://github.com 2>&1 | grep -i ":" | tee tests/fixtures/headers/github_raw.txt

# Or using the tool itself
sha https://github.com --format json > tests/fixtures/headers/github_headers.json
```

**2. Add Fixture to conftest.py:**
```python
@pytest.fixture
def github_headers():
    """Actual headers from GitHub.com."""
    import json
    with open("tests/fixtures/headers/github_headers.json") as f:
        return json.load(f)
```

**3. Write Validation Test:**
```python
def test_github_headers_no_critical_issues(github_headers):
    """GitHub should have no critical security issues."""
    findings = analyze_headers(github_headers)
    critical = [f for f in findings if f["severity"] == "critical"]
    assert len(critical) == 0, f"Found critical issues: {critical}"
```

---

## Solo Developer Testing Workflow

### Efficient Testing Practices

**1. Run Tests Before Commits:**
```bash
# Quick check (unit tests only)
pytest tests/analyzers/ -m "not slow"

# Full check before push
pytest --cov=sha --cov-report=term-missing
```

**2. Use Pre-Commit Hooks:**
```yaml
# .pre-commit-config.yaml includes pytest
repos:
  - repo: local
    hooks:
      - id: pytest-check
        name: pytest
        entry: pytest
        language: system
        pass_filenames: false
        always_run: true
```

**3. Focus on Changed Code:**
```bash
# Run tests for specific module you changed
pytest tests/analyzers/test_hsts.py -v

# Run with coverage for that module only
pytest tests/analyzers/test_hsts.py --cov=sha.analyzers.hsts
```

**4. Watch Mode (for active development):**
```bash
# Using pytest-watch (install: pip install pytest-watch)
ptw -- --cov=sha
```

---

## Common Testing Patterns in This Project

### Pattern 1: Test Missing Header First

```python
def test_analyze_missing(self):
    """Always test missing header case first."""
    result = analyze(None)
    assert result["status"] == STATUS_MISSING
```

### Pattern 2: Test Good/Acceptable/Bad

```python
def test_analyze_good(self):
    result = analyze("perfect-config")
    assert result["status"] == STATUS_GOOD

def test_analyze_acceptable(self):
    result = analyze("ok-config")
    assert result["status"] == STATUS_ACCEPTABLE

def test_analyze_bad(self):
    result = analyze("weak-config")
    assert result["status"] == STATUS_BAD
```

### Pattern 3: Test Edge Cases

```python
def test_analyze_empty_string(self):
    result = analyze("")

def test_analyze_whitespace_only(self):
    result = analyze("   ")

def test_analyze_very_long(self):
    result = analyze("x" * 10000)
```

---

## Summary

**Key Testing Principles:**

1. **97%+ Coverage:** Non-negotiable for overall project
2. **100% for Analyzers:** Every new analyzer must have complete coverage
3. **Class-Based Organization:** Separate Parse* and Analyze* test classes
4. **Real-World Validation:** Test against actual production headers
5. **Descriptive Names:** `test_<component>_<condition>_<expected>`
6. **Comprehensive Fixtures:** Use conftest.py for shared fixtures
7. **Mock External Dependencies:** Network, system calls, never internal logic

**Quick Commands:**
```bash
# Run all tests
pytest

# With coverage
pytest --cov=sha --cov-report=term-missing

# Specific file
pytest tests/analyzers/test_hsts.py -v

# Watch mode
ptw -- --cov=sha
```

**See Also:**
- [python-code-standards.md](python-code-standards.md) - Code patterns being tested
- [debugging-practices.md](debugging-practices.md) - Debugging test failures
- [docs/testing-guide.md](../testing-guide.md) - User-facing testing guide

---

**Last Updated:** 2026-01-01
**Test Stats:** 582 tests, 6,266+ lines, 97%+ coverage
