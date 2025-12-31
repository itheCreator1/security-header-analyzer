# Testing Guide

## Overview

Security Header Analyzer has comprehensive test coverage (~96%) with 478 tests across unit, integration, and edge case scenarios. This guide explains how to run tests, write new tests, and maintain test quality.

## Running Tests

### Basic Test Execution

```bash
# Run all tests
pytest

# Verbose output
pytest -v

# Run specific test file
pytest tests/test_hsts.py

# Run specific test
pytest tests/test_hsts.py::TestHSTSAnalyzer::test_good_value

# Run tests matching pattern
pytest -k "test_hsts"
```

### With Coverage

```bash
# Generate coverage report
pytest --cov=sha --cov-report=term-missing

# Generate HTML coverage report
pytest --cov=sha --cov-report=html

# Open HTML report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### Test Markers

```bash
# Run only unit tests
pytest -m unit

# Skip slow tests
pytest -m "not slow"

# Run only integration tests
pytest -m integration
```

## Test Structure

### Directory Organization

```
tests/
├── conftest.py              # Shared fixtures
├── test_integration.py      # End-to-end CLI tests
├── test_analyzer.py         # Analyzer orchestration
├── test_fetcher.py          # HTTP fetcher tests
├── test_reporter.py         # Report formatting tests
├── test_config.py           # Configuration tests
├── test_hsts.py             # HSTS analyzer tests
├── test_xframe.py           # X-Frame-Options tests
├── test_content_type.py     # X-Content-Type-Options tests
├── test_csp.py              # CSP analyzer tests
├── test_referrer_policy.py  # Referrer-Policy tests
├── test_permissions_policy.py  # Permissions-Policy tests
├── test_coep.py             # COEP tests
├── test_coop.py             # COOP tests
├── test_corp.py             # CORP tests
└── test_edge_cases.py       # Edge cases and boundaries
```

## Writing Tests

### Test Class Structure

```python
import pytest
from sha.analyzers.hsts import analyze, CONFIG

class TestHSTSAnalyzer:
    """Tests for HSTS analyzer."""

    def test_missing_header(self):
        """Test when header is missing."""
        result = analyze(None)
        assert result["status"] == "missing"
        assert result["severity"] == CONFIG["severity_missing"]

    def test_good_value(self):
        """Test with good HSTS header."""
        result = analyze("max-age=31536000; includeSubDomains")
        assert result["status"] == "good"
        assert result["severity"] == "info"

    def test_short_max_age(self):
        """Test with insufficient max-age."""
        result = analyze("max-age=300")
        assert result["status"] == "bad"
        assert "too short" in result["message"].lower()
```

### Using Fixtures

```python
# In conftest.py
@pytest.fixture
def all_headers_good():
    """Fixture providing all headers with good values."""
    return {
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        # ...
    }

# In test file
def test_all_good_headers(all_headers_good):
    """Test analysis with all good headers."""
    findings = analyze_headers(all_headers_good)
    assert all(f["status"] == "good" for f in findings)
```

### Mocking HTTP Requests

```python
import pytest
from unittest.mock import Mock, patch

def test_fetch_headers_success():
    """Test successful header fetching."""
    with patch('sha.fetcher.requests.Session') as mock_session:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Strict-Transport-Security": "max-age=31536000"}
        mock_response.url = "https://example.com"
        mock_session.return_value.head.return_value = mock_response

        headers = fetch_headers("https://example.com")
        assert "strict-transport-security" in headers
```

## Writing Tests for New Analyzers

### Template

```python
import pytest
from sha.analyzers.your_header import analyze, CONFIG

class TestYourHeaderAnalyzer:
    """Tests for Your-Header analyzer."""

    def test_missing_header(self):
        """Test when header is missing."""
        result = analyze(None)
        assert result["status"] == "missing"
        assert result["severity"] == CONFIG["severity_missing"]
        assert result["recommendation"] is not None

    def test_good_value(self):
        """Test with valid header value."""
        result = analyze("good-value")
        assert result["status"] == "good"
        assert result["severity"] == "info"
        assert result["recommendation"] is None

    def test_bad_value(self):
        """Test with unsafe header value."""
        result = analyze("unsafe-value")
        assert result["status"] == "bad"
        assert result["severity"] in ["high", "medium"]
        assert result["recommendation"] is not None

    def test_case_insensitive(self):
        """Test case-insensitive parsing."""
        result1 = analyze("GOOD-VALUE")
        result2 = analyze("good-value")
        assert result1["status"] == result2["status"]

    def test_whitespace_handling(self):
        """Test with extra whitespace."""
        result = analyze("  good-value  ")
        assert result["status"] == "good"

    def test_empty_value(self):
        """Test with empty string."""
        result = analyze("")
        assert result["status"] == "bad"

    def test_actual_value_preserved(self):
        """Test that actual value is preserved (not lowercased)."""
        result = analyze("Good-Value")
        assert result["actual_value"] == "Good-Value"
```

### Required Test Coverage

- ✅ Missing header
- ✅ Good values (all variants)
- ✅ Bad values (all variants)
- ✅ Edge cases (empty, whitespace, case sensitivity)
- ✅ All validation rules from CONFIG
- ✅ Proper severity levels
- ✅ Recommendations present when needed

## Best Practices

### 1. Test Names

- Use descriptive names: `test_good_hsts_with_preload` not `test_1`
- Start with `test_` prefix
- Include what's being tested and expected outcome

### 2. Assertions

```python
# Good - specific assertions
assert result["status"] == "good"
assert "max-age" in result["message"]

# Bad - vague assertions
assert result
assert len(result) > 0
```

### 3. Test Independence

```python
# Good - each test is independent
def test_feature_a():
    data = create_test_data()
    result = analyze(data)
    assert result["status"] == "good"

# Bad - tests depend on each other
def test_feature_a():
    global result
    result = analyze(data)

def test_feature_b():
    assert result["value"] == "expected"
```

### 4. Use Fixtures for Common Setup

```python
@pytest.fixture
def mock_headers():
    return {"strict-transport-security": "max-age=31536000"}

def test_with_headers(mock_headers):
    findings = analyze_headers(mock_headers)
    # ... assertions
```

## Continuous Integration

Tests run automatically on:
- Every push to main/develop
- Every pull request
- Python 3.8, 3.9, 3.10, 3.11, 3.12

### CI Requirements

- ✅ All tests must pass
- ✅ Coverage must be ≥ 90%
- ✅ No flake8 errors
- ✅ Type checking passes (mypy)
- ✅ Security scan passes (bandit)

## Coverage Requirements

### Minimum Coverage

- Overall: 90%
- Per file: 80%
- New code: 95%

### Excluded from Coverage

- `if __name__ == "__main__"` blocks
- Type checking blocks (`if TYPE_CHECKING:`)
- Abstract methods
- Debug code marked with `# pragma: no cover`

## Debugging Tests

### Print Debug Information

```python
def test_with_debug():
    result = analyze("test-value")
    print(f"Result: {result}")  # Use pytest -s to see output
    assert result["status"] == "good"
```

### Use pytest debugger

```bash
# Drop into debugger on failure
pytest --pdb

# Drop into debugger at start of test
pytest --trace
```

### Isolate Failing Test

```bash
# Run only the failing test
pytest tests/test_hsts.py::TestHSTSAnalyzer::test_failing_case -v
```

## Performance Testing

### Timing Tests

```bash
# Show slowest tests
pytest --duration=10
```

### Mark Slow Tests

```python
@pytest.mark.slow
def test_slow_operation():
    # ... long-running test
    pass
```

## Further Reading

- [pytest Documentation](https://docs.pytest.org/)
- [Coverage.py](https://coverage.readthedocs.io/)
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development workflow
