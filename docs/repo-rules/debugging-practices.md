# Debugging Practices

> Comprehensive debugging strategies for the Security Header Analyzer project

---

## Quick Reference

**Common Commands:**
```bash
# Verbose test output
pytest -v

# Full tracebacks
pytest --tb=long

# Debug single test
pytest tests/analyzers/test_hsts.py::TestAnalyzeHSTS::test_analyze_missing -vv

# Coverage gaps
pytest --cov=sha --cov-report=term-missing

# Type check
mypy sha/

# With debug output
pytest -vv -s  # -s shows print statements
```

---

## Debugging Tools

### pytest Verbosity Levels

```bash
# Default (minimal output)
pytest

# Verbose (-v)
pytest -v  # Show test names

# Extra verbose (-vv)
pytest -vv  # Show test names + assertion details

# Show stdout/stderr (-s)
pytest -s  # Don't capture output

# Combined
pytest -vvs
```

### Traceback Modes

```bash
# Short (default) - Minimal traceback
pytest --tb=short

# Long - Full traceback
pytest --tb=long

# Line - One line per failure
pytest --tb=line

# No traceback
pytest --tb=no
```

### Coverage Reports

```bash
# Terminal with missing lines
pytest --cov=sha --cov-report=term-missing

# HTML report
pytest --cov=sha --cov-report=html
open htmlcov/index.html

# Both
pytest --cov=sha --cov-report=html --cov-report=term-missing
```

---

## Analyzer Debugging

### Testing Individual Analyzers

```python
# In Python REPL or script
from sha.analyzers.hsts import analyze

# Test directly
result = analyze("max-age=31536000; includeSubDomains")
print(result)

# Test missing
result = analyze(None)
print(result)

# Test edge case
result = analyze("")
print(result)
```

### Debugging Analyzer Logic

```python
# Add debug prints (remove before commit)
def analyze(value: Optional[str]) -> Finding:
    print(f"DEBUG: Analyzing value: {value!r}")

    if value is None:
        print("DEBUG: Value is None, returning missing finding")
        return missing_finding

    normalized = value.lower()
    print(f"DEBUG: Normalized value: {normalized!r}")

    # ... rest of logic
```

### Running Specific Analyzer Tests

```bash
# All tests for one analyzer
pytest tests/analyzers/test_hsts.py -v

# Single test class
pytest tests/analyzers/test_hsts.py::TestAnalyzeHSTS -v

# Single test function
pytest tests/analyzers/test_hsts.py::TestAnalyzeHSTS::test_analyze_missing -vv

# With coverage for that module only
pytest tests/analyzers/test_hsts.py --cov=sha.analyzers.hsts --cov-report=term-missing
```

---

## Type Error Resolution

### Common MyPy Errors in This Project

**Error 1: Missing return type**
```python
# ❌ Error
def analyze(value):  # error: Function is missing a return type annotation

# ✅ Fix
def analyze(value: Optional[str]) -> Finding:
```

**Error 2: Incompatible types**
```python
# ❌ Error
result: Dict[str, str] = {"status": "good", "severity": None}  # None not compatible with str

# ✅ Fix
result: Dict[str, Optional[str]] = {"status": "good", "severity": None}
# Or use Any
result: Dict[str, Any] = {"status": "good", "severity": None}
```

**Error 3: Argument type mismatch**
```python
# ❌ Error
def process(value: str) -> None:
    pass

process(None)  # error: Argument 1 has incompatible type "None"

# ✅ Fix
def process(value: Optional[str]) -> None:
    if value is None:
        return
    # ... process value
```

**Error 4: Dict key type**
```python
# ❌ Error
config: Dict[str, int] = {"timeout": 10}
config["url"] = "https://example.com"  # error: Incompatible types

# ✅ Fix  
config: Dict[str, Union[int, str]] = {"timeout": 10}
config["url"] = "https://example.com"
```

### Running MyPy

```bash
# Check all source code
mypy sha/

# Check specific file
mypy sha/analyzers/hsts.py

# With verbose output
mypy sha/ --verbose

# Show error codes
mypy sha/ --show-error-codes
```

---

## Test Failures

### Reading pytest Output

**Example Failure:**
```
FAILED tests/analyzers/test_hsts.py::TestAnalyzeHSTS::test_analyze_missing - AssertionError: assert 'high' == 'critical'
```

**Breakdown:**
- `FAILED` - Test failed
- `tests/analyzers/test_hsts.py` - File
- `TestAnalyzeHSTS` - Class
- `test_analyze_missing` - Function
- `AssertionError` - Exception type
- `assert 'high' == 'critical'` - Failed assertion

### Debugging Failed Tests

**Step 1: Run with full traceback**
```bash
pytest tests/analyzers/test_hsts.py::TestAnalyzeHSTS::test_analyze_missing --tb=long
```

**Step 2: Add print statements**
```python
def test_analyze_missing(self):
    result = analyze(None)
    print(f"DEBUG: result = {result}")  # See actual output
    assert result["severity"] == "critical"
```

**Step 3: Run with output capture disabled**
```bash
pytest tests/analyzers/test_hsts.py::TestAnalyzeHSTS::test_analyze_missing -s
```

**Step 4: Use pdb debugger**
```python
def test_analyze_missing(self):
    result = analyze(None)
    import pdb; pdb.set_trace()  # Debugger breakpoint
    assert result["severity"] == "critical"
```

---

## Coverage Gaps

### Finding Untested Code

```bash
# Show missing lines
pytest --cov=sha --cov-report=term-missing

# Output shows:
sha/analyzers/hsts.py    95%    45-47, 52
                         ^^      ^^^^^^^
                      coverage   missing lines
```

### Investigating Missing Coverage

```python
# Lines 45-47 in hsts.py
def analyze(value: Optional[str]) -> Finding:
    if value is None:
        return missing_finding

    # Lines 45-47 (not covered)
    if "preload" in value.lower():
        has_preload = True
    else:
        has_preload = False

    # ... rest
```

**Add Test:**
```python
def test_analyze_with_preload(self):
    """Test HSTS with preload directive."""
    result = analyze("max-age=31536000; preload")
    # This will cover lines 45-47
```

---

## Integration Debugging

### CLI Workflow Debugging

**Test CLI with Mock:**
```python
def test_main_verbose_flag(capsys):
    """Test CLI with --verbose flag."""
    with patch("sys.argv", ["sha", "https://example.com", "--verbose"]):
        with patch("requests.Session") as mock_session:
            # Setup mock
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {"x-frame-options": "DENY"}

            mock_session_instance = Mock()
            mock_session_instance.head.return_value = mock_response
            mock_session.return_value = mock_session_instance

            # Run main
            with pytest.raises(SystemExit) as exc_info:
                main()

            # Check
            assert exc_info.value.code == 0
            captured = capsys.readouterr()
            print(f"DEBUG: stdout = {captured.out}")
            print(f"DEBUG: stderr = {captured.err}")
```

### HTTP Debugging with requests-mock

```python
import requests_mock

def test_fetch_headers_real_request():
    """Test with mocked HTTP response."""
    with requests_mock.Mocker() as m:
        m.head("https://example.com", headers={"x-frame-options": "DENY"})

        headers = fetch_headers("https://example.com")

        assert headers["x-frame-options"] == "DENY"
        assert m.call_count == 1
```

---

## Common Issues & Solutions

### Issue 1: Import Errors

**Error:** `ModuleNotFoundError: No module named 'sha'`

**Solution:**
```bash
# Install in editable mode
pip install -e .

# Or set PYTHONPATH
export PYTHONPATH=/path/to/security-header-analyzer:$PYTHONPATH
pytest
```

### Issue 2: Test Discovery

**Error:** `pytest` finds no tests

**Solution:**
```bash
# Check pytest.ini configuration
cat pytest.ini

# Ensure test files match pattern
ls tests/test_*.py

# Run from project root
cd /path/to/security-header-analyzer
pytest
```

### Issue 3: Fixture Not Found

**Error:** `fixture 'github_headers' not found`

**Solution:**
```python
# Ensure conftest.py is in tests/
ls tests/conftest.py

# Check fixture is defined
grep -n "def github_headers" tests/conftest.py

# Import fixture if needed
from .conftest import github_headers
```

### Issue 4: Mock Not Working

**Error:** Test passes but shouldn't (mock not applied)

**Solution:**
```python
# ❌ Wrong - Patching wrong location
with patch("requests.get") as mock_get:  # Won't work

# ✅ Correct - Patch where it's used
with patch("sha.fetcher.requests.Session") as mock_session:
```

---

## Debugging Workflows

### Workflow 1: New Analyzer Not Working

```bash
# 1. Test analyzer directly
python3 -c "from sha.analyzers.new_header import analyze; print(analyze('test-value'))"

# 2. Check registration
python3 -c "from sha.analyzers import ANALYZER_REGISTRY; print('new-header' in ANALYZER_REGISTRY)"

# 3. Run analyzer tests
pytest tests/analyzers/test_new_header.py -vv

# 4. Check integration
pytest tests/test_analyze_headers.py -vv

# 5. Test CLI
sha https://example.com --verbose
```

### Workflow 2: Tests Failing After Changes

```bash
# 1. Run all tests
pytest

# 2. Identify failed tests
pytest --lf  # Run last failed

# 3. Debug specific failure
pytest tests/analyzers/test_hsts.py::TestAnalyzeHSTS::test_analyze_missing -vv --tb=long

# 4. Check coverage
pytest --cov=sha --cov-report=term-missing

# 5. Fix and re-run
pytest
```

### Workflow 3: Type Errors from MyPy

```bash
# 1. Run mypy
mypy sha/

# 2. Focus on one file
mypy sha/analyzers/hsts.py

# 3. Understand error
mypy sha/analyzers/hsts.py --show-error-codes

# 4. Fix types
# ... edit file ...

# 5. Verify
mypy sha/
```

---

## IDE Integration

### VS Code

**Configure Python Extension:**
```json
// .vscode/settings.json
{
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": [
        "tests",
        "-v"
    ],
    "python.linting.mypyEnabled": true,
    "python.linting.enabled": true
}
```

**Run Tests in VS Code:**
- Open Testing sidebar
- Click run button next to test
- Set breakpoints in code
- Use Debug Test option

### PyCharm

**Configure pytest:**
1. Settings → Tools → Python Integrated Tools
2. Default test runner: pytest
3. pytest arguments: `-v`

**Debugging:**
1. Right-click test function
2. Select "Debug 'test_name'"
3. Set breakpoints
4. Step through code

---

## Performance Profiling

### When to Profile

- Tests running slow
- CLI taking too long
- Specific analyzer slow

### Using cProfile

```bash
# Profile CLI
python -m cProfile -s cumulative -m sha https://example.com

# Profile tests
pytest --profile

# Or in code
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()

# ... code to profile ...

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)  # Top 20 functions
```

---

## Summary

**Key Debugging Tools:**
- `pytest -vv --tb=long` - Detailed test output
- `pytest --cov=sha --cov-report=term-missing` - Coverage gaps
- `mypy sha/` - Type checking
- `pdb.set_trace()` - Interactive debugger
- `print()` statements - Quick inspection

**Common Commands:**
```bash
# Debug failing test
pytest path/to/test.py::TestClass::test_function -vvs --tb=long

# Find coverage gaps
pytest --cov=sha --cov-report=html

# Type check
mypy sha/

# Run last failed
pytest --lf

# Run with debugger
pytest --pdb
```

**See Also:**
- [testing-standards.md](testing-standards.md) - Test patterns
- [python-code-standards.md](python-code-standards.md) - Code structure
- [Documentation on pytest](https://docs.pytest.org/)

---

**Last Updated:** 2026-01-01
