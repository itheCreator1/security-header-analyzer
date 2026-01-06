# Python Code Standards

> Python coding conventions specific to the Security Header Analyzer project

---

## Quick Reference

**TL;DR:**
- **Type Hints:** MyPy strict mode (100% typed, no exceptions)
- **Formatting:** Black (100-char line length)
- **Imports:** isort (Black profile, stdlib → third-party → local)
- **Patterns:** Registry pattern for analyzers
- **Data Structure:** Standardized Finding dictionaries
- **Docstrings:** Comprehensive (Module, Purpose, Overview, Key Functions)

**Configuration Files:**
- [`pyproject.toml`](../../pyproject.toml) - All tool configurations
- [`.pre-commit-config.yaml`](../../.pre-commit-config.yaml) - Automated checks

---

## Type Hints (MyPy Strict Mode)

### Requirements

**Rule:** Every function, method, and variable must have type annotations.

**Configuration** (from `pyproject.toml`):
```toml
[tool.mypy]
python_version = "3.9"
disallow_untyped_defs = true        # ← Enforces all functions typed
disallow_incomplete_defs = true      # ← No missing annotations
check_untyped_defs = true
no_implicit_optional = true
strict_equality = true
```

### Conventions

**Python 3.8+ Compatibility:**
```python
# ✅ Correct (3.8-compatible)
from typing import Dict, List, Optional, Union, Callable, Any

def analyze(value: Optional[str]) -> Dict[str, Any]:
    pass

# ❌ Wrong (requires Python 3.10+)
def analyze(value: str | None) -> dict[str, any]:
    pass
```

**Type Aliases for Clarity:**
```python
# Define at module level
Finding = Dict[str, Any]

def analyze(value: Optional[str]) -> Finding:
    """Analyze header and return Finding dict."""
    return {
        "header_name": "Test",
        "status": "good",
        # ...
    }
```

**Optional vs Union:**
```python
# ✅ Preferred
def fetch(url: str, timeout: Optional[int] = None) -> Dict[str, str]:
    pass

# ❌ Avoid (less readable)
def fetch(url: str, timeout: Union[int, None] = None) -> Dict[str, str]:
    pass
```

**Return Type Annotations:**
```python
# ✅ Always annotate return type
def parse_hsts(value: str) -> Dict[str, Any]:
    return {"max_age": 31536000, "include_subdomains": True}

# ❌ Never omit return type
def parse_hsts(value: str):  # MyPy will error
    return {"max_age": 31536000}
```

### Common Type Patterns in This Project

**1. Finding Dictionary:**
```python
Finding = Dict[str, Any]  # Standard structure across all analyzers

def analyze(value: Optional[str]) -> Finding:
    return {
        "header_name": str,
        "status": str,  # "good" | "acceptable" | "bad" | "missing"
        "severity": str,  # "critical" | "high" | "medium" | "low" | "info"
        "message": str,
        "actual_value": Optional[str],
        "recommendation": Optional[str],
    }
```

**2. Headers Dictionary:**
```python
# Most headers are str, but Set-Cookie is List[str]
Headers = Dict[str, Union[str, List[str]]]

def fetch_headers(url: str) -> Headers:
    pass
```

**3. Callable Types (for Registry):**
```python
# Analyzer functions
AnalyzerFunction = Callable[[Optional[str]], Finding]

ANALYZER_REGISTRY: Dict[str, AnalyzerFunction] = {
    "hsts": hsts.analyze,
    "csp": csp.analyze,
}
```

---

## Code Organization

### Registry Pattern (Core Architecture)

**Purpose:** Decouple analyzer implementations from orchestration layer

**Implementation** ([`sha/analyzers/__init__.py`](../../sha/analyzers/__init__.py)):
```python
from typing import Any, Callable, Dict
from . import hsts, xframe, csp, # ... all analyzers

# Registry mapping header keys to analyzer functions
ANALYZER_REGISTRY: Dict[str, Callable] = {
    hsts.HEADER_KEY: hsts.analyze,
    xframe.HEADER_KEY: xframe.analyze,
    csp.HEADER_KEY: csp.analyze,
    # ... all 15 analyzers
}

# Registry mapping header keys to config dicts
CONFIG_REGISTRY: Dict[str, Dict[str, Any]] = {
    hsts.HEADER_KEY: hsts.CONFIG,
    xframe.HEADER_KEY: xframe.CONFIG,
    # ...
}
```

**Benefits:**
- Add new analyzers without modifying orchestration code
- All analyzers implement same interface: `analyze(value: Optional[str]) -> Finding`
- Centralized configuration

**Usage** ([`sha/analyzer.py`](../../sha/analyzer.py)):
```python
from .analyzers import ANALYZER_REGISTRY

def analyze_headers(headers: Headers) -> List[Finding]:
    findings = []
    for header_key, analyzer_func in ANALYZER_REGISTRY.items():
        value = headers.get(header_key)
        finding = analyzer_func(value)  # All analyzers have same signature
        findings.append(finding)
    return findings
```

### Standardized Finding Structure

**Required Keys** (all analyzers must return these):
```python
{
    "header_name": str,        # Display name (e.g., "Strict-Transport-Security")
    "status": str,             # "good" | "acceptable" | "bad" | "missing"
    "severity": str,           # "critical" | "high" | "medium" | "low" | "info"
    "message": str,            # Human-readable explanation
    "actual_value": Optional[str],  # The actual header value (None if missing)
    "recommendation": Optional[str]  # How to fix (None if already good)
}
```

**Example** ([`sha/analyzers/hsts.py`](../../sha/analyzers/hsts.py)):
```python
def analyze(value: Optional[str]) -> Finding:
    """Analyze HSTS header."""
    if value is None:
        return {
            "header_name": CONFIG["display_name"],
            "status": STATUS_MISSING,
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"][STATUS_MISSING],
            "actual_value": None,
            "recommendation": CONFIG["recommendations"]["missing"],
        }

    # ... validation logic ...

    return {
        "header_name": CONFIG["display_name"],
        "status": STATUS_GOOD,
        "severity": "info",
        "message": "HSTS properly configured",
        "actual_value": value,
        "recommendation": None,
    }
```

### Configuration Dictionary Pattern

**Purpose:** Externalize validation rules, messages, and thresholds

**Location:** Every analyzer module has a module-level `CONFIG` dict

**Example** ([`sha/analyzers/hsts.py`](../../sha/analyzers/hsts.py)):
```python
HEADER_KEY = "strict-transport-security"  # Lowercase with hyphens

CONFIG = {
    "display_name": "Strict-Transport-Security",
    "severity_missing": "critical",
    "description": "Enforces HTTPS connections",
    "validation": {
        "min_max_age": 10886400,  # 126 days
        "best_max_age": 31536000,  # 1 year
        "required_directives": ["includesubdomains"],
    },
    "messages": {
        STATUS_GOOD: "HSTS is properly configured",
        STATUS_ACCEPTABLE: "HSTS is configured but could be improved",
        STATUS_BAD: "HSTS configuration is insecure",
        STATUS_MISSING: "HSTS header is missing - site vulnerable to downgrade attacks",
    },
    "recommendations": {
        "missing": "Add Strict-Transport-Security header with max-age=31536000; includeSubDomains; preload",
        "too_short": "Increase max-age to at least 126 days (10886400 seconds)",
        "missing_subdomains": "Add includeSubDomains directive",
        # ...
    }
}
```

**Benefits:**
- Change thresholds without modifying code logic
- Consistent message structure
- Easy to test (mock CONFIG for different scenarios)
- Self-documenting (CONFIG shows what's validated)

---

## Naming Conventions

### Modules/Files
```python
# ✅ snake_case.py
hsts.py
cache_control.py
permissions_policy.py
cross_origin_validator.py

# ❌ Avoid
HSTS.py
CacheControl.py
```

### Classes
```python
# ✅ PascalCase
class SecurityHeaderAnalyzerError(Exception):
    pass

class NetworkError(SecurityHeaderAnalyzerError):
    pass

# ❌ Avoid
class security_header_analyzer_error(Exception):
    pass
```

### Functions/Methods
```python
# ✅ snake_case, action verbs
def analyze_headers(headers: Headers) -> List[Finding]:
    pass

def parse_hsts(value: str) -> Dict[str, Any]:
    pass

def validate_url_safety(url: str) -> None:
    pass

# ❌ Avoid
def AnalyzeHeaders():  # PascalCase for functions
    pass

def hsts():  # Not descriptive
    pass
```

### Constants
```python
# ✅ UPPER_SNAKE_CASE (module level)
DEFAULT_TIMEOUT = 10
PRIVATE_IP_RANGES = [...]
STATUS_GOOD = "good"
SEVERITY_CRITICAL = "critical"

# ✅ Configuration keys (in analyzer modules)
HEADER_KEY = "strict-transport-security"
```

### Private Functions/Variables
```python
# ✅ Leading underscore for private/internal use
def _normalize_headers_with_cookies(response):
    """Internal helper for header normalization."""
    pass

_INTERNAL_CACHE = {}

# Public API (no underscore)
def fetch_headers(url: str) -> Headers:
    """Public function for fetching headers."""
    pass
```

### Type Aliases
```python
# ✅ PascalCase (like classes)
Finding = Dict[str, Any]
Headers = Dict[str, Union[str, List[str]]]
AnalyzerFunction = Callable[[Optional[str]], Finding]
```

---

## Docstring Standards

### Module-Level Docstrings

**Template:**
```python
"""
[Module Name] - [One-line description]

Module: sha.analyzers.hsts

Purpose:
    Analyzes Strict-Transport-Security headers to ensure HTTPS enforcement
    is properly configured. Validates max-age, includeSubDomains, and preload
    directives.

Overview:
    The HSTS analyzer checks for proper HTTPS enforcement by validating the
    Strict-Transport-Security header. It ensures max-age is sufficient (126+ days),
    recommends includeSubDomains for complete coverage, and validates preload
    eligibility. Uses the Registry Pattern for integration with the main analyzer.

Key Functions:
    - analyze(value: Optional[str]) -> Finding
      Main analyzer function. Returns validation findings for HSTS header.

    - parse_hsts(value: str) -> Dict[str, Any]
      Parses HSTS header value into structured dict with max_age,
      include_subdomains, and preload flags.

Security Considerations:
    - Missing HSTS enables SSL stripping attacks
    - Short max-age provides limited protection
    - Without includeSubDomains, subdomains remain vulnerable

Related Modules:
    - sha.analyzer - Orchestration layer that calls this analyzer
    - sha.config - Status and severity constants
    - tests.analyzers.test_hsts - Comprehensive test suite

Example Usage:
    >>> from sha.analyzers.hsts import analyze
    >>> finding = analyze("max-age=31536000; includeSubDomains; preload")
    >>> print(finding["status"])
    'good'

See Also:
    - docs/headers/hsts.md - Detailed HSTS documentation
    - docs/architecture/registry-pattern.md - Registry pattern explanation
"""
```

**Required Sections:**
- `[Module Name] - [Description]` (first line)
- `Module:` (full module path)
- `Purpose:` (2-3 sentences)
- `Overview:` (4-6 sentences with architectural context)
- `Key Functions/Classes:` (list with brief descriptions)

**Optional Sections** (include if relevant):
- `Security Considerations:` (for security-critical modules)
- `Configuration:` (for modules with config requirements)
- `Related Modules:` (dependencies and related code)
- `Example Usage:` (executable code snippet)
- `See Also:` (documentation links)

### Function Docstrings

**Template:**
```python
def analyze(value: Optional[str]) -> Finding:
    """
    Analyze HSTS header and return validation findings.

    Validates max-age duration, includeSubDomains directive, and preload
    eligibility. Missing header returns critical severity finding.

    Args:
        value: The HSTS header value (None if header is missing)

    Returns:
        Finding dictionary with structure:
        {
            "header_name": str,
            "status": "good" | "acceptable" | "bad" | "missing",
            "severity": "critical" | "info",
            "message": str,
            "actual_value": Optional[str],
            "recommendation": Optional[str],
        }

    Example:
        >>> analyze("max-age=31536000; includeSubDomains")
        {"status": "good", "severity": "info", ...}

        >>> analyze(None)
        {"status": "missing", "severity": "critical", ...}

    Notes:
        - max-age < 10886400 (126 days) is considered too short
        - Preload directive is optional but recommended
        - Header is case-insensitive

    See Also:
        - parse_hsts() - Header parsing logic
        - CONFIG - Validation thresholds
    """
```

**Required Elements:**
- One-line summary
- `Args:` section (even if no args)
- `Returns:` section with structure for complex returns
- `Example:` section showing typical usage

**Optional Elements:**
- Extended description (2-3 sentences after summary)
- `Raises:` section (if function raises exceptions)
- `Notes:` section (caveats, edge cases)
- `See Also:` section (related functions/docs)

---

## Import Organization (isort)

### Configuration

**From `pyproject.toml`:**
```toml
[tool.isort]
profile = "black"              # Compatible with Black formatter
line_length = 100
known_first_party = ["sha"]    # Mark 'sha' as internal package
multi_line_output = 3          # Vertical hanging indent
include_trailing_comma = true
```

### Import Order

**1. Standard library** (alphabetical)
```python
import argparse
import json
import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
```

**2. Third-party** (alphabetical)
```python
import requests
```

**3. Local/relative** (alphabetical)
```python
from . import __version__
from .config import (
    DEFAULT_TIMEOUT,
    STATUS_GOOD,
    STATUS_BAD,
    InvalidURLError,
)
from .analyzers import ANALYZER_REGISTRY
```

### Multi-Line Imports

**Pattern:**
```python
# ✅ Vertical hanging indent with trailing comma
from .config import (
    DEFAULT_TIMEOUT,
    MAX_REDIRECTS,
    STATUS_GOOD,
    STATUS_BAD,
    NetworkError,
)

# ❌ Avoid
from .config import DEFAULT_TIMEOUT, MAX_REDIRECTS, STATUS_GOOD, STATUS_BAD, NetworkError
```

---

## Code Style (Black)

### Configuration

**From `pyproject.toml`:**
```toml
[tool.black]
line-length = 100         # Longer than Black default (88)
target-version = ['py38', 'py39', 'py310', 'py311', 'py312']
```

### Key Formatting Rules

**Line Length:**
```python
# ✅ Up to 100 characters
def fetch_headers_with_retry(url: str, timeout: int = DEFAULT_TIMEOUT, max_retries: int = 3) -> Headers:
    pass

# Black will auto-wrap at 100 chars:
def very_long_function_name_with_many_parameters(
    parameter_one: str,
    parameter_two: int,
    parameter_three: Optional[Dict[str, Any]] = None,
) -> Dict[str, Union[str, List[str]]]:
    pass
```

**String Quotes:**
```python
# ✅ Black prefers double quotes
message = "HSTS header is missing"
header_key = "strict-transport-security"

# Black will auto-convert single quotes to double
# (except when string contains double quotes)
```

**Trailing Commas:**
```python
# ✅ Trailing commas in multi-line structures
finding = {
    "header_name": "HSTS",
    "status": "good",
    "severity": "info",  # ← Trailing comma
}

# ✅ Function arguments
def analyze(
    value: Optional[str],
    strict: bool = False,  # ← Trailing comma
) -> Finding:
    pass
```

---

## Error Handling

### Custom Exception Hierarchy

**Location:** [`sha/config.py`](../../sha/config.py)

**Structure:**
```python
class SecurityHeaderAnalyzerError(Exception):
    """Base exception for all SHA errors."""
    pass

class NetworkError(SecurityHeaderAnalyzerError):
    """Connection failures, timeouts, SSL errors."""
    pass

class InvalidURLError(SecurityHeaderAnalyzerError):
    """Malformed URL or SSRF attempt."""
    pass

class HTTPError(SecurityHeaderAnalyzerError):
    """4xx, 5xx HTTP responses."""

    def __init__(self, message: str, status_code: Optional[int] = None, headers: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.headers = headers or {}
```

### Exception Usage Patterns

**Raising Exceptions:**
```python
# ✅ Specific exceptions with context
def validate_url(url: str) -> None:
    if not url.startswith(("http://", "https://")):
        raise InvalidURLError(f"URL must start with http:// or https://: {url}")

    if is_private_ip(url):
        raise InvalidURLError(f"Private IP addresses not allowed (SSRF protection): {url}")

# ✅ HTTPError with attached metadata
def fetch(url: str) -> requests.Response:
    response = requests.get(url)
    if response.status_code >= 400:
        raise HTTPError(
            f"HTTP {response.status_code} error for {url}",
            status_code=response.status_code,
            headers=dict(response.headers)
        )
```

**Catching Exceptions:**
```python
# ✅ Specific exception types
try:
    headers = fetch_headers(url)
except InvalidURLError as e:
    print(f"Error: Invalid URL - {e}", file=sys.stderr)
    sys.exit(2)  # Specific exit code
except NetworkError as e:
    print(f"Error: Network error - {e}", file=sys.stderr)
    sys.exit(1)
except HTTPError as e:
    # Can still attempt to analyze available headers
    if e.headers:
        findings = analyze_headers(e.headers)
    sys.exit(3)

# ❌ Avoid catching generic Exception
try:
    headers = fetch_headers(url)
except Exception as e:  # Too broad
    pass
```

### Validation Patterns

**Early Validation:**
```python
def parse_args() -> argparse.Namespace:
    """Parse CLI arguments with validation."""
    parser = argparse.ArgumentParser()
    # ... add arguments ...
    args = parser.parse_args()

    # ✅ Validate early, fail fast
    if args.verbose and args.quiet:
        parser.error("--verbose and --quiet are mutually exclusive")

    if args.timeout <= 0:
        parser.error("timeout must be positive")

    if args.timeout > MAX_TIMEOUT:
        parser.error(f"timeout cannot exceed {MAX_TIMEOUT} seconds")

    return args
```

---

## Analyzer Implementation Guide

### Step-by-Step: Adding a New Analyzer

**1. Create Analyzer Module** (`sha/analyzers/new_header.py`):

```python
"""
New-Header Analyzer - [Brief description]

Module: sha.analyzers.new_header

Purpose:
    [What this analyzer does and why]

[... rest of module docstring ...]
"""

from typing import Any, Dict, Optional
from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

# Type alias
Finding = Dict[str, Any]

# Header key (lowercase with hyphens)
HEADER_KEY = "new-header-name"

# Configuration dictionary
CONFIG = {
    "display_name": "New-Header-Name",
    "severity_missing": "high",  # critical | high | medium | low
    "description": "What this header does",
    "validation": {
        # Validation rules and thresholds
        "required_value": "expected-value",
        "min_length": 10,
    },
    "messages": {
        STATUS_GOOD: "Header is properly configured",
        STATUS_ACCEPTABLE: "Header is configured but could be improved",
        STATUS_BAD: "Header configuration is insecure",
        STATUS_MISSING: "Header is missing - [security impact]",
    },
    "recommendations": {
        "missing": "Add New-Header-Name header with value: ...",
        "wrong_value": "Change value to ...",
        # ...
    }
}

def analyze(value: Optional[str]) -> Finding:
    """
    Analyze the New-Header header and return findings.

    Args:
        value: The header value (None if header is missing)

    Returns:
        Finding dictionary with validation results

    Example:
        >>> analyze("expected-value")
        {"status": "good", ...}
    """
    # Handle missing header
    if value is None:
        return {
            "header_name": CONFIG["display_name"],
            "status": STATUS_MISSING,
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"][STATUS_MISSING],
            "actual_value": None,
            "recommendation": CONFIG["recommendations"]["missing"],
        }

    # Normalize value (lowercase, strip whitespace)
    normalized = value.lower().strip()

    # Validation logic
    if normalized == CONFIG["validation"]["required_value"]:
        return {
            "header_name": CONFIG["display_name"],
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Default: bad configuration
    return {
        "header_name": CONFIG["display_name"],
        "status": STATUS_BAD,
        "severity": "high",
        "message": CONFIG["messages"][STATUS_BAD],
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["wrong_value"],
    }
```

**2. Register in `sha/analyzers/__init__.py`:**

```python
from . import new_header  # ← Add import

ANALYZER_REGISTRY: Dict[str, Callable] = {
    # ... existing analyzers ...
    new_header.HEADER_KEY: new_header.analyze,  # ← Add registration
}

CONFIG_REGISTRY: Dict[str, Dict[str, Any]] = {
    # ... existing configs ...
    new_header.HEADER_KEY: new_header.CONFIG,  # ← Add config
}
```

**3. Create Tests** (`tests/analyzers/test_new_header.py`):

```python
"""Tests for New-Header analyzer."""

import pytest
from sha.analyzers.new_header import analyze, HEADER_KEY, CONFIG
from sha.config import STATUS_GOOD, STATUS_BAD, STATUS_MISSING

class TestAnalyzeNewHeader:
    """Test New-Header header analysis."""

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
```

**4. Update Documentation:**
- Create `docs/headers/new-header.md` (see documentation-standards.md)
- Update `docs/headers/README.md` index
- Update `docs/analyzer-reference.md`
- Update `docs/repo-rules/security-headers-best-practices.md` summary table

---

## Anti-Patterns (Things to Avoid)

### ❌ Anti-Pattern 1: Hardcoded Magic Numbers

```python
# ❌ Bad: Magic numbers in code
def analyze(value: str) -> Finding:
    parsed = parse_hsts(value)
    if parsed["max_age"] < 10886400:  # What is this number?
        return bad_finding
```

**✅ Solution: Use CONFIG dictionary**
```python
# ✅ Good: Configuration-driven
CONFIG = {
    "validation": {
        "min_max_age": 10886400,  # 126 days
    }
}

def analyze(value: str) -> Finding:
    parsed = parse_hsts(value)
    if parsed["max_age"] < CONFIG["validation"]["min_max_age"]:
        return bad_finding
```

### ❌ Anti-Pattern 2: Inconsistent Finding Structure

```python
# ❌ Bad: Different keys in different analyzers
def analyze_hsts(value: str) -> Dict:
    return {"name": "HSTS", "result": "good"}

def analyze_csp(value: str) -> Dict:
    return {"header": "CSP", "status": "good", "score": 10}
```

**✅ Solution: Standardized Finding structure**
```python
# ✅ Good: All analyzers return same structure
def analyze(value: str) -> Finding:
    return {
        "header_name": "HSTS",
        "status": "good",
        "severity": "info",
        "message": "...",
        "actual_value": value,
        "recommendation": None,
    }
```

### ❌ Anti-Pattern 3: Direct Registry Modification

```python
# ❌ Bad: Modifying registry outside __init__.py
from sha.analyzers import ANALYZER_REGISTRY

def my_custom_analyzer(value: str) -> Finding:
    pass

# Don't do this
ANALYZER_REGISTRY["custom"] = my_custom_analyzer
```

**✅ Solution: Follow registration pattern**
```python
# ✅ Good: Create module in analyzers/, register in __init__.py
# In sha/analyzers/custom.py:
HEADER_KEY = "custom"
def analyze(value: Optional[str]) -> Finding:
    pass

# In sha/analyzers/__init__.py:
from . import custom
ANALYZER_REGISTRY[custom.HEADER_KEY] = custom.analyze
```

### ❌ Anti-Pattern 4: Missing Type Hints

```python
# ❌ Bad: No type hints (MyPy will error in strict mode)
def analyze(value):
    if value is None:
        return {"status": "missing"}
    return {"status": "good"}
```

**✅ Solution: Full type annotations**
```python
# ✅ Good: Complete type hints
def analyze(value: Optional[str]) -> Finding:
    if value is None:
        return {"status": "missing"}
    return {"status": "good"}
```

### ❌ Anti-Pattern 5: Catching Generic Exceptions

```python
# ❌ Bad: Too broad exception handling
try:
    headers = fetch_headers(url)
except Exception:
    print("Error")
```

**✅ Solution: Specific exception types**
```python
# ✅ Good: Specific exceptions with context
try:
    headers = fetch_headers(url)
except InvalidURLError as e:
    print(f"Invalid URL: {e}")
except NetworkError as e:
    print(f"Network error: {e}")
```

---

## Summary

**Key Takeaways:**

1. **Type Everything:** MyPy strict mode enforced - no exceptions
2. **Use the Registry:** All analyzers integrate via ANALYZER_REGISTRY
3. **Standardize Findings:** All analyzers return identical dict structure
4. **Externalize Config:** Use CONFIG dictionaries for thresholds/messages
5. **Document Thoroughly:** Module + function docstrings required
6. **Follow Black/isort:** Automated formatting, don't fight it
7. **Specific Exceptions:** Custom exception hierarchy, never catch generic Exception

**Automation:**
```bash
# Format code
black sha/ tests/

# Sort imports
isort sha/ tests/

# Type check
mypy sha/

# Run all pre-commit hooks
pre-commit run --all-files
```

**See Also:**
- [testing-standards.md](testing-standards.md) - How to test these patterns
- [documentation-standards.md](documentation-standards.md) - Docstring templates
- [git-practices.md](git-practices.md) - Committing code changes

---

**Last Updated:** 2026-01-01
**Configuration:** [`pyproject.toml`](../../pyproject.toml) | [`.pre-commit-config.yaml`](../../.pre-commit-config.yaml)
