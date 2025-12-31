# Extensibility Guide

## Overview

Adding a new security header analyzer to the system requires only 4 steps and no modifications to existing code. This guide provides complete instructions with templates and examples.

## Why It's Easy

The Registry Pattern enables:
- **No core code changes** - Just add your analyzer
- **Consistent structure** - Follow proven template
- **Isolated testing** - Test independently
- **Automatic integration** - Registry handles dispatch

---

## Step-by-Step Guide

### Step 1: Create Analyzer Module

Create a new file in `sha/analyzers/` following this template:

**File:** `sha/analyzers/new_header.py`

```python
"""
New-Security-Header Analyzer.

This header provides XYZ security protection against ABC attacks.
Recommended by OWASP/Mozilla for all production websites.
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

# Header key (REQUIRED) - lowercase with hyphens
HEADER_KEY = "new-security-header"

# Configuration dictionary (REQUIRED)
CONFIG = {
    "display_name": "New-Security-Header",
    "severity_missing": "medium",  # critical|high|medium|low
    "description": "Brief description of what this header does",

    "validation": {
        "good": ["secure-value", "another-good-value"],
        "acceptable": ["acceptable-value"],
        "bad": ["unsafe-value"],
    },

    "messages": {
        STATUS_GOOD: "Header is properly configured with strong settings",
        STATUS_ACCEPTABLE: "Header is present but could be improved",
        STATUS_BAD: "Header is present but improperly configured",
        STATUS_MISSING: "Header is missing - vulnerable to XYZ attacks",
    },

    "recommendations": {
        "missing": "Add: New-Security-Header: secure-value",
        "bad": "Change to: New-Security-Header: secure-value",
        "improve": "Consider adding additional-directive for enhanced protection",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze New-Security-Header value.

    Args:
        value: Header value or None if missing

    Returns:
        Finding dictionary with keys:
        - header_name: str
        - status: "good" | "acceptable" | "bad" | "missing"
        - severity: "critical" | "high" | "medium" | "low" | "info"
        - message: str
        - actual_value: Optional[str]
        - recommendation: Optional[str]

    Example:
        >>> result = analyze("secure-value")
        >>> result["status"]
        "good"
        >>> result = analyze(None)
        >>> result["status"]
        "missing"
    """
    header_name = CONFIG["display_name"]

    # Handle missing header
    if value is None:
        return {
            "header_name": header_name,
            "status": STATUS_MISSING,
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"][STATUS_MISSING],
            "actual_value": None,
            "recommendation": CONFIG["recommendations"]["missing"],
        }

    # Normalize value (lowercase, strip whitespace)
    value_normalized = value.lower().strip()

    # Check for good configuration
    if value_normalized in CONFIG["validation"]["good"]:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,  # No recommendation when good
        }

    # Check for acceptable configuration
    if value_normalized in CONFIG["validation"]["acceptable"]:
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["improve"],
        }

    # Check for bad configuration
    if value_normalized in CONFIG["validation"]["bad"]:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": "high",
            "message": CONFIG["messages"][STATUS_BAD],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["bad"],
        }

    # Unknown value - treat as bad
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": "medium",
        "message": f"Unknown or invalid value: {value}",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["bad"],
    }
```

---

### Step 2: Register Analyzer

Edit `sha/analyzers/__init__.py` to register your analyzer:

**Add Import:**
```python
from . import (
    hsts,
    xframe,
    # ... existing imports ...
    new_header,  # ADD THIS
)
```

**Add to ANALYZER_REGISTRY:**
```python
ANALYZER_REGISTRY: Dict[str, Callable] = {
    hsts.HEADER_KEY: hsts.analyze,
    xframe.HEADER_KEY: xframe.analyze,
    # ... existing entries ...
    new_header.HEADER_KEY: new_header.analyze,  # ADD THIS
}
```

**Add to CONFIG_REGISTRY:**
```python
CONFIG_REGISTRY: Dict[str, Dict[str, Any]] = {
    hsts.HEADER_KEY: hsts.CONFIG,
    xframe.HEADER_KEY: xframe.CONFIG,
    # ... existing entries ...
    new_header.HEADER_KEY: new_header.CONFIG,  # ADD THIS
}
```

**Add to __all__ (optional):**
```python
__all__ = [
    # ... existing exports ...
    "new_header",  # ADD THIS
]
```

---

### Step 3: Add Tests

Create comprehensive tests in `tests/test_new_header.py`:

```python
"""
Tests for New-Security-Header analyzer.
"""

import pytest

from sha.analyzers.new_header import analyze, CONFIG, HEADER_KEY


class TestNewHeaderAnalyzer:
    """Test cases for New-Security-Header analyzer."""

    def test_missing_header(self):
        """Test that missing header is detected."""
        result = analyze(None)

        assert result["status"] == "missing"
        assert result["severity"] == CONFIG["severity_missing"]
        assert result["actual_value"] is None
        assert result["recommendation"] is not None

    def test_good_value(self):
        """Test good header value."""
        result = analyze("secure-value")

        assert result["status"] == "good"
        assert result["severity"] == "info"
        assert result["actual_value"] == "secure-value"
        assert result["recommendation"] is None

    def test_acceptable_value(self):
        """Test acceptable header value."""
        result = analyze("acceptable-value")

        assert result["status"] == "acceptable"
        assert result["severity"] == "low"
        assert result["recommendation"] is not None

    def test_bad_value(self):
        """Test bad header value."""
        result = analyze("unsafe-value")

        assert result["status"] == "bad"
        assert result["severity"] in ["high", "medium"]
        assert result["recommendation"] is not None

    def test_case_insensitive(self):
        """Test that parsing is case-insensitive."""
        result1 = analyze("SECURE-VALUE")
        result2 = analyze("secure-value")

        assert result1["status"] == result2["status"]

    def test_whitespace_handling(self):
        """Test that leading/trailing whitespace is handled."""
        result = analyze("  secure-value  ")

        assert result["status"] == "good"

    def test_unknown_value(self):
        """Test unknown header value."""
        result = analyze("unknown-weird-value")

        assert result["status"] == "bad"
        assert result["recommendation"] is not None

    def test_return_structure(self):
        """Test that return value has all required keys."""
        result = analyze("secure-value")

        required_keys = {
            "header_name",
            "status",
            "severity",
            "message",
            "actual_value",
            "recommendation"
        }

        assert set(result.keys()) == required_keys

    def test_header_key_constant(self):
        """Test that HEADER_KEY is properly defined."""
        assert HEADER_KEY == "new-security-header"
        assert HEADER_KEY.islower()
        assert "-" in HEADER_KEY  # Uses hyphens, not underscores


class TestNewHeaderConfig:
    """Test cases for New-Security-Header configuration."""

    def test_config_structure(self):
        """Test that CONFIG has all required keys."""
        required_keys = {
            "display_name",
            "severity_missing",
            "description",
            "validation",
            "messages",
            "recommendations"
        }

        assert set(CONFIG.keys()) == required_keys

    def test_validation_rules(self):
        """Test that validation rules are defined."""
        assert "good" in CONFIG["validation"]
        assert "acceptable" in CONFIG["validation"]
        assert "bad" in CONFIG["validation"]
```

---

### Step 4: Update Documentation

**1. Add to analyzer-reference.md:**

Add an entry describing your analyzer:

```markdown
## New-Security-Header

**Header:** `New-Security-Header`
**Severity if Missing:** Medium
**Status:** Active

### Description
This header provides XYZ security protection...

### Configuration
- **Good:** `secure-value`
- **Acceptable:** `acceptable-value`
- **Bad:** `unsafe-value`

### References
- [MDN Documentation](https://developer.mozilla.org/...)
- [OWASP Guide](https://owasp.org/...)
```

**2. Update CHANGELOG.md:**

```markdown
## [Unreleased]

### Added
- New analyzer for New-Security-Header
```

**3. Update README.md (if major):**

If this is a significant addition, update the feature count in README.md.

---

## Complete Example: Adding X-Download-Options

### Real Implementation

**File:** `sha/analyzers/x_download_options.py`

```python
"""
X-Download-Options Header Analyzer.

Prevents Internet Explorer from executing downloads in the context
of the site (IE8+ feature). Recommended value: noopen.
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "x-download-options"

CONFIG = {
    "display_name": "X-Download-Options",
    "severity_missing": "low",
    "description": "Prevents IE from executing downloads in site context",

    "validation": {
        "good": ["noopen"],
        "acceptable": [],
        "bad": [],
    },

    "messages": {
        STATUS_GOOD: "X-Download-Options is properly set to 'noopen'",
        STATUS_ACCEPTABLE: "X-Download-Options is set",
        STATUS_BAD: "X-Download-Options has invalid value",
        STATUS_MISSING: "X-Download-Options is missing (low risk for modern browsers)",
    },

    "recommendations": {
        "missing": "Add: X-Download-Options: noopen",
        "bad": "Change to: X-Download-Options: noopen",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """Analyze X-Download-Options header."""
    header_name = CONFIG["display_name"]

    if value is None:
        return {
            "header_name": header_name,
            "status": STATUS_MISSING,
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"][STATUS_MISSING],
            "actual_value": None,
            "recommendation": CONFIG["recommendations"]["missing"],
        }

    value_normalized = value.lower().strip()

    if value_normalized == "noopen":
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Any other value is bad
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": "low",
        "message": f"Invalid value: {value}",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["bad"],
    }
```

---

## Advanced Patterns

### Complex Parsing

For headers that require complex parsing (like CSP or HSTS):

```python
def parse_complex_header(value: str) -> Dict[str, Any]:
    """
    Parse complex header into components.

    Returns dict with parsed components.
    """
    result = {}
    # Parsing logic...
    return result


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """Analyze with parsing."""
    if value is None:
        # Handle missing...
        pass

    parsed = parse_complex_header(value)

    # Use parsed data for validation...
```

### Multiple Status Levels

For headers with multiple severity levels:

```python
def analyze(value: Optional[str]) -> Dict[str, Any]:
    """Analyze with multiple severity levels."""
    if value is None:
        return {...}  # Critical

    if is_critically_bad(value):
        return {..., "severity": "critical"}

    if is_high_risk(value):
        return {..., "severity": "high"}

    if is_medium_risk(value):
        return {..., "severity": "medium"}

    return {..., "severity": "info"}  # Good
```

---

## Integration Checklist

- [ ] Analyzer module created in `sha/analyzers/`
- [ ] `HEADER_KEY` defined (lowercase with hyphens)
- [ ] `CONFIG` dictionary complete
- [ ] `analyze()` function implemented
- [ ] Registered in `__init__.py` (ANALYZER_REGISTRY)
- [ ] Registered in `__init__.py` (CONFIG_REGISTRY)
- [ ] Tests created in `tests/`
- [ ] All tests passing (`pytest tests/test_new_header.py`)
- [ ] Added to `docs/analyzer-reference.md`
- [ ] Updated `CHANGELOG.md`
- [ ] Pre-commit hooks pass
- [ ] Type checking passes (`mypy`)

---

## See Also

- [Registry Pattern](REGISTRY_PATTERN.md) - How registration works
- [Components](COMPONENTS.md) - Analyzer layer details
- [Testing Guide](../TESTING.md) - Testing best practices
- [Contributing](../../CONTRIBUTING.md) - Development workflow
