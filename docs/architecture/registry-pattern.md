# Registry Pattern

## Overview

The Registry Pattern is a key architectural pattern used in Security Header Analyzer to enable dynamic analyzer registration without modifying core code. This makes the system highly extensible and maintainable.

## Problem Solved

**Without Registry:**
- Core analyzer code needs modification for each new header
- Tight coupling between analyzer coordination and individual analyzers
- Hard to test analyzers in isolation
- Difficult to maintain as analyzers grow

**With Registry:**
- Add analyzers without touching core code
- Loose coupling via registry lookup
- Easy to test each analyzer independently
- Clear separation of concerns

---

## Implementation

### Registry Definition

**Location:** `sha/analyzers/__init__.py`

```python
from typing import Any, Callable, Dict

# Import all analyzer modules
from . import (
    hsts,
    xframe,
    content_type,
    csp,
    referrer_policy,
    permissions_policy,
    coep,
    coop,
    corp,
    set_cookie,
    cache_control,
    expect_ct,
    x_xss_protection,
    x_download_options,
    x_permitted_cross_domain_policies,
)

# Registry mapping header keys to analyzer functions
ANALYZER_REGISTRY: Dict[str, Callable] = {
    hsts.HEADER_KEY: hsts.analyze,
    xframe.HEADER_KEY: xframe.analyze,
    content_type.HEADER_KEY: content_type.analyze,
    csp.HEADER_KEY: csp.analyze,
    referrer_policy.HEADER_KEY: referrer_policy.analyze,
    permissions_policy.HEADER_KEY: permissions_policy.analyze,
    coep.HEADER_KEY: coep.analyze,
    coop.HEADER_KEY: coop.analyze,
    corp.HEADER_KEY: corp.analyze,
    set_cookie.HEADER_KEY: set_cookie.analyze,
    cache_control.HEADER_KEY: cache_control.analyze,
    expect_ct.HEADER_KEY: expect_ct.analyze,
    x_xss_protection.HEADER_KEY: x_xss_protection.analyze,
    x_download_options.HEADER_KEY: x_download_options.analyze,
    x_permitted_cross_domain_policies.HEADER_KEY: x_permitted_cross_domain_policies.analyze,
}

# Registry mapping header keys to configurations
CONFIG_REGISTRY: Dict[str, Dict[str, Any]] = {
    hsts.HEADER_KEY: hsts.CONFIG,
    xframe.HEADER_KEY: xframe.CONFIG,
    # ... (same pattern for all analyzers)
}
```

### Registry Usage

**Location:** `sha/analyzer.py`

```python
from .analyzers import ANALYZER_REGISTRY

def analyze_headers(headers: Dict[str, str]) -> List[Finding]:
    """Analyze all headers using registered analyzers."""
    findings = []

    # Loop through registry
    for header_key, analyze_func in ANALYZER_REGISTRY.items():
        # Get header value (None if missing)
        value = headers.get(header_key)

        # Call analyzer function
        finding = analyze_func(value)

        # Aggregate results
        findings.append(finding)

    return findings
```

---

## Analyzer Contract

Every analyzer must follow this contract to be registry-compatible:

### 1. Module Structure

```python
"""
Analyzer docstring.
"""

from typing import Any, Dict, Optional

# 1. Header key (REQUIRED)
HEADER_KEY = "header-name"  # lowercase with hyphens

# 2. Configuration dictionary (REQUIRED)
CONFIG = {
    "display_name": str,
    "severity_missing": str,
    "description": str,
    "validation": {...},
    "messages": {...},
    "recommendations": {...}
}

# 3. Analyze function (REQUIRED)
def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze header value.

    Args:
        value: Header value or None if missing

    Returns:
        Finding dictionary with status, severity, message, etc.
    """
    pass
```

### 2. Function Signature

```python
def analyze(value: Optional[str]) -> Dict[str, Any]:
```

**Must accept:**
- `value`: `Optional[str]` - Header value or None if missing

**Must return:**
- Dictionary with keys: `header_name`, `status`, `severity`, `message`, `actual_value`, `recommendation`

### 3. Return Value Format

```python
{
    "header_name": str,           # Display name (from CONFIG)
    "status": str,                # "good" | "acceptable" | "bad" | "missing"
    "severity": str,              # "critical" | "high" | "medium" | "low" | "info"
    "message": str,               # Human-readable explanation
    "actual_value": Optional[str], # Current header value (None if missing)
    "recommendation": Optional[str] # Fix suggestion (None if status is "good")
}
```

---

## Registration Process

### Adding a New Analyzer

**Step 1:** Create analyzer module

```python
# sha/analyzers/new_header.py

HEADER_KEY = "new-security-header"

CONFIG = {...}

def analyze(value: Optional[str]) -> Dict[str, Any]:
    # Implementation
    pass
```

**Step 2:** Import in `__init__.py`

```python
# sha/analyzers/__init__.py

from . import new_header
```

**Step 3:** Register in dictionaries

```python
ANALYZER_REGISTRY[new_header.HEADER_KEY] = new_header.analyze
CONFIG_REGISTRY[new_header.HEADER_KEY] = new_header.CONFIG
```

**Done!** The analyzer is now automatically called during analysis.

---

## Benefits

### 1. Open/Closed Principle
- **Open for extension:** Add new analyzers easily
- **Closed for modification:** Core code never changes

### 2. Single Responsibility
- Registry handles dispatching
- Analyzers handle validation
- Clear separation

### 3. Testability
- Test analyzers in complete isolation
- Mock registry for integration tests
- No dependencies between analyzers

### 4. Maintainability
- Each analyzer is self-contained
- Easy to locate and modify
- Clear structure for all analyzers

### 5. Discoverability
- Single source of truth (registry)
- Easy to see all available analyzers
- Simple to audit coverage

---

## Alternative Approaches (Not Used)

### 1. Factory Pattern
```python
def create_analyzer(header_type):
    if header_type == "hsts":
        return HSTSAnalyzer()
    elif header_type == "csp":
        return CSPAnalyzer()
    # ... (requires modification for each new analyzer)
```

**Why not:** Requires modifying factory for each new analyzer

### 2. Class Hierarchy
```python
class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, value):
        pass

class HSTSAnalyzer(BaseAnalyzer):
    def analyze(self, value):
        pass
```

**Why not:** Adds unnecessary complexity for simple function-based analyzers

### 3. Plugin System
```python
# Load analyzers dynamically from external packages
import importlib
```

**Why not:** Overkill for current needs, may be added in future

---

## Registry Utilities

### Get All Header Keys

```python
def get_all_header_keys() -> List[str]:
    """Get list of all registered header keys."""
    return list(ANALYZER_REGISTRY.keys())
```

### Get Specific Analyzer

```python
def get_analyzer(header_key: str) -> Callable:
    """
    Get analyzer function for a specific header.

    Raises:
        KeyError: If header_key is not registered
    """
    return ANALYZER_REGISTRY[header_key]
```

### Get Configuration

```python
def get_config(header_key: str) -> Dict[str, Any]:
    """
    Get configuration for a specific header.

    Raises:
        KeyError: If header_key is not registered
    """
    return CONFIG_REGISTRY[header_key]
```

---

## See Also

- [Extensibility Guide](extensibility-guide.md) - Step-by-step guide to adding analyzers
- [Components](components.md) - Analyzer layer details
- [System Design](system-design.md) - Overall architecture
