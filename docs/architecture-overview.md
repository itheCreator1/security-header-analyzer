# Architecture Documentation

## Overview

Security Header Analyzer is built with a modular, extensible architecture that separates concerns and makes it easy to add new security header analyzers. The system follows a pipeline pattern with clear data flow from CLI input to formatted output.

## System Design

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                            │
│                       (main.py)                              │
│  • Argument parsing                                          │
│  • Error handling                                            │
│  • Exit code management                                      │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                      Fetcher Layer                           │
│                     (fetcher.py)                             │
│  • HTTP HEAD requests                                        │
│  • SSRF protection                                           │
│  • DNS rebinding validation                                  │
│  • SSL/TLS verification                                      │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                     Analyzer Layer                           │
│                    (analyzer.py)                             │
│  • Registry-based analyzer dispatch                          │
│  • Header analysis coordination                              │
│  • Finding aggregation                                       │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                Individual Analyzers                          │
│              (analyzers/*.py)                                │
│  • HSTS, CSP, X-Frame-Options, etc.                         │
│  • Header-specific validation logic                          │
│  • Severity assessment                                       │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                     Reporter Layer                           │
│                    (reporter.py)                             │
│  • Text formatting                                           │
│  • JSON serialization                                        │
│  • Summary calculation                                       │
└─────────────────────────────────────────────────────────────┘
```

## Component Interactions

### 1. CLI Layer (`main.py`)

**Responsibilities:**
- Parse command-line arguments using `argparse`
- Validate user input (timeout, max_redirects)
- Orchestrate the analysis workflow
- Handle exceptions and set appropriate exit codes
- Display output to user

**Key Functions:**
```python
def main() -> NoReturn:
    """Main entry point that coordinates the entire analysis."""

def parse_args(args: Optional[List[str]]) -> argparse.Namespace:
    """Parse and validate command-line arguments."""
```

**Data Flow:**
```
User Input → parse_args() → fetch_headers() → analyze_headers()
→ generate_report() → print() → exit()
```

### 2. Fetcher Layer (`fetcher.py`)

**Responsibilities:**
- Make HTTP HEAD requests to target URLs
- Implement SSRF (Server-Side Request Forgery) protection
- Validate redirect destinations against DNS rebinding
- Handle network errors gracefully
- Normalize header names to lowercase

**Key Functions:**
```python
def fetch_headers(url: str, ...) -> Dict[str, str]:
    """Fetch headers with full error handling and security checks."""

def validate_url_safety(url: str) -> None:
    """SSRF protection: validate URL doesn't resolve to private IPs."""

def validate_redirect_destination(final_url: str) -> None:
    """DNS rebinding protection: re-validate after redirects."""
```

**Security Features:**
- Blocks private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Blocks IPv6 private ranges (::1, fc00::/7, fe80::/10)
- Validates both initial URL and redirect destinations
- Configurable timeout and redirect limits

**Known Limitations:**
- TOCTOU vulnerability: DNS can change between validation and request
- Documented in code and SECURITY.md

### 3. Analyzer Layer (`analyzer.py`)

**Responsibilities:**
- Coordinate analysis across all registered analyzers
- Maintain backward compatibility with legacy code
- Aggregate findings from individual analyzers

**Key Functions:**
```python
def analyze_headers(headers: Dict[str, str]) -> List[Finding]:
    """Analyze all headers using registered analyzers."""
```

**Registry Pattern:**
```python
from analyzers import ANALYZER_REGISTRY

for header_key, analyze_func in ANALYZER_REGISTRY.items():
    value = headers.get(header_key)
    finding = analyze_func(value)
    findings.append(finding)
```

### 4. Individual Analyzers (`analyzers/*.py`)

**Structure:**
Each analyzer module follows a consistent pattern:

```python
# 1. Header key (lowercase)
HEADER_KEY = "strict-transport-security"

# 2. Configuration dictionary
CONFIG = {
    "display_name": "Strict-Transport-Security",
    "severity_missing": "high",
    "description": "Forces HTTPS connections",
    "validation": {...},
    "messages": {...},
    "recommendations": {...}
}

# 3. Analysis function
def analyze(value: Optional[str]) -> Dict[str, Any]:
    """Analyze the header value and return a finding."""
    # Returns: {
    #     "header_name": str,
    #     "status": "good" | "acceptable" | "bad" | "missing",
    #     "severity": "critical" | "high" | "medium" | "low" | "info",
    #     "message": str,
    #     "actual_value": Optional[str],
    #     "recommendation": Optional[str]
    # }
```

**Current Analyzers:**
1. `hsts.py` - Strict-Transport-Security
2. `xframe.py` - X-Frame-Options
3. `content_type.py` - X-Content-Type-Options
4. `csp.py` - Content-Security-Policy
5. `referrer_policy.py` - Referrer-Policy
6. `permissions_policy.py` - Permissions-Policy
7. `coep.py` - Cross-Origin-Embedder-Policy
8. `coop.py` - Cross-Origin-Opener-Policy
9. `corp.py` - Cross-Origin-Resource-Policy

### 5. Registry System (`analyzers/__init__.py`)

**The Registry Pattern:**

```python
from . import hsts, xframe, content_type, csp, referrer_policy
from . import permissions_policy, coep, coop, corp

# Analyzer function registry
ANALYZER_REGISTRY: Dict[str, Callable] = {
    hsts.HEADER_KEY: hsts.analyze,
    xframe.HEADER_KEY: xframe.analyze,
    content_type.HEADER_KEY: content_type.analyze,
    # ... etc
}

# Configuration registry
CONFIG_REGISTRY: Dict[str, Dict[str, Any]] = {
    hsts.HEADER_KEY: hsts.CONFIG,
    xframe.HEADER_KEY: xframe.CONFIG,
    # ... etc
}
```

**Benefits:**
- Easy to add new analyzers (just register them)
- No modification needed to core analyzer.py
- Consistent interface for all analyzers
- Testable in isolation

### 6. Reporter Layer (`reporter.py`)

**Responsibilities:**
- Format findings for human readability (text mode)
- Serialize findings to JSON (automation mode)
- Calculate summary statistics
- Sort findings by severity

**Key Functions:**
```python
def generate_report(findings: List[Finding], ...) -> str:
    """Generate report in text or JSON format."""

def format_text_report(findings: List[Finding], ...) -> str:
    """Create human-readable terminal output."""

def format_json_report(findings: List[Finding], ...) -> str:
    """Serialize to JSON for automation."""

def calculate_summary(findings: List[Finding]) -> Dict[str, int]:
    """Count issues by severity level."""
```

**Text Output Format:**
```
======================================================================
SECURITY HEADER ANALYSIS REPORT
======================================================================

URL: https://example.com
Timestamp: 2025-12-04T12:00:00.000Z

SUMMARY
----------------------------------------------------------------------
Critical Issues: 0
High Issues:     2
Medium Issues:   1
Low Issues:      0

DETAILED FINDINGS
----------------------------------------------------------------------

[High] Strict-Transport-Security
Status: missing
Message: HSTS header is not set
Recommendation: Add 'Strict-Transport-Security: max-age=31536000; ...'
```

## Data Structures

### Finding Dictionary

```python
Finding = Dict[str, Any]  # TypedDict recommended

{
    "header_name": str,           # Display name (e.g., "Strict-Transport-Security")
    "status": Literal["good", "acceptable", "bad", "missing"],
    "severity": Literal["critical", "high", "medium-high", "medium", "low", "info"],
    "message": str,               # Human-readable explanation
    "actual_value": Optional[str], # Current header value (None if missing)
    "recommendation": Optional[str] # How to fix (None if status is "good")
}
```

### Configuration Dictionary

```python
Config = Dict[str, Any]  # TypedDict recommended

{
    "display_name": str,
    "severity_missing": str,
    "description": str,
    "validation": {
        "good": List[str],
        "acceptable": List[str],
        "bad": List[str]
    },
    "messages": {
        "good": str,
        "acceptable": str,
        "bad": str,
        "missing": str
    },
    "recommendations": {
        "missing": str,
        "bad": str
    }
}
```

## Extensibility: Adding New Analyzers

### Step-by-Step Guide

**1. Create Analyzer Module**

Create `sha/analyzers/new_header.py`:

```python
"""
Analyzer for New-Security-Header.

This header provides XYZ security protection...
"""

from typing import Dict, Any, Optional

HEADER_KEY = "new-security-header"  # lowercase!

CONFIG = {
    "display_name": "New-Security-Header",
    "severity_missing": "medium",
    "description": "Brief description",
    "validation": {
        "good": ["secure-value"],
        "acceptable": ["acceptable-value"],
        "bad": ["unsafe-value"],
    },
    "messages": {
        "good": "Header is properly configured",
        "acceptable": "Header is set but could be improved",
        "bad": "Header has unsafe configuration",
        "missing": "Header is not set",
    },
    "recommendations": {
        "missing": "Add 'New-Security-Header: secure-value'",
        "bad": "Change to 'secure-value'",
    },
}

def analyze(value: Optional[str]) -> Dict[str, Any]:
    """Analyze New-Security-Header value."""
    if value is None:
        return {
            "header_name": CONFIG["display_name"],
            "status": "missing",
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"]["missing"],
            "actual_value": None,
            "recommendation": CONFIG["recommendations"]["missing"],
        }

    # Add your validation logic here
    value_lower = value.lower().strip()

    if value_lower in CONFIG["validation"]["good"]:
        return {
            "header_name": CONFIG["display_name"],
            "status": "good",
            "severity": "info",
            "message": CONFIG["messages"]["good"],
            "actual_value": value,
            "recommendation": None,
        }

    # ... more validation ...

    # Default to bad
    return {
        "header_name": CONFIG["display_name"],
        "status": "bad",
        "severity": "high",
        "message": CONFIG["messages"]["bad"],
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["bad"],
    }
```

**2. Register Analyzer**

Update `sha/analyzers/__init__.py`:

```python
from . import new_header

ANALYZER_REGISTRY[new_header.HEADER_KEY] = new_header.analyze
CONFIG_REGISTRY[new_header.HEADER_KEY] = new_header.CONFIG
```

**3. Add Tests**

Create `tests/test_new_header.py`:

```python
import pytest
from sha.analyzers.new_header import analyze, CONFIG

class TestNewHeaderAnalyzer:
    def test_missing_header(self):
        result = analyze(None)
        assert result["status"] == "missing"
        assert result["severity"] == CONFIG["severity_missing"]

    def test_good_value(self):
        result = analyze("secure-value")
        assert result["status"] == "good"
        assert result["severity"] == "info"

    # Add more tests...
```

**4. Update Documentation**

- Add entry to `docs/analyzer-reference.md`
- Update CHANGELOG.md
- Update README.md if it's a major addition

**That's it!** The analyzer is now fully integrated.

## Design Patterns

### 1. Registry Pattern
- Allows dynamic registration of analyzers
- No modification of core code needed
- Easy to test in isolation

### 2. Pipeline Pattern
- Clear data flow: Fetch → Analyze → Report
- Each stage is independent
- Easy to debug and test

### 3. Strategy Pattern
- Each analyzer implements the same interface
- Interchangeable analysis strategies
- New strategies can be added without changing clients

### 4. Dependency Injection
- Configuration passed to functions
- No global state
- Testable with mock data

## Error Handling

### Exception Hierarchy

```python
SecurityHeaderAnalyzerError (base)
├── NetworkError
│   ├── Timeout
│   ├── Connection failed
│   ├── SSL error
│   └── Too many redirects
├── InvalidURLError
│   ├── Malformed URL
│   ├── SSRF blocked
│   └── Invalid scheme
└── HTTPError
    ├── 4xx errors
    └── 5xx errors
```

### Exit Codes

```python
0  # Success
1  # Network error
2  # Invalid input
3  # HTTP error
130  # User interruption (Ctrl+C)
```

## Testing Architecture

### Test Organization

```
tests/
├── conftest.py              # Shared fixtures
├── test_integration.py      # End-to-end tests
├── test_analyzer.py         # Analyzer orchestration tests
├── test_fetcher.py          # Network layer tests
├── test_reporter.py         # Output formatting tests
├── test_config.py           # Configuration tests
└── test_<header>.py         # Individual analyzer tests
```

### Test Patterns

**1. Unit Tests:**
```python
def test_analyze_good_hsts():
    result = hsts.analyze("max-age=31536000")
    assert result["status"] == "good"
```

**2. Integration Tests:**
```python
def test_full_workflow(mock_requests):
    # Mock HTTP response
    # Run full analysis
    # Verify output
```

**3. Fixtures:**
```python
@pytest.fixture
def all_headers_good():
    return {
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        # ...
    }
```

## Performance Considerations

### Current Performance

- **HTTP Request**: 10-second timeout (configurable)
- **Analysis**: < 1ms per header (in-memory only)
- **Report Generation**: < 1ms (formatting only)
- **Total**: Dominated by network latency

### Optimization Opportunities

1. **Parallel Requests**: Analyze multiple URLs concurrently
2. **Caching**: Cache DNS resolutions (with TTL)
3. **Connection Pooling**: Reuse HTTP connections
4. **Async I/O**: Use asyncio for non-blocking requests

Currently not implemented to keep code simple and dependencies minimal.

## Security Architecture

### SSRF Protection

```python
# 1. Normalize URL (add https://)
url = normalize_url(url)

# 2. Validate URL doesn't resolve to private IP
validate_url_safety(url)  # Checks DNS resolution

# 3. Make request
response = requests.head(url, ...)

# 4. Validate redirect destination
if response.url != url:
    validate_redirect_destination(response.url)
```

### Known Vulnerabilities

See [SECURITY.md](../SECURITY.md) for:
- TOCTOU vulnerability details
- DNS rebinding attack vectors
- Mitigation strategies

## Configuration Management

### Centralized Configuration (`config.py`)

```python
# Constants
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_USER_AGENT = "SecurityHeaderAnalyzer/1.0.0"

# Private IP ranges (SSRF protection)
PRIVATE_IP_RANGES = [...]

# Severity levels
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]
```

### Per-Analyzer Configuration

Each analyzer has its own `CONFIG` dictionary with:
- Display name
- Severity levels
- Validation rules
- Messages
- Recommendations

## Future Enhancements

### Planned Features

1. **Plugin System**: Load analyzers dynamically from external packages
2. **Custom Rules**: User-defined validation rules
3. **Batch Mode**: Analyze multiple URLs from file
4. **Continuous Monitoring**: Schedule periodic checks
5. **Diff Mode**: Compare headers over time
6. **Export Formats**: HTML, PDF, CSV reports

### Architectural Changes Needed

1. **Plugin System**:
   - Use `importlib` for dynamic loading
   - Define `AnalyzerProtocol` interface

2. **Async Support**:
   - Rewrite fetcher with `aiohttp`
   - Update CLI to use `asyncio`

3. **Storage Layer**:
   - Add database support (SQLite)
   - Historical tracking

---

## References

- [Original Repository](https://github.com/itheCreator1/security-header-analyzer)
- [SECURITY.md](../SECURITY.md) - Security considerations
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development guide
- [API.md](./API.md) - API documentation
- [analyzer-reference.md](./analyzer-reference.md) - Analyzer details
