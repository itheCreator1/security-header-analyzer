# Component Specifications

## Overview

This document provides detailed specifications for each component in the Security Header Analyzer architecture. Each component has specific responsibilities, key functions, and well-defined interfaces.

---

## 1. CLI Layer

**Module:** [`sha/main.py`](../../sha/main.py)

### Responsibilities
- Parse command-line arguments using `argparse`
- Validate user input (timeout, max_redirects)
- Orchestrate the analysis workflow
- Handle exceptions and set appropriate exit codes
- Display output to user

### Key Functions

#### `main() -> NoReturn`
Main entry point that coordinates the entire analysis workflow.

**Workflow:**
1. Parse arguments
2. Fetch headers
3. Analyze headers
4. Generate report
5. Display and exit

**Exit Codes:**
- `0` - Success
- `1` - Network error
- `2` - Invalid input
- `3` - HTTP error
- `130` - User interruption (Ctrl+C)

#### `parse_args(args: Optional[List[str]]) -> argparse.Namespace`
Parse and validate command-line arguments.

**Arguments:**
- `url` (required) - Target URL to analyze
- `--json` - Output in JSON format
- `--timeout N` - Request timeout in seconds (default: 10)
- `--no-redirects` - Don't follow redirects
- `--max-redirects N` - Maximum redirects to follow (default: 5)
- `--user-agent STR` - Custom User-Agent string
- `--debug` - Enable debug logging
- `--version` - Show version and exit

**Validation:**
- Timeout must be positive
- max_redirects must be non-negative

### Data Flow

```
User Input (argv)
    ↓
parse_args()
    ↓
fetch_headers()
    ↓
analyze_headers()
    ↓
generate_report()
    ↓
print() + exit()
```

---

## 2. Fetcher Layer

**Module:** [`sha/fetcher.py`](../../sha/fetcher.py)

### Responsibilities
- Make HTTP HEAD requests to target URLs
- Implement SSRF (Server-Side Request Forgery) protection
- Validate redirect destinations against DNS rebinding
- Handle network errors gracefully
- Normalize header names to lowercase
- Handle multiple Set-Cookie headers specially

### Key Functions

#### `fetch_headers(url, timeout, follow_redirects, max_redirects, user_agent) -> Dict[str, str]`
Fetch headers with full error handling and security checks.

**Process:**
1. Normalize URL (add https:// if missing)
2. Validate URL safety (SSRF protection)
3. Make HTTP HEAD request
4. Handle redirects if enabled
5. Validate redirect destination (DNS rebinding protection)
6. Normalize header names to lowercase
7. Handle multiple Set-Cookie headers

**Returns:** Dictionary of normalized headers

**Raises:**
- `NetworkError` - Connection, timeout, or SSL errors
- `InvalidURLError` - Malformed URL or SSRF attempt blocked
- `HTTPError` - HTTP 4xx/5xx responses

#### `normalize_url(url: str) -> str`
Add HTTPS protocol if missing.

**Examples:**
```python
normalize_url("example.com")        # → "https://example.com"
normalize_url("http://example.com") # → "http://example.com"
```

#### `validate_url_safety(url: str) -> None`
SSRF protection via DNS validation.

**Checks:**
1. URL is properly formatted
2. Hostname doesn't resolve to private IP addresses
3. Hostname is not localhost or similar

**Raises:** `InvalidURLError` if unsafe

**Known Limitation:** TOCTOU vulnerability (see Security section)

#### `validate_redirect_destination(final_url: str) -> None`
DNS rebinding protection after redirects.

Re-validates the final URL after following redirects to prevent DNS rebinding attacks.

### Security Features

**Blocked IP Ranges:**
- IPv4: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- IPv6: `::1`, `fc00::/7`, `fe80::/10`

**Blocked Hostnames:**
- `localhost`, `local`, `localdomain`

**Configuration:**
- Configurable timeout (default: 10 seconds)
- Configurable redirect limit (default: 5 redirects)
- SSL/TLS certificate verification enabled

### Special Cases

**Multiple Set-Cookie Headers:**
```python
# HTTP response may have multiple Set-Cookie headers
# Combined into single value with '; ' separator
_normalize_headers_with_cookies(response) -> Dict[str, str]
```

---

## 3. Analyzer Layer

**Module:** [`sha/analyzer.py`](../../sha/analyzer.py)

### Responsibilities
- Coordinate analysis across all registered analyzers
- Maintain backward compatibility with legacy code
- Aggregate findings from individual analyzers
- Ensure all registered headers are checked

### Key Functions

#### `analyze_headers(headers: Dict[str, str]) -> List[Finding]`
Main entry point that coordinates analysis across all registered analyzers.

**Algorithm:**
```python
findings = []
for header_key, analyze_func in ANALYZER_REGISTRY.items():
    value = headers.get(header_key)  # None if missing
    finding = analyze_func(value)    # Call analyzer
    findings.append(finding)         # Aggregate
return findings
```

**Returns:** List of Finding dictionaries

### Registry Pattern

Uses `ANALYZER_REGISTRY` from `sha/analyzers/__init__.py` to dispatch to the appropriate analyzer for each header.

**Benefits:**
- No modification needed to add new analyzers
- Analyzers tested in isolation
- Clear separation of concerns

### Backward Compatibility

Exports commonly used analyzer functions for legacy code:
```python
from .analyzers import hsts, csp, xframe
```

---

## 4. Individual Analyzers

**Modules:** [`sha/analyzers/*.py`](../../sha/analyzers/) (15 total)

### Common Structure

Every analyzer follows this pattern:

```python
"""Analyzer docstring."""

from typing import Any, Dict, Optional

# 1. Header key (lowercase)
HEADER_KEY = "header-name"

# 2. Configuration dictionary
CONFIG = {
    "display_name": "Header-Name",
    "severity_missing": "high",
    "description": "Brief description",
    "validation": {...},
    "messages": {...},
    "recommendations": {...}
}

# 3. Analysis function
def analyze(value: Optional[str]) -> Dict[str, Any]:
    """Analyze header value and return finding."""
    if value is None:
        return {
            "header_name": CONFIG["display_name"],
            "status": "missing",
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"]["missing"],
            "actual_value": None,
            "recommendation": CONFIG["recommendations"]["missing"]
        }

    # Validation logic here
    # ...

    return finding
```

### Analyzer Responsibilities

1. **Parse** header values into components
2. **Validate** against best practices
3. **Assess** severity levels
4. **Generate** clear recommendations
5. **Return** structured findings

### Current Analyzers

| Module | Header | Severity Missing |
|--------|--------|------------------|
| `hsts.py` | Strict-Transport-Security | Critical |
| `csp.py` | Content-Security-Policy | Critical |
| `xframe.py` | X-Frame-Options | High |
| `referrer_policy.py` | Referrer-Policy | High |
| `content_type.py` | X-Content-Type-Options | Medium |
| `set_cookie.py` | Set-Cookie | Medium |
| `cache_control.py` | Cache-Control | Medium |
| `expect_ct.py` | Expect-CT | Medium |
| `x_permitted_cross_domain_policies.py` | X-Permitted-Cross-Domain-Policies | Medium |
| `x_xss_protection.py` | X-XSS-Protection | Low (deprecated) |
| `x_download_options.py` | X-Download-Options | Low |
| `permissions_policy.py` | Permissions-Policy | Low |
| `coep.py` | Cross-Origin-Embedder-Policy | Low |
| `coop.py` | Cross-Origin-Opener-Policy | Low |
| `corp.py` | Cross-Origin-Resource-Policy | Low |

### Example: HSTS Analyzer

**Validation Logic:**
1. Check if header is missing → Critical
2. Parse max-age value
3. Check max-age >= 126 days (10,886,400 seconds)
4. Check for includeSubDomains directive
5. Check for preload directive
6. Assign status: good / acceptable / bad

**Status Assignment:**
- **Good:** max-age >= 1 year + includeSubDomains + preload
- **Acceptable:** max-age >= 126 days + includeSubDomains
- **Bad:** max-age < 126 days or malformed

---

## 5. Registry System

**Module:** [`sha/analyzers/__init__.py`](../../sha/analyzers/__init__.py)

### Responsibilities
- Import all analyzer modules
- Maintain ANALYZER_REGISTRY dictionary
- Maintain CONFIG_REGISTRY dictionary
- Provide utility functions for registry access

### Key Data Structures

#### ANALYZER_REGISTRY

Maps header keys to analyzer functions:

```python
ANALYZER_REGISTRY: Dict[str, Callable] = {
    "strict-transport-security": hsts.analyze,
    "x-frame-options": xframe.analyze,
    # ... 15 total entries
}
```

#### CONFIG_REGISTRY

Maps header keys to configuration dictionaries:

```python
CONFIG_REGISTRY: Dict[str, Dict[str, Any]] = {
    "strict-transport-security": hsts.CONFIG,
    "x-frame-options": xframe.CONFIG,
    # ... 15 total entries
}
```

### Utility Functions

```python
def get_all_header_keys() -> List[str]
def get_analyzer(header_key: str) -> Callable
def get_config(header_key: str) -> Dict[str, Any]
```

---

## 6. Reporter Layer

**Module:** [`sha/reporter.py`](../../sha/reporter.py)

### Responsibilities
- Format findings for human readability (text mode)
- Serialize findings to JSON (automation mode)
- Calculate summary statistics
- Sort findings by severity

### Key Functions

#### `generate_report(findings, url, format) -> str`
Main entry point supporting text and JSON formats.

**Parameters:**
- `findings: List[Finding]` - Analysis results
- `url: str` - Target URL
- `format: str` - "text" or "json"

**Returns:** Formatted report string

#### `format_text_report(findings, url) -> str`
Create human-readable terminal output.

**Format:**
```
======================================================================
SECURITY HEADER ANALYSIS REPORT
======================================================================

URL: https://example.com
Timestamp: 2025-12-12T10:00:00.000Z

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

#### `format_json_report(findings, url) -> str`
Serialize to JSON for automation.

**Structure:**
```json
{
    "url": "https://example.com",
    "timestamp": "2025-12-12T10:00:00.000Z",
    "summary": {
        "critical": 0,
        "high": 2,
        "medium": 1,
        "low": 0,
        "info": 12
    },
    "findings": [...]
}
```

#### `calculate_summary(findings) -> Dict[str, int]`
Count issues by severity level.

**Returns:**
```python
{
    "critical": 0,
    "high": 2,
    "medium": 1,
    "low": 0,
    "info": 12
}
```

#### `sort_findings_by_severity(findings) -> List[Finding]`
Order findings from critical → high → medium → low → info.

Uses `SEVERITY_RANK` from config.py for ordering.

### Supporting Functions

- `get_severity_label(severity) -> str` - Format severity for display
- `get_timestamp() -> str` - ISO 8601 timestamp
- `get_total_issues(summary) -> int` - Sum non-info issues
- `format_summary_oneline(summary) -> str` - Compact summary

---

## 7. Configuration Module

**Module:** [`sha/config.py`](../../sha/config.py)

### Responsibilities
- Define default constants
- Define exception classes
- Define private IP ranges for SSRF protection
- Define status and severity constants

### Constants

```python
DEFAULT_TIMEOUT = 10               # seconds
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_USER_AGENT = "SecurityHeaderAnalyzer/1.0.0"

# Status constants
STATUS_GOOD = "good"
STATUS_ACCEPTABLE = "acceptable"
STATUS_BAD = "bad"
STATUS_MISSING = "missing"

# Severity constants
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"
```

### Exception Classes

```python
class SecurityHeaderAnalyzerError(Exception):
    """Base exception."""

class NetworkError(SecurityHeaderAnalyzerError):
    """Network-related errors."""

class InvalidURLError(SecurityHeaderAnalyzerError):
    """Invalid or unsafe URLs."""

class HTTPError(SecurityHeaderAnalyzerError):
    """HTTP errors (4xx, 5xx)."""
```

### Private IP Ranges

Defines SSRF protection lists:
- `PRIVATE_IP_RANGES: List[str]`
- `LOCALHOST_NAMES: Set[str]`

---

## See Also

- [System Design](SYSTEM_DESIGN.md) - Architecture overview
- [Data Flow](DATA_FLOW.md) - Request processing pipeline
- [Registry Pattern](REGISTRY_PATTERN.md) - Analyzer registration
- [Extensibility](EXTENSIBILITY.md) - Adding new analyzers
- [Security](SECURITY.md) - SSRF protection details
