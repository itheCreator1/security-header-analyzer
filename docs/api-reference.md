# API Documentation

## Overview

While Security Header Analyzer is primarily a CLI tool, it's designed as a Python library that can be used programmatically in your own applications. This document covers the public API for library usage.

## Installation

```bash
pip install -e .
# Or from source
pip install git+https://github.com/itheCreator1/security-header-analyzer.git
```

## Quick Start

### Basic Usage

```python
from sha.fetcher import fetch_headers
from sha.analyzer import analyze_headers
from sha.reporter import generate_report

# Fetch headers
headers = fetch_headers("https://example.com")

# Analyze headers
findings = analyze_headers(headers)

# Generate report
report = generate_report(findings, url="https://example.com", format="text")
print(report)
```

### With Error Handling

```python
from sha.fetcher import fetch_headers
from sha.analyzer import analyze_headers
from sha.config import NetworkError, InvalidURLError, HTTPError

try:
    headers = fetch_headers("https://example.com", timeout=10)
    findings = analyze_headers(headers)

    for finding in findings:
        print(f"{finding['severity']}: {finding['header_name']}")
        print(f"  Status: {finding['status']}")
        print(f"  Message: {finding['message']}")

except InvalidURLError as e:
    print(f"Invalid URL: {e}")
except NetworkError as e:
    print(f"Network error: {e}")
except HTTPError as e:
    print(f"HTTP {e.status_code}: {e}")
```

---

## API Reference

### Fetcher Module (`sha.fetcher`)

#### `fetch_headers()`

Fetch HTTP headers from a URL with SSRF protection.

```python
def fetch_headers(
    url: str,
    timeout: int = 10,
    follow_redirects: bool = True,
    max_redirects: int = 5,
    user_agent: Optional[str] = None
) -> Dict[str, Union[str, List[str]]]:
    """
    Fetch HTTP headers from a URL using HEAD request.

    Args:
        url: Target URL (protocol added if missing)
        timeout: Request timeout in seconds (default: 10)
        follow_redirects: Whether to follow redirects (default: True)
        max_redirects: Maximum redirects to follow (default: 5)
        user_agent: Custom User-Agent string (default: SecurityHeaderAnalyzer/1.0.0)

    Returns:
        Dictionary of headers with lowercase keys.
        Most headers are str, but 'set-cookie' is List[str] to capture all cookies.

    Raises:
        InvalidURLError: If URL is invalid or unsafe (SSRF)
        NetworkError: If network request fails
        HTTPError: If server returns error status code (4xx, 5xx)

    Example:
        >>> headers = fetch_headers("https://example.com")
        >>> print(headers.get("strict-transport-security"))
        max-age=31536000

        >>> headers = fetch_headers(
        ...     "https://example.com",
        ...     timeout=5,
        ...     follow_redirects=False
        ... )
    """
```

#### `fetch_headers_safe()`

Safe wrapper that returns errors instead of raising exceptions.

```python
def fetch_headers_safe(
    url: str,
    timeout: int = 10,
    follow_redirects: bool = True,
    max_redirects: int = 5,
    user_agent: Optional[str] = None
) -> Tuple[Dict[str, Union[str, List[str]]], Optional[Exception]]:
    """
    Safely fetch headers without raising exceptions.

    Returns:
        Tuple of (headers_dict, error)
        - If successful: (headers, None)
        - If failed: ({}, error_exception)
        - On HTTPError with headers: (headers, error_exception)

    Example:
        >>> headers, error = fetch_headers_safe("https://example.com")
        >>> if error:
        ...     print(f"Failed: {error}")
        ... else:
        ...     print(f"Got {len(headers)} headers")
    """
```

#### `normalize_url()`

Add HTTPS protocol to URL if missing.

```python
def normalize_url(url: str) -> str:
    """
    Normalize URL by adding HTTPS protocol if missing.

    Args:
        url: URL string (may or may not include protocol)

    Returns:
        Normalized URL with protocol

    Example:
        >>> normalize_url("example.com")
        'https://example.com'
        >>> normalize_url("http://example.com")
        'http://example.com'
    """
```

#### `validate_url_safety()`

Validate URL is safe to fetch (SSRF protection).

```python
def validate_url_safety(url: str) -> None:
    """
    Validate that a URL is safe to fetch (SSRF protection).

    Checks:
    1. URL is properly formatted
    2. Hostname doesn't resolve to private IP addresses
    3. Hostname is not localhost or similar

    Args:
        url: URL to validate

    Raises:
        InvalidURLError: If URL is invalid or unsafe

    Example:
        >>> validate_url_safety("https://example.com")  # OK
        >>> validate_url_safety("https://localhost")  # Raises InvalidURLError
        >>> validate_url_safety("https://192.168.1.1")  # Raises InvalidURLError
    """
```

---

### Analyzer Module (`sha.analyzer`)

#### `analyze_headers()`

Analyze headers using all registered analyzers.

```python
def analyze_headers(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Analyze all headers using registered analyzers.

    Args:
        headers: Dictionary of headers (lowercase keys)

    Returns:
        List of Finding dictionaries:
        [{
            "header_name": str,
            "status": "good" | "acceptable" | "bad" | "missing",
            "severity": "critical" | "high" | "medium" | "low" | "info",
            "message": str,
            "actual_value": Optional[str],
            "recommendation": Optional[str]
        }, ...]

    Example:
        >>> headers = {"strict-transport-security": "max-age=31536000"}
        >>> findings = analyze_headers(headers)
        >>> for finding in findings:
        ...     print(f"{finding['header_name']}: {finding['status']}")
    """
```

---

### Reporter Module (`sha.reporter`)

#### `generate_report()`

Generate formatted report from findings.

```python
def generate_report(
    findings: List[Dict[str, Any]],
    url: str,
    timestamp: Optional[str] = None,
    format: str = "text"
) -> str:
    """
    Generate report in text or JSON format.

    Args:
        findings: List of Finding dictionaries from analyze_headers()
        url: Target URL that was analyzed
        timestamp: ISO 8601 timestamp (auto-generated if None)
        format: "text" for human-readable, "json" for machine-readable

    Returns:
        Formatted report string

    Example:
        # Text format
        >>> report = generate_report(findings, "https://example.com", format="text")
        >>> print(report)

        # JSON format
        >>> import json
        >>> report_json = generate_report(findings, "https://example.com", format="json")
        >>> data = json.loads(report_json)
        >>> print(data["summary"]["high_issues"])
    """
```

#### `format_text_report()`

Format findings as human-readable text.

```python
def format_text_report(
    findings: List[Dict[str, Any]],
    url: str,
    timestamp: str
) -> str:
    """
    Create human-readable terminal output.

    Includes:
    - Header with URL and timestamp
    - Summary section with issue counts by severity
    - Detailed findings sorted by severity
    """
```

#### `format_json_report()`

Serialize findings to JSON.

```python
def format_json_report(
    findings: List[Dict[str, Any]],
    url: str,
    timestamp: str
) -> str:
    """
    Serialize to JSON for automation.

    Returns:
        JSON string with structure:
        {
            "url": str,
            "timestamp": str,
            "summary": {
                "critical_issues": int,
                "high_issues": int,
                "medium_issues": int,
                "low_issues": int
            },
            "findings": [...]
        }
    """
```

---

### Individual Analyzers (`sha.analyzers.*`)

Each analyzer module exports:

```python
HEADER_KEY: str  # Lowercase header name
CONFIG: Dict[str, Any]  # Configuration dictionary
analyze(value: Optional[str]) -> Dict[str, Any]  # Analysis function
```

#### Example: HSTS Analyzer

```python
from sha.analyzers import hsts

# Analyze HSTS header
finding = hsts.analyze("max-age=31536000; includeSubDomains")
print(finding["status"])  # "good"

# Check configuration
print(hsts.CONFIG["display_name"])  # "Strict-Transport-Security"
print(hsts.CONFIG["severity_missing"])  # "high"
```

#### Available Analyzers

```python
from sha.analyzers import (
    hsts,            # Strict-Transport-Security
    xframe,          # X-Frame-Options
    content_type,    # X-Content-Type-Options
    csp,             # Content-Security-Policy
    referrer_policy, # Referrer-Policy
    permissions_policy,  # Permissions-Policy
    coep,            # Cross-Origin-Embedder-Policy
    coop,            # Cross-Origin-Opener-Policy
    corp             # Cross-Origin-Resource-Policy
)
```

---

### Configuration Module (`sha.config`)

#### Constants

```python
from sha.config import (
    VERSION,                # "1.0.0"
    DEFAULT_TIMEOUT,        # 10
    DEFAULT_MAX_REDIRECTS,  # 5
    DEFAULT_USER_AGENT,     # "SecurityHeaderAnalyzer/1.0.0 (...)"
    PRIVATE_IP_RANGES,      # List of blocked IP ranges
    LOCALHOST_NAMES,        # ["localhost", "0.0.0.0"]
    SEVERITY_LEVELS,        # ["critical", "high", "medium", "low", "info"]
    STATUS_GOOD,            # "good"
    STATUS_ACCEPTABLE,      # "acceptable"
    STATUS_BAD,             # "bad"
    STATUS_MISSING          # "missing"
)
```

#### Exceptions

```python
from sha.config import (
    SecurityHeaderAnalyzerError,  # Base exception
    NetworkError,                  # Network-related errors
    InvalidURLError,               # Invalid/unsafe URLs
    HTTPError                      # HTTP error responses
)

# HTTPError has additional attributes:
try:
    fetch_headers("https://example.com")
except HTTPError as e:
    print(e.status_code)  # e.g., 404
    print(e.headers)      # Headers dictionary (may be available)
```

---

## Advanced Usage

### Analyze Multiple URLs

```python
from sha.fetcher import fetch_headers_safe
from sha.analyzer import analyze_headers

urls = ["https://example.com", "https://example.org", "https://example.net"]

for url in urls:
    headers, error = fetch_headers_safe(url, timeout=5)

    if error:
        print(f"{url}: Error - {error}")
        continue

    findings = analyze_headers(headers)
    high_severity = [f for f in findings if f["severity"] in ["critical", "high"]]

    print(f"{url}: {len(high_severity)} high-severity issues")
```

### Custom Analysis

```python
from sha.fetcher import fetch_headers
from sha.analyzers import hsts, csp

headers = fetch_headers("https://example.com")

# Analyze only specific headers
hsts_finding = hsts.analyze(headers.get("strict-transport-security"))
csp_finding = csp.analyze(headers.get("content-security-policy"))

if hsts_finding["status"] == "missing":
    print("WARNING: No HSTS header!")

if csp_finding["status"] == "bad":
    print(f"CSP issue: {csp_finding['message']}")
```

### Integration with Testing Frameworks

```python
import pytest
from sha.fetcher import fetch_headers
from sha.analyzer import analyze_headers

def test_production_headers():
    """Ensure production site has proper security headers."""
    headers = fetch_headers("https://production.example.com")
    findings = analyze_headers(headers)

    # No critical or high severity issues allowed
    critical = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]

    assert len(critical) == 0, f"Critical issues: {critical}"
    assert len(high) == 0, f"High severity issues: {high}"

    # Specific headers must be present
    hsts = next(f for f in findings if f["header_name"] == "Strict-Transport-Security")
    assert hsts["status"] == "good", "HSTS must be properly configured"
```

### CI/CD Integration

```python
#!/usr/bin/env python3
"""
CI/CD script to check security headers.
Exit code 0 if all good, 1 if issues found.
"""
import sys
from sha.fetcher import fetch_headers
from sha.analyzer import analyze_headers

def main():
    headers = fetch_headers("https://staging.example.com")
    findings = analyze_headers(headers)

    # Count high-severity issues
    high_severity = [
        f for f in findings
        if f["severity"] in ["critical", "high"]
    ]

    if high_severity:
        print(f"FAILED: {len(high_severity)} high-severity issues found")
        for finding in high_severity:
            print(f"  - {finding['header_name']}: {finding['message']}")
        sys.exit(1)

    print("PASSED: All security headers properly configured")
    sys.exit(0)

if __name__ == "__main__":
    main()
```

---

## Type Hints

All public API functions have comprehensive type hints. Enable type checking with mypy:

```bash
mypy your_script.py
```

Example with type annotations:

```python
from typing import Dict, List, Optional, Any
from sha.fetcher import fetch_headers
from sha.analyzer import analyze_headers

def analyze_url(url: str, timeout: int = 10) -> List[Dict[str, Any]]:
    """Analyze headers with full type safety."""
    headers: Dict[str, str] = fetch_headers(url, timeout=timeout)
    findings: List[Dict[str, Any]] = analyze_headers(headers)
    return findings
```

---

## Best Practices

### 1. Always Handle Exceptions

```python
from sha.config import NetworkError, InvalidURLError, HTTPError

try:
    headers = fetch_headers(url)
    findings = analyze_headers(headers)
except InvalidURLError:
    # Invalid/unsafe URL
    pass
except NetworkError:
    # Network issues
    pass
except HTTPError as e:
    # HTTP error, but headers may still be available
    if e.headers:
        findings = analyze_headers(e.headers)
```

### 2. Use Safe Wrappers for Batch Processing

```python
from sha.fetcher import fetch_headers_safe

urls = [...]  # Many URLs
results = []

for url in urls:
    headers, error = fetch_headers_safe(url)
    if not error:
        findings = analyze_headers(headers)
        results.append((url, findings))
```

### 3. Configure Timeouts Appropriately

```python
# Quick checks
headers = fetch_headers(url, timeout=5)

# Slow networks
headers = fetch_headers(url, timeout=30)

# No redirects for maximum speed
headers = fetch_headers(url, timeout=5, follow_redirects=False)
```

### 4. Validate URLs Before Batch Operations

```python
from sha.fetcher import validate_url_safety, normalize_url

urls = [...]
safe_urls = []

for url in urls:
    try:
        normalized = normalize_url(url)
        validate_url_safety(normalized)
        safe_urls.append(normalized)
    except InvalidURLError as e:
        print(f"Skipping {url}: {e}")

# Now fetch from safe_urls
```

---

## Performance Tips

1. **Use `fetch_headers_safe()` for bulk operations** - Avoids exception overhead
2. **Set shorter timeouts** - Default 10s may be too long
3. **Disable redirects when possible** - Faster and more secure
4. **Consider async version** - For analyzing many URLs (not yet implemented)

---

## Limitations

1. **No caching** - Each call fetches fresh headers
2. **Synchronous only** - Blocks on I/O (async version planned)
3. **No connection pooling** - New connection per request
4. **SSRF vulnerability** - TOCTOU issue documented in SECURITY.md

---

## Further Reading

- [Architecture Documentation](./ARCHITECTURE.md) - System design
- [Analyzer Documentation](./analyzer-reference.md) - Header analysis details
- [Security Policy](../SECURITY.md) - Security considerations
- [Contributing Guide](../CONTRIBUTING.md) - Development workflow

---

**Need help?** Open an issue on [GitHub](https://github.com/itheCreator1/security-header-analyzer/issues)
