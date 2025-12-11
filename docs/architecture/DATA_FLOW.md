# Data Flow

## Overview

Security Header Analyzer follows a linear pipeline pattern where data flows through five distinct stages from user input to formatted output. Each stage transforms the data in a specific way.

## Pipeline Stages

```
┌──────┐   ┌─────────┐   ┌──────────┐   ┌──────────┐   ┌────────┐
│ User │ → │  Parse  │ → │  Fetch   │ → │ Analyze  │ → │ Report │
│ Input│   │   Args  │   │ Headers  │   │ Headers  │   │ Format │
└──────┘   └─────────┘   └──────────┘   └──────────┘   └────────┘
```

---

## Stage 1: Argument Parsing

**Input:** Command-line arguments (argv)

**Processing:**
1. Parse arguments with `argparse`
2. Validate timeout (must be positive)
3. Validate max_redirects (must be non-negative)
4. Normalize URL (add https:// if missing)

**Output:** `argparse.Namespace` object

**Error Handling:** Invalid arguments → exit code 2

```python
# Input: ['https://example.com', '--timeout', '5']
# Output: Namespace(url='https://example.com', timeout=5, ...)
```

---

## Stage 2: Header Fetching

**Input:** URL string + options

**Processing:**
1. Normalize URL (add https:// prefix)
2. Validate URL safety (SSRF check via DNS)
3. Execute HTTP HEAD request
4. Validate redirect destination (DNS rebinding check)
5. Normalize header names to lowercase
6. Handle special case: multiple Set-Cookie headers

**Output:** `Dict[str, str]` (headers dictionary)

**Error Handling:**
- Network errors → NetworkError exception → exit code 1
- SSRF blocked → InvalidURLError exception → exit code 2
- HTTP errors → HTTPError exception → exit code 3

```python
# Input: 'https://example.com'
# Output: {
#     'strict-transport-security': 'max-age=31536000',
#     'x-frame-options': 'DENY',
#     'x-content-type-options': 'nosniff'
# }
```

---

## Stage 3: Header Analysis

**Input:** Headers dictionary

**Processing:**
1. Loop through ANALYZER_REGISTRY
2. For each registered header:
   - Get header value from dict (None if missing)
   - Call analyzer's `analyze()` function
   - Receive Finding dictionary
3. Aggregate all findings into list

**Output:** `List[Finding]` (list of finding dictionaries)

**Error Handling:** None (analyzers never raise exceptions)

```python
# Input: {'strict-transport-security': 'max-age=31536000', ...}
# Output: [
#     {
#         'header_name': 'Strict-Transport-Security',
#         'status': 'acceptable',
#         'severity': 'low',
#         'message': 'HSTS is present but could be improved',
#         'actual_value': 'max-age=31536000',
#         'recommendation': 'Add includeSubDomains directive'
#     },
#     {...}
# ]
```

---

## Stage 4: Report Generation

**Input:** List of findings + URL + format

**Processing:**
1. Sort findings by severity (critical → high → medium → low → info)
2. Calculate summary statistics (count by severity)
3. Format according to output mode:
   - **Text mode:** Create human-readable report with headers
   - **JSON mode:** Serialize to JSON with metadata

**Output:** String (formatted report)

**Error Handling:** None (formatting never fails)

```python
# Input: [Finding1, Finding2, ...], format='text'
# Output: """
# ======================================================================
# SECURITY HEADER ANALYSIS REPORT
# ======================================================================
#
# URL: https://example.com
# Timestamp: 2025-12-12T10:00:00.000Z
#
# SUMMARY
# ----------------------------------------------------------------------
# Critical Issues: 0
# High Issues:     2
# ...
# """
```

---

## Stage 5: Output Display

**Input:** Formatted report string

**Processing:**
1. Print report to stdout
2. Set exit code based on success/failure

**Output:** Console output + exit code

```python
print(report)
sys.exit(0)  # Success
```

---

## Complete Data Flow Example

### Input
```bash
python -m sha https://example.com --json --timeout 5
```

### Stage-by-Stage Transformation

**1. Parse Args:**
```python
Namespace(
    url='https://example.com',
    json=True,
    timeout=5,
    no_redirects=False,
    max_redirects=5,
    user_agent='SecurityHeaderAnalyzer/1.0.0',
    debug=False
)
```

**2. Fetch Headers:**
```python
{
    'strict-transport-security': 'max-age=31536000',
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'self'",
    'referrer-policy': 'strict-origin-when-cross-origin'
}
```

**3. Analyze Headers:**
```python
[
    {
        'header_name': 'Strict-Transport-Security',
        'status': 'acceptable',
        'severity': 'low',
        'message': 'HSTS is present but could be improved',
        'actual_value': 'max-age=31536000',
        'recommendation': 'Add includeSubDomains; preload'
    },
    {
        'header_name': 'X-Frame-Options',
        'status': 'good',
        'severity': 'info',
        'message': 'X-Frame-Options is properly configured',
        'actual_value': 'DENY',
        'recommendation': None
    },
    # ... 13 more findings
]
```

**4. Generate Report:**
```json
{
    "url": "https://example.com",
    "timestamp": "2025-12-12T10:00:00.000Z",
    "summary": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 1,
        "info": 14
    },
    "findings": [ ... ]
}
```

**5. Output:**
```
{JSON printed to stdout}
Exit code: 0
```

---

## Error Flow

### Network Error Example

```
User Input
    ↓
Parse Args ✓
    ↓
Fetch Headers ✗ (connection timeout)
    ↓
Raise NetworkError
    ↓
Catch in main()
    ↓
Print error message
    ↓
Exit with code 1
```

### SSRF Blocked Example

```
User Input: http://localhost/admin
    ↓
Parse Args ✓
    ↓
Normalize URL ✓
    ↓
Validate URL Safety ✗ (resolves to 127.0.0.1)
    ↓
Raise InvalidURLError("SSRF attempt blocked")
    ↓
Catch in main()
    ↓
Print error message
    ↓
Exit with code 2
```

---

## Data Transformations Summary

| Stage | Input Type | Output Type | Transform |
|-------|-----------|-------------|-----------|
| Parse Args | `List[str]` | `Namespace` | Parse & validate |
| Fetch | `str` (URL) | `Dict[str, str]` | HTTP request |
| Analyze | `Dict[str, str]` | `List[Finding]` | Validation logic |
| Report | `List[Finding]` | `str` | Formatting |
| Output | `str` | Console | Display |

---

## See Also

- [System Design](SYSTEM_DESIGN.md) - Architecture overview
- [Components](COMPONENTS.md) - Individual component details
- [Security](SECURITY.md) - SSRF protection in fetcher
