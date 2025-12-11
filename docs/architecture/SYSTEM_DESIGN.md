# System Design

## High-Level Architecture

Security Header Analyzer uses a layered pipeline architecture with clear separation of concerns. Each layer has specific responsibilities and communicates through well-defined interfaces.

### Architecture Diagram

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

---

## Layer Responsibilities

### CLI Layer
**Purpose:** User interface and workflow orchestration

**Responsibilities:**
- Parse and validate command-line arguments
- Coordinate execution flow
- Handle exceptions at the top level
- Set appropriate exit codes
- Display output to user

**Module:** `sha/main.py`

---

### Fetcher Layer
**Purpose:** Safe HTTP header retrieval

**Responsibilities:**
- Execute HTTP HEAD requests
- Validate URLs against SSRF attacks
- Handle redirects securely
- Manage timeouts and errors
- Normalize header names

**Module:** `sha/fetcher.py`

**Security:** SSRF protection is the primary responsibility

---

### Analyzer Layer
**Purpose:** Coordinate analysis across all headers

**Responsibilities:**
- Dispatch to appropriate analyzers via registry
- Aggregate findings from all analyzers
- Maintain backward compatibility
- Ensure all registered headers are checked

**Module:** `sha/analyzer.py`

**Pattern:** Registry pattern for dynamic dispatch

---

### Individual Analyzers
**Purpose:** Header-specific validation logic

**Responsibilities:**
- Parse header values
- Apply validation rules
- Assess severity levels
- Generate recommendations
- Return structured findings

**Modules:** `sha/analyzers/*.py` (15 modules)

**Pattern:** Strategy pattern (interchangeable analyzers)

---

### Reporter Layer
**Purpose:** Format and present findings

**Responsibilities:**
- Format findings for human readability
- Serialize findings to JSON
- Calculate summary statistics
- Sort findings by severity

**Module:** `sha/reporter.py`

---

## Design Patterns

### 1. Registry Pattern

**Used in:** Analyzer registration

**Implementation:**
```python
from analyzers import ANALYZER_REGISTRY

for header_key, analyze_func in ANALYZER_REGISTRY.items():
    value = headers.get(header_key)
    finding = analyze_func(value)
    findings.append(finding)
```

**Benefits:**
- No modification of core code to add analyzers
- Easy to test analyzers in isolation
- Clear separation of concerns
- Extensible without changing existing code

---

### 2. Pipeline Pattern

**Used in:** Overall architecture

**Implementation:**
```
Input → Transform 1 → Transform 2 → Transform 3 → Output
URL   → Headers     → Findings    → Report     → Display
```

**Benefits:**
- Clear data flow
- Each stage is independent
- Easy to debug and test
- Can optimize individual stages

---

### 3. Strategy Pattern

**Used in:** Individual analyzers

**Implementation:**
```python
# All analyzers implement the same interface
def analyze(value: Optional[str]) -> Dict[str, Any]:
    """Analyze header value and return finding."""
```

**Benefits:**
- Interchangeable analysis strategies
- New strategies don't affect existing code
- Consistent interface for all analyzers
- Testable independently

---

### 4. Dependency Injection

**Used in:** Configuration management

**Implementation:**
```python
# Configuration passed to functions, not global state
def fetch_headers(url: str, timeout: int, max_redirects: int):
    pass
```

**Benefits:**
- No global state
- Testable with mock data
- Clear dependencies
- Flexible configuration

---

## Error Handling Strategy

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
    ├── 4xx errors (client)
    └── 5xx errors (server)
```

### Exit Code Mapping

```python
0   # Success - analysis completed
1   # Network error (timeout, connection failed, SSL)
2   # Invalid input (bad URL, invalid arguments)
3   # HTTP error (4xx, 5xx responses)
130 # User interruption (Ctrl+C)
```

**Rationale:** Standard Unix exit codes for automation compatibility

---

## Performance Characteristics

### Current Performance

| Operation | Time | Bottleneck |
|-----------|------|------------|
| HTTP Request | 10s max | Network latency |
| Analysis | < 1ms | In-memory only |
| Report Generation | < 1ms | String formatting |
| **Total** | ~Network time | **Dominated by HTTP** |

### Optimization Opportunities

**Not Currently Implemented** (to keep code simple):

1. **Parallel Requests** - Analyze multiple URLs concurrently
2. **Caching** - Cache DNS resolutions with TTL
3. **Connection Pooling** - Reuse HTTP connections
4. **Async I/O** - Use `asyncio` for non-blocking requests

**Trade-off:** Simplicity and minimal dependencies vs. performance

---

## Configuration Management

### Centralized Configuration

**Location:** `sha/config.py`

**Contents:**
- Default constants (timeout, user agent, redirects)
- Private IP ranges for SSRF protection
- Status constants (good/acceptable/bad/missing)
- Severity levels (critical/high/medium/low/info)
- Exception classes

### Per-Analyzer Configuration

**Location:** Each analyzer's `CONFIG` dictionary

**Contents:**
- Display name
- Severity when missing
- Validation rules
- User-facing messages
- Recommendations

**Benefit:** Analyzers are self-contained and portable

---

## Data Structures

### Finding Dictionary

```python
Finding = Dict[str, Any]  # Consider TypedDict for type safety

{
    "header_name": str,           # Display name
    "status": Literal["good", "acceptable", "bad", "missing"],
    "severity": Literal["critical", "high", "medium", "low", "info"],
    "message": str,               # Human-readable explanation
    "actual_value": Optional[str], # Current value (None if missing)
    "recommendation": Optional[str] # Fix suggestion (None if good)
}
```

### Configuration Dictionary

```python
Config = Dict[str, Any]  # Consider TypedDict for type safety

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

---

## See Also

- [Data Flow](DATA_FLOW.md) - Detailed request processing flow
- [Components](COMPONENTS.md) - Individual component specifications
- [Registry Pattern](REGISTRY_PATTERN.md) - Registry implementation details
- [Extensibility](EXTENSIBILITY.md) - Adding new analyzers
