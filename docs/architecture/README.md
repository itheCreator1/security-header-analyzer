# Architecture Documentation

## Overview

Security Header Analyzer is built with a modular, extensible architecture that separates concerns and makes it easy to add new security header analyzers. The system follows a pipeline pattern with clear data flow from CLI input to formatted output.

## Architecture at a Glance

```
CLI → Fetcher → Analyzer → Reporter
      (SSRF)    (Registry)  (Format)
```

**Pipeline Flow:**
1. **CLI Layer** - Parse args, handle errors, orchestrate workflow
2. **Fetcher Layer** - HTTP requests with SSRF protection
3. **Analyzer Layer** - Registry-based analyzer dispatch
4. **Reporter Layer** - Text/JSON output formatting

---

## Documentation Index

### Core Architecture

- **[System Design](system-design.md)** - High-level architecture and design patterns
  - Layer responsibilities
  - Component diagram
  - Design patterns used

- **[Data Flow](data-flow.md)** - Pipeline pattern and request flow
  - End-to-end request processing
  - Data transformations
  - Error handling flow

- **[Components](components.md)** - Detailed component specifications
  - CLI Layer (main.py)
  - Fetcher Layer (fetcher.py)
  - Analyzer Layer (analyzer.py)
  - Reporter Layer (reporter.py)
  - Individual Analyzers (analyzers/*.py)

### Advanced Topics

- **[Registry Pattern](registry-pattern.md)** - How analyzer registration works
  - ANALYZER_REGISTRY explained
  - CONFIG_REGISTRY explained
  - Benefits and trade-offs

- **[Extensibility Guide](extensibility-guide.md)** - Adding new analyzers
  - Step-by-step guide
  - Code templates
  - Testing patterns
  - Integration checklist

- **[Security Architecture](security-implementation.md)** - SSRF protection implementation
  - DNS validation flow
  - Redirect validation
  - TOCTOU vulnerability details
  - Mitigation strategies

- **[Future Enhancements](future-roadmap.md)** - Planned features and roadmap
  - Plugin system
  - Async support
  - Batch mode
  - Additional export formats

---

## Key Principles

### 1. Registry Pattern
Dynamic analyzer registration enables adding new headers without modifying core code.

### 2. Pipeline Architecture
Clear data flow through independent layers makes the system easy to understand and debug.

### 3. Security First
SSRF protection is built into the fetcher layer to prevent attacks against internal infrastructure.

### 4. Extensibility
Adding a new analyzer requires only 4 steps with no changes to existing code.

---

## Quick Reference

### Data Structures

**Finding:**
```python
{
    "header_name": str,
    "status": "good" | "acceptable" | "bad" | "missing",
    "severity": "critical" | "high" | "medium" | "low" | "info",
    "message": str,
    "actual_value": Optional[str],
    "recommendation": Optional[str]
}
```

**Config:**
```python
{
    "display_name": str,
    "severity_missing": str,
    "description": str,
    "validation": {...},
    "messages": {...},
    "recommendations": {...}
}
```

### File Structure

```
sha/
├── main.py              # CLI layer
├── fetcher.py           # Fetcher layer (SSRF protection)
├── analyzer.py          # Analyzer layer (orchestration)
├── reporter.py          # Reporter layer (formatting)
├── config.py            # Configuration and exceptions
└── analyzers/
    ├── __init__.py      # Registry
    └── *.py             # Individual analyzers (15 total)
```

---

## See Also

- [API Documentation](../API.md) - Programmatic usage
- [Analyzer Reference](../analyzer-reference.md) - Individual analyzer specs
- [Testing Guide](../TESTING.md) - Running and writing tests
- [Security Policy](../../security-implementation.md) - Vulnerability reporting
