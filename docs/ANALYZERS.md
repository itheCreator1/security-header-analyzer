# Security Header Analyzers

## Overview

This document provides detailed information about each security header analyzer, including what the header does, how it's evaluated, severity levels, and configuration options.

## Analyzers

### 1. Strict-Transport-Security (HSTS)

**Module:** `sha/analyzers/hsts.py`

**Purpose:**  
Forces browsers to only communicate with the server over HTTPS, preventing protocol downgrade attacks and cookie hijacking.

**How It Works:**
- Analyzes the `max-age` directive (minimum 10886400 seconds / 126 days required)
- Checks for `includeSubDomains` directive
- Detects `preload` directive

**Severity Levels:**
- Missing: HIGH
- Bad configuration: HIGH  
- Good configuration: INFO

**Good Values:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Strict-Transport-Security: max-age=63072000
```

**Bad Values:**
```
Strict-Transport-Security: max-age=300  (too short)
```

**References:**
- [Mozilla: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [OWASP: HSTS](https://owasp.org/www-project-secure-headers/#strict-transport-security)

---

### 2. X-Frame-Options

**Module:** `sha/analyzers/xframe.py`

**Purpose:**  
Prevents clickjacking attacks by controlling whether the page can be framed.

**How It Works:**
- Checks for DENY or SAMEORIGIN directives
- Detects deprecated ALLOW-FROM directive

**Severity Levels:**
- Missing: HIGH
- DENY: INFO (best)
- SAMEORIGIN: INFO (good)
- ALLOW-FROM: HIGH (deprecated)

**Good Values:**
```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
```

**References:**
- [Mozilla: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)

---

### 3. X-Content-Type-Options

**Module:** `sha/analyzers/content_type.py`

**Purpose:**  
Prevents MIME-sniffing attacks by forcing browsers to respect declared Content-Type.

**How It Works:**
- Checks for `nosniff` directive

**Severity Levels:**
- Missing: MEDIUM-HIGH
- Present: INFO

**Good Values:**
```
X-Content-Type-Options: nosniff
```

---

### 4. Content-Security-Policy (CSP)

**Module:** `sha/analyzers/csp.py`

**Purpose:**  
Mitigates XSS and data injection attacks by controlling which resources can be loaded.

**How It Works:**
- Parses CSP directives
- Detects `unsafe-inline` and `unsafe-eval`
- Checks for wildcard sources (`*`)
- Validates nonce/hash usage
- Detects `strict-dynamic`

**Severity Levels:**
- Missing: HIGH
- Contains unsafe-inline or unsafe-eval: HIGH
- Wildcard sources: MEDIUM-HIGH
- Good configuration: INFO

**Good Values:**
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-xyz'
Content-Security-Policy: default-src 'none'; script-src 'strict-dynamic'
```

**Bad Values:**
```
Content-Security-Policy: default-src *
Content-Security-Policy: script-src 'unsafe-inline'
```

---

### 5. Referrer-Policy

**Module:** `sha/analyzers/referrer_policy.py`

**Purpose:**  
Controls how much referrer information is sent with requests.

**How It Works:**
- Evaluates policy strictness
- Recommends stricter policies when appropriate

**Severity Levels:**
- Missing: MEDIUM
- Unsafe values: MEDIUM
- Good values: INFO

**Good Values:**
```
Referrer-Policy: no-referrer
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: same-origin
```

**Bad Values:**
```
Referrer-Policy: unsafe-url
Referrer-Policy: origin
```

---

### 6. Permissions-Policy

**Module:** `sha/analyzers/permissions_policy.py`

**Purpose:**  
Controls which browser features and APIs can be used.

**How It Works:**
- Parses feature directives
- Validates allowlist syntax
- Checks for sensible defaults

**Severity Levels:**
- Missing: LOW
- Present: INFO

**Good Values:**
```
Permissions-Policy: geolocation=(), microphone=(), camera=()
Permissions-Policy: payment=(self)
```

---

### 7. Cross-Origin-Embedder-Policy (COEP)

**Module:** `sha/analyzers/coep.py`

**Purpose:**  
Enables cross-origin isolation, protecting against Spectre attacks.

**How It Works:**
- Checks for `require-corp` or `credentialless`

**Severity Levels:**
- Missing: LOW
- Present: INFO

**Good Values:**
```
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Embedder-Policy: credentialless
```

---

### 8. Cross-Origin-Opener-Policy (COOP)

**Module:** `sha/analyzers/coop.py`

**Purpose:**  
Isolates browsing context from cross-origin windows.

**How It Works:**
- Checks for isolation level
- `same-origin` is strongest

**Severity Levels:**
- Missing: LOW
- Present: INFO

**Good Values:**
```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin-allow-popups
```

---

### 9. Cross-Origin-Resource-Policy (CORP)

**Module:** `sha/analyzers/corp.py`

**Purpose:**  
Controls which origins can load the resource.

**How It Works:**
- Validates policy value

**Severity Levels:**
- Missing: LOW
- Present: INFO

**Good Values:**
```
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Resource-Policy: same-site
Cross-Origin-Resource-Policy: cross-origin
```

---

## Severity Level Guide

- **CRITICAL**: Immediate security risk (currently unused)
- **HIGH**: Significant security vulnerability
- **MEDIUM-HIGH**: Important security improvement
- **MEDIUM**: Recommended security enhancement
- **LOW**: Nice-to-have security feature
- **INFO**: Properly configured (no action needed)

---

## Configuration Format

Each analyzer follows this structure:

```python
CONFIG = {
    "display_name": "Header-Name",
    "severity_missing": "high",
    "description": "What this header does",
    "validation": {
        "good": ["list", "of", "good", "values"],
        "acceptable": ["acceptable", "values"],
        "bad": ["unsafe", "values"]
    },
    "messages": {
        "good": "Message for good configuration",
        "acceptable": "Message for acceptable configuration",
        "bad": "Message for bad configuration",
        "missing": "Message when header is missing"
    },
    "recommendations": {
        "missing": "How to add the header",
        "bad": "How to fix bad configuration"
    }
}
```

## Further Reading

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [SecurityHeaders.com](https://securityheaders.com/)
