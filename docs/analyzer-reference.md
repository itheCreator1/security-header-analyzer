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
- Missing: CRITICAL
- Bad configuration: CRITICAL
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
- **NEW: Detects 12 common CSP bypass patterns:**
  - JSONP endpoints (Google APIs, AngularJS CDN, AWS S3, Cloudflare, etc.)
  - Angular/AngularJS template injection vulnerabilities
  - User-uploaded content domains
  - Missing `base-uri` (allows base tag injection)
  - Missing/permissive `object-src` (Flash/plugin bypass)
  - `script-src 'self'` with file upload capability (stored XSS)
  - `unsafe-hashes` without proper context
  - `data:` URIs in `script-src`
  - `script-src-elem` without `script-src`
  - Dangling markup injection via `img-src`

**Severity Levels:**
- Missing: CRITICAL
- Contains unsafe-inline or unsafe-eval: HIGH
- **HIGH severity bypasses (JSONP, data URIs, Angular):** HIGH
- Wildcard sources: MEDIUM-HIGH
- **LOW/MEDIUM severity bypasses (base-uri, object-src):** Recommendations only
- Good configuration: INFO

**Good Values:**
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-xyz'; base-uri 'self'; object-src 'none'
Content-Security-Policy: default-src 'none'; script-src 'strict-dynamic' 'nonce-xyz'; base-uri 'none'
```

**Bad Values:**
```
Content-Security-Policy: default-src *
Content-Security-Policy: script-src 'unsafe-inline'
Content-Security-Policy: script-src 'self' https://ajax.googleapis.com (JSONP bypass)
Content-Security-Policy: script-src 'self' data: (data URI bypass)
```

**Common Bypasses Detected:**
```
# JSONP bypass via Google APIs
Content-Security-Policy: script-src 'self' https://accounts.google.com

# Angular template injection
Content-Security-Policy: script-src 'self' https://ajax.googleapis.com/ajax/libs/angularjs/

# AWS S3 JSONP endpoints
Content-Security-Policy: script-src 'self' https://mybucket.s3.amazonaws.com

# Missing base-uri (recommended in addition to script-src)
Content-Security-Policy: script-src 'self' 'nonce-xyz'
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
- Missing: HIGH
- Unsafe values: HIGH
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

### 10. X-XSS-Protection

**Module:** `sha/analyzers/x_xss_protection.py`

**Purpose:**
Legacy header that controlled browser XSS filters in Internet Explorer, Chrome, and Safari. Now deprecated. Modern recommendation is to explicitly disable it or rely on Content-Security-Policy.

**How It Works:**
- Checks for value `0` (explicitly disabled - recommended)
- Detects `1; mode=block` (legacy acceptable)
- Flags `1` alone as bad (creates vulnerabilities)

**Severity Levels:**
- Missing: LOW
- Value `0`: INFO (best)
- Value `1; mode=block`: ACCEPTABLE (legacy)
- Value `1`: BAD (medium severity)
- Unknown values: BAD

**Good Values:**
```
X-XSS-Protection: 0
```

**Acceptable Values:**
```
X-XSS-Protection: 1; mode=block
```

**Bad Values:**
```
X-XSS-Protection: 1
```

**References:**
- [OWASP: X-XSS-Protection](https://owasp.org/www-project-secure-headers/)
- [MDN: X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)

---

### 11. X-Download-Options

**Module:** `sha/analyzers/x_download_options.py`

**Purpose:**
Internet Explorer 8+ specific header that prevents the browser from executing downloaded HTML files in the context of the site, preventing Same Origin Policy violations.

**How It Works:**
- Checks for `noopen` value
- Any other value is flagged as bad

**Severity Levels:**
- Missing: LOW
- Value `noopen`: INFO
- Other values: BAD (low severity)

**Good Values:**
```
X-Download-Options: noopen
```

**References:**
- [OWASP: X-Download-Options](https://owasp.org/www-project-secure-headers/)

---

### 12. X-Permitted-Cross-Domain-Policies

**Module:** `sha/analyzers/x_permitted_cross_domain_policies.py`

**Purpose:**
Controls whether Adobe Flash Player, Adobe Acrobat, or PDF documents can load cross-domain policy files from the web server. Prevents untrusted Flash/PDF content from accessing site data.

**How It Works:**
- Checks for `none` (best - completely prohibits policy files)
- Detects `master-only` (acceptable - allows only /crossdomain.xml)
- Flags permissive values: `all`, `by-content-type`, `by-ftp-filename`

**Severity Levels:**
- Missing: MEDIUM
- Value `none`: INFO (best)
- Value `master-only`: ACCEPTABLE (low severity)
- Value `all`: BAD (high severity)
- Values `by-content-type`, `by-ftp-filename`: BAD (medium severity)
- Unknown values: BAD (medium severity)

**Good Values:**
```
X-Permitted-Cross-Domain-Policies: none
```

**Acceptable Values:**
```
X-Permitted-Cross-Domain-Policies: master-only
```

**Bad Values:**
```
X-Permitted-Cross-Domain-Policies: all
X-Permitted-Cross-Domain-Policies: by-content-type
X-Permitted-Cross-Domain-Policies: by-ftp-filename
```

**References:**
- [OWASP: X-Permitted-Cross-Domain-Policies](https://owasp.org/www-project-secure-headers/)
- [Adobe: Cross-Domain Policy](https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/xdomain.html)

---

### 13. Set-Cookie

**Module:** `sha/analyzers/set_cookie.py`

**Purpose:**
Analyzes cookie security attributes to prevent session hijacking, XSS cookie theft, and CSRF attacks. Validates that cookies include proper security directives.

**How It Works:**
- Validates Secure, HttpOnly, and SameSite attributes
- **NEW: Validates cookie prefix constraints (__Secure-, __Host-)**
- **NEW: Analyzes Domain/Path scope for overly broad configurations**
- **NEW: Detects sensitive cookies (session/auth) with missing security**
- **NEW: Warns about excessive SameSite=None usage (third-party cookies)**
- Handles multiple Set-Cookie headers
- Provides aggregate analysis across all cookies

**Severity Levels:**
- Missing Secure or HttpOnly: HIGH
- Missing SameSite or SameSite=None without Secure: MEDIUM
- **Prefix violations (__Secure-/__Host- constraints):** HIGH
- **Sensitive cookie without security attributes:** HIGH
- **Overly broad Domain scope (e.g., "com"):** MEDIUM
- **Domain with leading dot or Path=/ on sensitive cookies:** LOW (recommendation only)
- Good configuration: INFO

**Good Values:**
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
Set-Cookie: __Host-session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
Set-Cookie: __Secure-token=xyz; Secure; HttpOnly; SameSite=Lax
```

**Bad Values:**
```
Set-Cookie: session=abc123
Set-Cookie: __Secure-session=abc123; HttpOnly; SameSite=Strict  (missing Secure - violates prefix)
Set-Cookie: __Host-session=abc123; Secure; HttpOnly; Domain=example.com  (has Domain - violates prefix)
Set-Cookie: PHPSESSID=xyz  (sensitive cookie, no security attributes)
Set-Cookie: tracking=123; Secure; HttpOnly; SameSite=None; Domain=com  (overly broad domain)
```

**Cookie Prefix Validation (RFC 6265bis):**
- `__Secure-` prefix requires:
  - Secure attribute
- `__Host-` prefix requires:
  - Secure attribute
  - No Domain attribute
  - Path=/ or omitted

**Scope Analysis:**
- Detects Domain with leading dot (applies to all subdomains)
- Detects overly broad domains (e.g., "com", "co.uk")
- Warns when sensitive cookies have Path=/ (exposed to entire site)

**Sensitive Cookie Detection:**
Detects cookies that appear to contain sensitive data based on name patterns:
- Session identifiers: session, sess, sid, jsessionid, phpsessid
- Authentication: auth, token, jwt, bearer, access, refresh
- User identifiers: user, uid, userid
- CSRF tokens: csrf, xsrf

**SameSite=None Frequency Warning:**
- Triggers when ≥50% of cookies use SameSite=None
- Warns about third-party cookie privacy risks
- Recommends evaluating necessity of cross-site cookie access

**References:**
- [RFC 6265bis Cookie Prefixes](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)
- [OWASP: Session Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes)
- [MDN: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)

---

### 14. Cache-Control

**Module:** `sha/analyzers/cache_control.py`

**Purpose:**
Controls caching behavior to prevent sensitive data leakage through browser and proxy caches. Ensures that sensitive pages (login forms, account details, personal data) are not cached where unauthorized parties could access them.

**How It Works:**
- Parses Cache-Control directives (no-store, no-cache, must-revalidate, private, public, max-age)
- **NEW: Detects directive conflicts (mutually exclusive or redundant combinations)**
- **NEW: Validates must-revalidate usage for long cache durations**
- **NEW: Supports stale-while-revalidate and stale-if-error directives**
- Evaluates appropriateness for sensitive vs. static content

**Severity Levels:**
- Missing (for sensitive pages): MEDIUM
- **Directive conflicts (public+private, no-store+max-age):** MEDIUM (conflicts trigger BAD status)
- Long max-age without must-revalidate: LOW (recommendation only)
- Good configuration: INFO

**Good Values (Sensitive Pages):**
```
Cache-Control: no-store, no-cache, must-revalidate, private
Cache-Control: no-store, private
```

**Good Values (Static Resources):**
```
Cache-Control: public, max-age=31536000, immutable
Cache-Control: public, max-age=604800, must-revalidate
```

**Acceptable Values:**
```
Cache-Control: private, max-age=0
Cache-Control: max-age=604800  (without must-revalidate - gets recommendation)
```

**Bad Values:**
```
Cache-Control: public, max-age=86400  (for sensitive data)
Cache-Control: public, private  (mutually exclusive - CONFLICT)
Cache-Control: no-store, max-age=3600  (max-age redundant with no-store - CONFLICT)
Cache-Control: no-store, no-cache  (no-cache redundant with no-store - CONFLICT)
Cache-Control: private, s-maxage=3600  (s-maxage inapplicable with private - CONFLICT)
```

**Directive Conflicts Detected:**

1. **public + private (Mutually Exclusive)** - MEDIUM severity
   ```
   Cache-Control: public, private
   # Recommendation: Remove either 'public' or 'private' - use 'private' for sensitive data
   ```

2. **no-store + max-age (Redundant)** - LOW severity
   ```
   Cache-Control: no-store, max-age=3600
   # Recommendation: Remove 'max-age' - 'no-store' already prevents caching
   ```

3. **no-store + no-cache (Redundant)** - LOW severity
   ```
   Cache-Control: no-store, no-cache
   # Recommendation: Remove 'no-cache' - 'no-store' is stronger
   ```

4. **private + s-maxage (Inapplicable)** - LOW severity
   ```
   Cache-Control: private, s-maxage=3600
   # Recommendation: Remove 's-maxage' - only applies to shared caches, inapplicable with 'private'
   ```

**must-revalidate Validation:**

Warns when long cache durations (>1 day) are used without must-revalidate or immutable:
```
Cache-Control: max-age=604800  (7 days)
# Recommendation: Consider adding 'must-revalidate' to prevent serving stale content if origin is unreachable
```

This prevents browsers from serving very stale content when the origin server is unreachable.

**Modern Stale-* Directives:**

Supports RFC 5861 stale-while-revalidate and stale-if-error:
```
Cache-Control: max-age=600, stale-while-revalidate=30
Cache-Control: max-age=600, stale-if-error=86400
```

These directives enable graceful degradation by allowing slightly stale content to be served while revalidating in the background.

**Common Use Cases:**

| Content Type | Recommended Configuration |
|--------------|---------------------------|
| Login pages | `no-store, private` |
| Account pages | `no-store, no-cache, must-revalidate, private` |
| API responses (sensitive) | `no-store, private` |
| Static assets (versioned) | `public, max-age=31536000, immutable` |
| Static assets (unversioned) | `public, max-age=3600, must-revalidate` |
| Dynamic content (public) | `public, max-age=60, must-revalidate` |

**References:**
- [MDN: Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)
- [RFC 7234: HTTP Caching](https://datatracker.ietf.org/doc/html/rfc7234)
- [RFC 5861: HTTP stale-while-revalidate](https://datatracker.ietf.org/doc/html/rfc5861)
- [OWASP: Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching)

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
