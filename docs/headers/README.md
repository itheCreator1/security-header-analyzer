# Security Headers Index

## Overview

This directory contains detailed documentation for all 15 security headers analyzed by this tool. Each header has its own dedicated guide covering technical details, attack scenarios, and configuration examples.

---

## Quick Reference

| Header | Severity | Complexity | Status |
|--------|----------|------------|--------|
| [HSTS](#hsts) | **Critical** | Medium | Active |
| [CSP](#csp) | **Critical** | Hard | Active |
| [X-Frame-Options](#x-frame-options) | High | Easy | Active |
| [Referrer-Policy](#referrer-policy) | High | Medium | Active |
| [X-Content-Type-Options](#x-content-type-options) | Medium | Easy | Active |
| [Set-Cookie](#set-cookie) | Medium | Medium | Active |
| [Cache-Control](#cache-control) | Medium | Medium | Active |
| [Expect-CT](#expect-ct) | Medium | Easy | Deprecated |
| [X-Permitted-Cross-Domain-Policies](#x-permitted-cross-domain-policies) | Medium | Easy | Legacy |
| [X-XSS-Protection](#x-xss-protection) | Low | Easy | Deprecated |
| [X-Download-Options](#x-download-options) | Low | Easy | IE Only |
| [Permissions-Policy](#permissions-policy) | Low | Hard | Active |
| [COEP](#coep) | Low | Medium | Active |
| [COOP](#coop) | Low | Medium | Active |
| [CORP](#corp) | Low | Medium | Active |

---

## Headers by Severity

### Critical Severity

Missing these headers is a **critical security issue**.

#### HSTS
**Header:** `Strict-Transport-Security`
**File:** [HSTS.md](HSTS.md)
**Purpose:** Forces HTTPS connections to prevent protocol downgrade attacks

**Attack Prevented:** SSL stripping, man-in-the-middle attacks
**Best Practice:** `max-age=31536000; includeSubDomains; preload`

---

#### CSP
**Header:** `Content-Security-Policy`
**File:** [CSP.md](CSP.md)
**Purpose:** Controls which resources can be loaded to prevent XSS attacks

**Attack Prevented:** Cross-site scripting (XSS), code injection
**Best Practice:** `default-src 'self'; script-src 'self'` (strict policy)

---

### High Severity

Missing these headers is a **high-risk** security issue.

#### X-Frame-Options
**Header:** `X-Frame-Options`
**File:** [X-Frame-Options.md](X-Frame-Options.md)
**Purpose:** Prevents page from being embedded in frames to stop clickjacking

**Attack Prevented:** Clickjacking, UI redressing attacks
**Best Practice:** `DENY` or `SAMEORIGIN`

---

#### Referrer-Policy
**Header:** `Referrer-Policy`
**File:** [Referrer-Policy.md](Referrer-Policy.md)
**Purpose:** Controls how much referrer information is sent with requests

**Attack Prevented:** Information leakage through referrer headers
**Best Practice:** `strict-origin-when-cross-origin` or `no-referrer`

---

### Medium Severity

Missing these headers is a **medium-risk** security issue.

#### X-Content-Type-Options
**Header:** `X-Content-Type-Options`
**File:** [X-Content-Type-Options.md](X-Content-Type-Options.md)
**Purpose:** Prevents MIME type sniffing

**Attack Prevented:** MIME confusion attacks
**Best Practice:** `nosniff`

---

#### Set-Cookie
**Header:** `Set-Cookie`
**File:** [Set-Cookie.md](Set-Cookie.md)
**Purpose:** Secure cookie attributes (HttpOnly, Secure, SameSite)

**Attack Prevented:** Session hijacking, CSRF
**Best Practice:** Include `Secure; HttpOnly; SameSite=Strict` attributes

---

#### Cache-Control
**Header:** `Cache-Control`
**File:** [Cache-Control.md](Cache-Control.md)
**Purpose:** Controls caching behavior for sensitive content

**Attack Prevented:** Information disclosure through caches
**Best Practice:** `no-store, no-cache` for sensitive pages

---

#### Expect-CT
**Header:** `Expect-CT`
**File:** [Expect-CT.md](Expect-CT.md)
**Purpose:** Enforces Certificate Transparency

**Status:** ⚠️ Deprecated (Chrome 107+)
**Best Practice:** `enforce, max-age=86400`

---

#### X-Permitted-Cross-Domain-Policies
**Header:** `X-Permitted-Cross-Domain-Policies`
**File:** [X-Permitted-Cross-Domain-Policies.md](X-Permitted-Cross-Domain-Policies.md)
**Purpose:** Controls Flash and PDF cross-domain policies

**Attack Prevented:** Cross-domain data access by Flash/PDFs
**Best Practice:** `none`

---

### Low Severity

Missing these headers is a **low-risk** security issue.

#### X-XSS-Protection
**Header:** `X-XSS-Protection`
**File:** [X-XSS-Protection.md](X-XSS-Protection.md)
**Purpose:** Legacy XSS filter control (deprecated)

**Status:** ⚠️ Deprecated - Use CSP instead
**Best Practice:** `0` (disabled) or omit entirely

---

#### X-Download-Options
**Header:** `X-Download-Options`
**File:** [X-Download-Options.md](X-Download-Options.md)
**Purpose:** Prevents IE from executing downloads in site context

**Attack Prevented:** Drive-by downloads in IE8+
**Best Practice:** `noopen`

---

#### Permissions-Policy
**Header:** `Permissions-Policy`
**File:** [Permissions-Policy.md](Permissions-Policy.md)
**Purpose:** Controls browser feature access (camera, geolocation, etc.)

**Attack Prevented:** Unauthorized feature usage
**Best Practice:** Deny unused features

---

#### COEP
**Header:** `Cross-Origin-Embedder-Policy`
**File:** [COEP.md](COEP.md)
**Purpose:** Controls cross-origin resource embedding

**Attack Prevented:** Spectre attacks via cross-origin resources
**Best Practice:** `require-corp` for isolation

---

#### COOP
**Header:** `Cross-Origin-Opener-Policy`
**File:** [COOP.md](COOP.md)
**Purpose:** Isolates browsing context from cross-origin windows

**Attack Prevented:** Cross-origin attacks via window references
**Best Practice:** `same-origin` for isolation

---

#### CORP
**Header:** `Cross-Origin-Resource-Policy`
**File:** [CORP.md](CORP.md)
**Purpose:** Protects resources from cross-origin reads

**Attack Prevented:** Spectre attacks, cross-origin data theft
**Best Practice:** `same-origin` or `same-site`

---

## Headers by Category

### Transport Security
- [HSTS](HSTS.md) - Force HTTPS connections

### Content Security
- [CSP](CSP.md) - Control resource loading
- [X-Content-Type-Options](X-Content-Type-Options.md) - Prevent MIME sniffing

### Clickjacking Protection
- [X-Frame-Options](X-Frame-Options.md) - Frame embedding control

### Privacy
- [Referrer-Policy](Referrer-Policy.md) - Referrer information control

### Cookie Security
- [Set-Cookie](Set-Cookie.md) - Secure cookie attributes
- [Cache-Control](Cache-Control.md) - Caching control

### Cross-Origin Isolation
- [COEP](COEP.md) - Embedder policy
- [COOP](COOP.md) - Opener policy
- [CORP](CORP.md) - Resource policy

### Browser Features
- [Permissions-Policy](Permissions-Policy.md) - Feature control

### Legacy/Deprecated
- [X-XSS-Protection](X-XSS-Protection.md) - ⚠️ Deprecated
- [Expect-CT](Expect-CT.md) - ⚠️ Deprecated
- [X-Download-Options](X-Download-Options.md) - IE only
- [X-Permitted-Cross-Domain-Policies](X-Permitted-Cross-Domain-Policies.md) - Flash/PDF

---

## How to Use This Documentation

### For Each Header, You'll Find:

1. **Quick Reference** - Name, purpose, severity
2. **What It Does** - Plain English explanation
3. **How It Works** - Technical details
4. **Real-World Attack Scenarios** - Concrete exploit examples
5. **Configuration Examples** - Good ✅, Acceptable ⚠️, Bad ❌
6. **Common Mistakes** - Pitfalls and fixes
7. **Implementation Guide** - Framework-specific instructions
8. **Browser Compatibility** - Support table
9. **Additional Resources** - MDN, OWASP, RFCs

### Recommended Reading Order

**Beginners:**
1. Start with [X-Content-Type-Options](X-Content-Type-Options.md) (simplest)
2. Then [X-Frame-Options](X-Frame-Options.md) (easy to understand)
3. Move to [HSTS](HSTS.md) (more complex)
4. Finally [CSP](CSP.md) (most complex)

**Security Engineers:**
1. [Attack Scenarios Guide](../ATTACK_SCENARIOS.md) - Cross-header attacks
2. Critical headers: [HSTS](HSTS.md), [CSP](CSP.md)
3. High priority: [X-Frame-Options](X-Frame-Options.md), [Referrer-Policy](Referrer-Policy.md)
4. Review all others for comprehensive coverage

**Developers:**
1. [Best Practices](../SecurityHeadersBestPractices.md) - Quick configuration guide
2. Header docs relevant to your stack
3. [API Documentation](../API.md) - Programmatic usage

---

## Additional Resources

### Internal Documentation
- [Attack Scenarios](../ATTACK_SCENARIOS.md) - Real-world attack examples
- [Best Practices](../SecurityHeadersBestPractices.md) - Configuration recommendations
- [Analyzer Specifications](../ANALYZERS.md) - How we validate each header
- [API Reference](../API.md) - Library usage

### External Resources
- [Mozilla Observatory](https://observatory.mozilla.org/) - Test your site
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [SecurityHeaders.com](https://securityheaders.com/) - Online scanner

---

## Contributing

Found an issue or want to improve header documentation?

1. Check [Contributing Guidelines](../../CONTRIBUTING.md)
2. Open an issue or pull request
3. Follow documentation standards:
   - Brevity
   - Conciseness
   - Accuracy

---

**Last Updated:** 2025-12-12
**Headers Documented:** 15/15
**Coverage:** Complete
