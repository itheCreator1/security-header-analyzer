# Expect-CT Security Header

## Quick Reference

**Header:** `Expect-CT`
**Purpose:** Enforces Certificate Transparency
**Severity if Missing:** Medium
**Complexity:** Easy
**Status:** ⚠️ **DEPRECATED** (Chrome 107+)

**Configuration (Historical):**
```
Expect-CT: enforce, max-age=86400
```

---

## What It Does

Expect-CT required browsers to check that SSL/TLS certificates appear in public Certificate Transparency logs, helping detect rogue certificates issued by compromised Certificate Authorities.

**Important:** This header is deprecated. Certificate Transparency is now mandatory in modern browsers and doesn't require this header.

---

## Deprecation Notice

**Chrome 107+ (October 2022):** Header ignored
**Modern browsers:** CT enforced automatically

**Migration:** Remove header or keep for legacy browser support (no harm).

---

## How It Worked

**Directives:**
- **`enforce`** - Block connections if CT requirement not met
- **`max-age=<seconds>`** - How long to remember policy
- **`report-uri=<url>`** - Where to send violation reports

---

## Real-World Context

### Problem It Solved

**Before CT:**
- Compromised CA could issue fraudulent certificate
- No public record of issuance
- Man-in-the-middle attacks possible

**With CT:**
- All certificates must be logged publicly
- Domain owners can monitor for unauthorized certificates
- Rogue certificates quickly detected

---

## Configuration Examples

### Historical Good Configuration ✅
```
Expect-CT: enforce, max-age=86400, report-uri="https://example.com/ct-report"
```

### Current Recommendation ✅
```
(Remove header - no longer needed)
```

Modern browsers enforce CT automatically.

---

## Common Mistakes

**1. Still Adding to New Sites**
Not necessary for modern browsers.

**2. Using without enforce**
```
Expect-CT: max-age=86400  # Report-only mode
```
Didn't provide protection, only monitoring.

---

## Migration Guide

**Old:**
```http
Expect-CT: enforce, max-age=86400
```

**New:**
```http
(Remove header)
```

Certificate Transparency now built into browsers.

---

## Browser Compatibility

| Browser | Support | Status |
|---------|---------|--------|
| Chrome | 61-106 | Deprecated |
| Firefox | Never | Not implemented |
| Safari | Never | Not implemented |

---

## See Also

- [HSTS](HSTS.md) - Still active and important
- [Certificate Transparency](https://certificate.transparency.dev/)

---

**Last Updated:** 2025-12-12
**Status:** Deprecated
**Recommendation:** Remove from new deployments
