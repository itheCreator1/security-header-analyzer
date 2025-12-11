# X-XSS-Protection Security Header

## Quick Reference

**Header:** `X-XSS-Protection`
**Purpose:** Legacy XSS filter control
**Severity if Missing:** Low
**Complexity:** Easy
**Status:** ⚠️ **DEPRECATED**

**Current Recommendation:**
```
X-XSS-Protection: 0
```
Or omit entirely and use CSP instead.

---

## What It Does

This header controlled built-in XSS filters in older browsers (IE8-11, old Chrome/Safari). These filters attempted to detect and block reflected XSS attacks.

**Problem:** The filters themselves had vulnerabilities and could be exploited.

---

## Why It's Deprecated

1. **Removed from modern browsers** (Chrome 2019, Edge 2020)
2. **Filter had bypasses** - Not reliable protection
3. **Could be weaponized** - Filter could create vulnerabilities
4. **CSP is superior** - Modern replacement

---

## How It Worked (Historical)

**Values:**
- **`0`** - Disable filter
- **`1`** - Enable filter (sanitize page)
- **`1; mode=block`** - Enable filter (block page entirely)

---

## Real-World Issues

### Filter Bypass Example

Attackers could craft payloads that:
1. Trigger the filter
2. Cause filter to modify page in exploitable way
3. Create XSS vulnerability that didn't exist before

---

## Configuration Examples

### Current Recommendation ✅
```
X-XSS-Protection: 0
```

Explicitly disable for security (prevents filter exploitation).

### Alternative ✅
```
(Omit header entirely)
```

Focus on proper CSP implementation instead.

### Old/Deprecated ❌
```
X-XSS-Protection: 1; mode=block
```

No longer effective, filter removed from browsers.

---

## Migration to CSP

**Instead of X-XSS-Protection:**
```http
X-XSS-Protection: 1; mode=block
```

**Use CSP:**
```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```

CSP provides robust XSS protection that works in all modern browsers.

---

## Implementation

**If setting (to disable):**
```nginx
add_header X-XSS-Protection "0" always;
```

**Recommended:**
Remove header entirely and implement CSP.

---

## Browser Compatibility

| Browser | Status |
|---------|--------|
| Chrome | Removed (2019) |
| Firefox | Never implemented |
| Safari | Removed (2020) |
| Edge | Removed (2020) |
| IE | Deprecated |

---

## See Also

- [CSP](CSP.md) - Modern XSS protection
- [Best Practices](../SecurityHeadersBestPractices.md)

---

**Last Updated:** 2025-12-12
**Status:** Deprecated
**Recommendation:** Use Content-Security-Policy instead
