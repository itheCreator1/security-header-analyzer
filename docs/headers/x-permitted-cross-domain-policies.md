# X-Permitted-Cross-Domain-Policies Security Header

## Quick Reference

**Header:** `X-Permitted-Cross-Domain-Policies`
**Purpose:** Controls Flash and PDF cross-domain data access
**Severity if Missing:** Medium (legacy concern)
**Complexity:** Easy

**Best Practice:**
```
X-Permitted-Cross-Domain-Policies: none
```

---

## What It Does

This header controls whether Adobe Flash and PDFs can load data from your domain. Since Flash is deprecated and PDFs rarely use cross-domain policies, this is mainly relevant for legacy systems.

---

## How It Works

**Values:**
- **`none`** - No policy files allowed (most secure)
- **`master-only`** - Only /crossdomain.xml at root
- **`by-content-type`** - Only files served with specific Content-Type
- **`all`** - Any policy file (insecure)

---

## Real-World Context

### Flash Era Problem (Historical)

**Without header:**
Flash files could load `crossdomain.xml` from your domain and access your data cross-origin, potentially exposing sensitive information.

**With header set to `none`:**
Flash files blocked from accessing your domain's data.

---

## Configuration Examples

### Good ✅
```
X-Permitted-Cross-Domain-Policies: none
```

Blocks all Flash/PDF cross-domain access.

### Bad ❌
```
X-Permitted-Cross-Domain-Policies: all
```

Allows unrestricted cross-domain access.

---

## Current Relevance

**Flash:** End-of-life December 2020 (browsers blocked)
**PDFs:** Rarely use cross-domain policies
**Recommendation:** Set to `none` for defense-in-depth

---

## Implementation

**Nginx:**
```nginx
add_header X-Permitted-Cross-Domain-Policies "none" always;
```

**Apache:**
```apache
Header always set X-Permitted-Cross-Domain-Policies "none"
```

---

## Browser Compatibility

Recognized by Flash and PDF readers, not browsers directly.

---

## See Also

- [CSP](CSP.md) - Modern approach to cross-origin control

---

**Last Updated:** 2025-12-12
**Status:** Legacy (still recommended for defense-in-depth)
