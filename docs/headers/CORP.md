# CORP (Cross-Origin-Resource-Policy) Security Header

## Quick Reference

**Header:** `Cross-Origin-Resource-Policy`
**Purpose:** Protects resources from cross-origin reads
**Severity if Missing:** Low
**Complexity:** Medium

**Best Practice:**
```
Cross-Origin-Resource-Policy: same-origin
```

---

## What It Does

CORP prevents other websites from loading your resources (images, scripts, etc.) in their pages. This mitigates certain Spectre attacks and prevents unauthorized cross-origin resource inclusion.

---

## How It Works

**Values:**
- **`same-origin`** - Only same origin can load
- **`same-site`** - Same site (including subdomains) can load
- **`cross-origin`** - Anyone can load (opt-in to COEP embedding)

---

## Real-World Attack Scenarios

### Attack: Cross-Origin Resource Timing

**Without CORP:**

Attacker embeds your resources:
```html
<img src="https://victim.com/private-image.png">
```

Uses timing attacks to detect if resource exists or infer data about it.

---

**With CORP:**

```http
Cross-Origin-Resource-Policy: same-origin
```

Browser blocks cross-origin loading → Attack prevented.

---

## Configuration Examples

### Good (Private Resources) ✅
```
Cross-Origin-Resource-Policy: same-origin
```

Use for private/internal resources.

### Acceptable (Same Site) ⚠️
```
Cross-Origin-Resource-Policy: same-site
```

Allows subdomains to load resource.

### Opt-In to Embedding ✅
```
Cross-Origin-Resource-Policy: cross-origin
```

Explicitly allows cross-origin loading (needed for COEP pages).

---

## Common Mistakes

**1. Breaking CDN Resources**
Public CDN resources should use `cross-origin`.

**2. Breaking Subdomains**
Use `same-site` if subdomains need access.

**3. Not Setting for Sensitive Resources**
APIs, private images should use `same-origin`.

---

## Implementation

**Nginx (Private):**
```nginx
add_header Cross-Origin-Resource-Policy "same-origin" always;
```

**Nginx (Public CDN):**
```nginx
add_header Cross-Origin-Resource-Policy "cross-origin" always;
```

**Apache:**
```apache
Header always set Cross-Origin-Resource-Policy "same-origin"
```

---

## Browser Compatibility

| Browser | Version | Support |
|---------|---------|---------|
| Chrome  | 73+     | Full |
| Firefox | 74+     | Full |
| Safari  | 12+     | Full |
| Edge    | 79+     | Full |

---

## See Also

- [COEP](COEP.md) - Companion header
- [COOP](COOP.md) - Opener policy
- [MDN CORP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy)

---

**Last Updated:** 2025-12-12
**Status:** Active
**Use Case:** Protect resources from unauthorized cross-origin access
