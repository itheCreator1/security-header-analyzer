# COOP (Cross-Origin-Opener-Policy) Security Header

## Quick Reference

**Header:** `Cross-Origin-Opener-Policy`
**Purpose:** Isolates browsing context from cross-origin windows
**Severity if Missing:** Low
**Complexity:** Medium

**Best Practice:**
```
Cross-Origin-Opener-Policy: same-origin
```

---

## What It Does

COOP prevents cross-origin windows (opened with `window.open()` or `target="_blank"`) from accessing your page through the `window.opener` reference. This mitigates attacks via window references and enables cross-origin isolation.

---

## How It Works

**Values:**
- **`same-origin`** - Only same-origin windows share context
- **`same-origin-allow-popups`** - Same-origin + popups you open
- **`unsafe-none`** - No protection (default)

**Use with COEP for full isolation:**
```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

---

## Real-World Attack Scenarios

### Attack: Tabnabbing

**Without COOP:**

**Your site opens external link:**
```html
<a href="https://external.com" target="_blank">Click here</a>
```

**External site can access opener:**
```javascript
// external.com code
if (window.opener) {
    window.opener.location = 'https://phishing-site.com';
}
```

**Result:** Your tab redirected to phishing site while user on external page.

---

**With COOP:**

```http
Cross-Origin-Opener-Policy: same-origin
```

`window.opener` is null for cross-origin windows → Attack fails.

---

## Configuration Examples

### Good (Isolation) ✅
```
Cross-Origin-Opener-Policy: same-origin
```

Complete isolation from cross-origin windows.

### Acceptable (With Popups) ⚠️
```
Cross-Origin-Opener-Policy: same-origin-allow-popups
```

Allows popups you open to access opener.

### Default (No Protection) ❌
```
Cross-Origin-Opener-Policy: unsafe-none
```

No isolation, vulnerable to tabnabbing.

---

## Common Mistakes

**1. Breaking OAuth Flows**
OAuth popups may need `same-origin-allow-popups`.

**2. Breaking Analytics**
Some analytics track via `window.opener`.

**3. Not Using with COEP**
For full cross-origin isolation, set both COOP and COEP.

---

## Implementation

**Nginx:**
```nginx
add_header Cross-Origin-Opener-Policy "same-origin" always;
```

**Apache:**
```apache
Header always set Cross-Origin-Opener-Policy "same-origin"
```

**Test first with report-only:**
```
Cross-Origin-Opener-Policy-Report-Only: same-origin
```

---

## Browser Compatibility

| Browser | Version | Support |
|---------|---------|---------|
| Chrome  | 83+     | Full |
| Firefox | 79+     | Full |
| Safari  | 15.2+   | Full |
| Edge    | 83+     | Full |

---

## See Also

- [COEP](COEP.md) - Companion for full isolation
- [MDN COOP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)

---

**Last Updated:** 2025-12-12
**Status:** Active
**Use Case:** Prevent tabnabbing, enable cross-origin isolation
