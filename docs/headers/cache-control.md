# Cache-Control Security Header

## Quick Reference

**Header:** `Cache-Control`
**Purpose:** Controls caching behavior to prevent sensitive data leakage
**Severity if Missing:** Medium (for sensitive pages)
**Complexity:** Medium

**Best Practice (Sensitive Pages):**
```
Cache-Control: no-store, no-cache, must-revalidate, private
```

---

## What It Does

Cache-Control directives control how browsers and intermediate proxies cache responses. For pages containing sensitive information (login forms, account details, personal data), proper cache settings prevent data from being stored and potentially accessed by unauthorized parties.

---

## Security-Relevant Directives

**Prevent Caching:**
- **`no-store`** - Never cache (strongest for sensitive data)
- **`no-cache`** - Cache but revalidate before use
- **`must-revalidate`** - Force revalidation when stale

**Scope:**
- **`private`** - Only browser cache, not shared proxies
- **`public`** - Can be cached by any cache (avoid for sensitive content)

**Timing:**
- **`max-age=<seconds>`** - How long to cache

---

## Real-World Attack Scenarios

### Attack: Sensitive Data from Shared Computer

**Without proper Cache-Control:**

**User logs into banking site on library computer**

**Response headers:**
```http
Cache-Control: public, max-age=3600
```

**Browser caches account page for 1 hour**

**User logs out and leaves**

**Next user on same computer:**
- Presses back button
- Browser shows cached account page
- Sees previous user's account balance, transactions

**Result:** Privacy breach

---

**With proper Cache-Control:**

```http
Cache-Control: no-store, private
```

**Browser never caches page** → Back button shows login page

---

## Configuration Examples

### Good for Sensitive Pages ✅
```
Cache-Control: no-store, no-cache, must-revalidate, private
```

Use for: Login pages, account pages, checkout, personal data.

### Good for Static Resources ✅
```
Cache-Control: public, max-age=31536000, immutable
```

Use for: Images, CSS, JS with versioned URLs (style.v123.css).

### Acceptable ⚠️
```
Cache-Control: private, max-age=0
```

Caches briefly, requires revalidation.

### Bad for Sensitive Data ❌
```
Cache-Control: public, max-age=86400
```

Sensitive data cached for 24 hours in shared caches.

---

## Common Mistakes

**1. Caching Login Pages**
```
Cache-Control: public  # Wrong for login!
```
**Fix:** Use `no-store` for authentication pages.

**2. Confusing no-cache and no-store**
- `no-cache` still caches (just revalidates)
- `no-store` never caches
Use `no-store` for sensitive data.

**3. Not Setting private for User Data**
User-specific content should be `private` to avoid proxy caching.

---

## Implementation

**Express.js:**
```javascript
// Sensitive pages
res.setHeader('Cache-Control', 'no-store, private');

// Static assets
res.setHeader('Cache-Control', 'public, max-age=31536000');
```

**Nginx (sensitive):**
```nginx
add_header Cache-Control "no-store, no-cache, must-revalidate" always;
```

**Nginx (static):**
```nginx
location ~* \.(jpg|jpeg|png|css|js)$ {
    add_header Cache-Control "public, max-age=31536000";
}
```

---

## Browser Compatibility

All browsers support Cache-Control.

---

## See Also

- [Best Practices](../SecurityHeadersBestPractices.md#cache-control)

---

**Last Updated:** 2025-12-12
**Status:** Active
