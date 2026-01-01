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
- **`must-revalidate`** - Force revalidation when stale (prevents serving stale content if origin unreachable)

**Scope:**
- **`private`** - Only browser cache, not shared proxies
- **`public`** - Can be cached by any cache (avoid for sensitive content)

**Timing:**
- **`max-age=<seconds>`** - How long to cache
- **`s-maxage=<seconds>`** - Shared cache (proxy) max age (overrides max-age for shared caches)

**Modern Stale Directives (RFC 5861):**
- **`stale-while-revalidate=<seconds>`** - Serve stale content while revalidating in background
- **`stale-if-error=<seconds>`** - Serve stale content if origin is down/errors
- **`immutable`** - Content will never change (strong hint for long-lived resources)

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

### Attack: Directive Conflicts Leading to Undefined Behavior

**Scenario: Conflicting public + private directives**

**Response headers:**
```http
Cache-Control: public, private, max-age=3600
```

**Problem:** Mutually exclusive directives create undefined behavior.

**Browser interpretation varies:**
- Some browsers treat `public` as last-wins
- Others treat `private` as more restrictive (last-wins)
- Inconsistent behavior across browsers = unpredictable security

**Result:** Some users' sensitive data may be cached in shared proxies despite `private` directive.

---

**Secure Configuration:**

Remove conflicting directive:
```http
Cache-Control: private, max-age=3600
```

**Browser behavior is now consistent** → Sensitive data stays in browser cache only.

---

### Attack: Redundant Directives Masking Intent

**Scenario: no-store with redundant max-age**

**Response headers:**
```http
Cache-Control: no-store, max-age=3600
```

**Problem:** Redundant `max-age` masks security intent and creates confusion.

**Developer confusion:**
- "Why is max-age here if we're not storing anything?"
- Future developer removes `no-store` thinking max-age is the control
- Creates maintenance risk

**Clear Configuration:**
```http
Cache-Control: no-store, private
```

---

### Attack: Long Cache Duration Without Revalidation Safeguard

**Scenario: Long-lived cache without must-revalidate**

**Response headers:**
```http
Cache-Control: max-age=604800  (7 days)
```

**User accesses site → content cached for 7 days**

**Day 5: Origin server goes down**

**Day 6: User returns to site**
- Browser has stale content (6 days old, 1 day before expiry)
- Origin unreachable → cannot revalidate
- Browser serves stale content **despite origin being down**

**Result:** User sees outdated/incorrect information for up to 1 more day.

---

**With must-revalidate:**

```http
Cache-Control: max-age=604800, must-revalidate
```

**Day 6: User returns to site**
- Browser has stale content (6 days old, 1 day before expiry)
- Origin unreachable → must-revalidate prevents serving stale
- Browser shows error page

**Result:** User sees error instead of potentially dangerous stale data.

---

## Directive Conflicts

The analyzer detects these common directive conflicts:

### 1. public + private (Mutually Exclusive)

**Severity:** MEDIUM

**Example:**
```
Cache-Control: public, private
```

**Problem:** These directives are mutually exclusive. Browsers may interpret differently.

**Fix:** Remove one directive.
```
Cache-Control: private  (for sensitive data)
Cache-Control: public   (for static resources)
```

---

### 2. no-store + max-age (Redundant)

**Severity:** LOW

**Example:**
```
Cache-Control: no-store, max-age=3600
```

**Problem:** `max-age` is redundant when `no-store` is present. Creates confusion.

**Fix:** Remove `max-age` directive.
```
Cache-Control: no-store, private
```

---

### 3. no-store + no-cache (Redundant)

**Severity:** LOW

**Example:**
```
Cache-Control: no-store, no-cache
```

**Problem:** `no-cache` is redundant when `no-store` is present (no-store is stronger).

**Fix:** Remove `no-cache` directive.
```
Cache-Control: no-store, private
```

---

### 4. private + s-maxage (Inapplicable)

**Severity:** LOW

**Example:**
```
Cache-Control: private, s-maxage=3600
```

**Problem:** `s-maxage` only applies to shared caches. `private` prevents shared caching, making `s-maxage` inapplicable.

**Fix:** Remove `s-maxage` directive.
```
Cache-Control: private, max-age=3600
```

---

## must-revalidate Best Practices

### When to Use must-revalidate

Use `must-revalidate` when:

1. **Long cache durations (>1 day)** - Prevents serving very stale content
2. **Critical content accuracy** - Financial data, stock prices, medical info
3. **Regulatory compliance** - When serving outdated data violates rules

**Example:**
```
Cache-Control: max-age=86400, must-revalidate  (1 day)
```

### When NOT to Use must-revalidate

Don't use when:

1. **Using immutable** - Already guarantees content never changes
   ```
   Cache-Control: public, max-age=31536000, immutable
   ```

2. **Very short max-age (<1 hour)** - Overhead not worth it
   ```
   Cache-Control: max-age=300  (5 minutes - no must-revalidate needed)
   ```

3. **Using no-store** - Already prevents caching entirely
   ```
   Cache-Control: no-store, private
   ```

---

## Modern Stale Directives

### stale-while-revalidate

Allows serving slightly stale content while fetching fresh content in background.

**Syntax:**
```
Cache-Control: max-age=600, stale-while-revalidate=30
```

**How it works:**
- Content fresh for 10 minutes (max-age=600)
- Content stale after 10 minutes
- For next 30 seconds, browser serves stale content immediately
- Browser revalidates in background
- Next request gets fresh content

**Use case:** Improve perceived performance for frequently changing content.

---

### stale-if-error

Allows serving stale content if origin errors (5xx) or is unreachable.

**Syntax:**
```
Cache-Control: max-age=600, stale-if-error=86400
```

**How it works:**
- Content fresh for 10 minutes
- If origin returns error or is down, serve stale content
- Can serve stale for up to 24 hours (86400 seconds)

**Use case:** Graceful degradation when origin is down.

---

### Combining Stale Directives

**Optimal for resilience + performance:**
```
Cache-Control: max-age=600, stale-while-revalidate=30, stale-if-error=86400
```

- Fresh for 10 minutes
- Stale-while-revalidate for 30 seconds (fast response)
- Stale-if-error for 24 hours (resilience to outages)

---

## Configuration Examples

### Excellent for Sensitive Pages ✅
```
Cache-Control: no-store, private
```

Clean, no conflicts. Use for: Login pages, account pages, checkout, personal data.

### Good for Sensitive Pages ✅
```
Cache-Control: no-store, no-cache, must-revalidate, private
```

Works but has redundant directives (no-cache redundant with no-store). First example is cleaner.

### Excellent for Static Resources (Versioned) ✅
```
Cache-Control: public, max-age=31536000, immutable
```

Use for: Images, CSS, JS with versioned URLs (style.v123.css).

### Good for Static Resources (Long-lived) ✅
```
Cache-Control: public, max-age=604800, must-revalidate
```

7-day cache with revalidation safeguard. Use for: unversioned static content.

### Good for Dynamic Content with Resilience ✅
```
Cache-Control: max-age=600, stale-while-revalidate=30, stale-if-error=3600
```

Modern caching with graceful degradation. Use for: API responses, news feeds.

### Acceptable ⚠️
```
Cache-Control: private, max-age=0
```

Caches briefly, requires revalidation.

### Acceptable (Gets Recommendation) ⚠️
```
Cache-Control: max-age=604800
```

Long cache (7 days) without must-revalidate. Analyzer recommends adding must-revalidate.

### Bad for Sensitive Data ❌
```
Cache-Control: public, max-age=86400
```

Sensitive data cached for 24 hours in shared caches.

### Bad - Directive Conflicts ❌
```
Cache-Control: public, private
```

Mutually exclusive directives. Analyzer detects conflict (MEDIUM severity).

### Bad - Redundant Directives ❌
```
Cache-Control: no-store, max-age=3600
```

Redundant max-age with no-store. Analyzer flags as conflict (LOW severity).

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

**4. Directive Conflicts (NEW)**
```
Cache-Control: public, private, max-age=3600
```
**Fix:** Remove conflicting directives. Use only `private` for user data.

**5. Redundant Directives (NEW)**
```
Cache-Control: no-store, max-age=3600
```
**Fix:** Remove `max-age` when using `no-store`. They conflict.

**6. Long Cache Without Revalidation Safeguard (NEW)**
```
Cache-Control: max-age=604800  # 7 days, no must-revalidate
```
**Fix:** Add `must-revalidate` for long cache durations (>1 day):
```
Cache-Control: max-age=604800, must-revalidate
```

**7. Using s-maxage with private (NEW)**
```
Cache-Control: private, s-maxage=3600
```
**Fix:** Remove `s-maxage` - it's inapplicable when using `private` (no shared caching).

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
- [Analyzer Reference](../analyzer-reference.md#14-cache-control)
- [RFC 7234: HTTP Caching](https://datatracker.ietf.org/doc/html/rfc7234)
- [RFC 5861: HTTP Cache-Control Extensions for Stale Content](https://datatracker.ietf.org/doc/html/rfc5861)

---

**Last Updated:** 2026-01-01
**Status:** Active
