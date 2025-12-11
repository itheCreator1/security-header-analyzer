# Referrer-Policy Security Header

## Quick Reference

**Header:** `Referrer-Policy`
**Purpose:** Controls how much referrer information is sent with requests
**Severity if Missing:** **HIGH**
**Complexity:** Medium

**Best Practice Configuration:**
```
Referrer-Policy: strict-origin-when-cross-origin
```

---

## What It Does

The Referrer-Policy header controls how much information about the originating page is included in the `Referer` HTTP header when users navigate away from your site or when your page loads external resources.

Without this header, browsers may leak sensitive information contained in URLs (session IDs, authentication tokens, search queries, personal data) to third-party sites through the Referer header.

---

## How It Works

### Header Syntax

```
Referrer-Policy: <policy>
```

### Policy Values (Strictest to Most Permissive)

**Recommended:**
- **`no-referrer`** - Never send referrer (maximum privacy)
- **`strict-origin`** - Send only origin on HTTPS→HTTPS, nothing on downgrade
- **`strict-origin-when-cross-origin`** - Send full URL to same-origin, origin to cross-origin

**Acceptable:**
- **`same-origin`** - Send referrer only to same-origin requests
- **`origin`** - Always send origin only (no path/query)
- **`origin-when-cross-origin`** - Full URL to same-origin, origin to cross-origin

**Unsafe:**
- **`unsafe-url`** - Always send full URL (leaks everything)
- **`no-referrer-when-downgrade`** - Send referrer except on HTTPS→HTTP (default browser behavior)

---

## Real-World Attack Scenarios

### Attack 1: Session Token Leakage

**Without Referrer-Policy:**

**Step 1:** User logs into sensitive app
```
https://healthportal.com/dashboard?session=abc123secret
```

**Step 2:** User clicks external link on dashboard
```html
<a href="https://external-site.com">Read more</a>
```

**Step 3:** Browser sends full URL in Referer header
```http
GET / HTTP/1.1
Host: external-site.com
Referer: https://healthportal.com/dashboard?session=abc123secret
```

**Step 4:** External site logs the referrer

**Step 5:** Attacker compromises external-site.com or reads analytics logs

**Result:** Session token stolen, account compromised

---

**With Referrer-Policy: strict-origin-when-cross-origin:**

**Step 3:** Browser sends only origin
```http
GET / HTTP/1.1
Host: external-site.com
Referer: https://healthportal.com
```

**Result:** Session token protected, only domain visible

---

### Attack 2: Search Query Leakage

**Without Protection:**

**User searches:**
```
https://example.com/search?q=my+medical+condition
```

**Clicks on result linking to third-party site**

**Third party receives:**
```http
Referer: https://example.com/search?q=my+medical+condition
```

**Result:** Sensitive search queries leaked to advertisers, analytics, third parties

---

**With Referrer-Policy: strict-origin:**

**Third party receives:**
```http
Referer: https://example.com
```

**Result:** Privacy protected, search query not leaked

---

### Attack 3: Private URL Disclosure

**Without Protection:**

**User accesses private document:**
```
https://company.com/documents/confidential-2024-Q4-layoffs.pdf
```

**PDF contains image from external CDN:**
```html
<img src="https://cdn.example.com/logo.png">
```

**CDN receives:**
```http
GET /logo.png HTTP/1.1
Host: cdn.example.com
Referer: https://company.com/documents/confidential-2024-Q4-layoffs.pdf
```

**Result:** Confidential document name leaked to CDN logs

---

**With Referrer-Policy: no-referrer:**

**CDN receives:**
```http
GET /logo.png HTTP/1.1
Host: cdn.example.com
(No Referer header)
```

**Result:** Document name protected

---

## Configuration Examples

### Good Configuration ✅

```
Referrer-Policy: strict-origin-when-cross-origin
```

**Why it's good:**
- Sends full URL to same-origin (analytics still work)
- Sends only origin to cross-origin (privacy protected)
- Blocks referrer on HTTPS→HTTP downgrade
- Good balance of privacy and functionality

**Use case:** Most production websites

---

### Maximum Privacy ✅

```
Referrer-Policy: no-referrer
```

**Why it's strongest:**
- Never sends any referrer information
- Maximum privacy protection
- No risk of URL parameter leakage

**Use case:** Healthcare, financial, or highly sensitive applications

**Trade-off:** Some analytics and affiliate links may break

---

### Acceptable Configuration ⚠️

```
Referrer-Policy: origin-when-cross-origin
```

**Why it's acceptable:**
- Sends origin to cross-origin (not full URL)
- Still allows HTTPS→HTTP referrer (slight risk)
- Works well for most sites

**Use case:** Websites transitioning to stricter policy

---

### Unsafe Configuration ❌

```
Referrer-Policy: unsafe-url
```

**Why it's terrible:**
- **Always** sends full URL with all parameters
- Leaks session tokens, search queries, personal data
- Even sends on HTTPS→HTTP downgrade
- No privacy protection whatsoever

**Never use this unless:** You absolutely need referrer for critical functionality (very rare)

---

### Default Browser Behavior ❌

```
Referrer-Policy: no-referrer-when-downgrade
```

**Why it's weak:**
- Sends full URL to HTTPS sites (leaks parameters)
- Only blocks on HTTPS→HTTP downgrade
- Doesn't protect against most privacy risks

**Fix:** Set explicit strict policy

---

## Common Mistakes

### 1. Not Setting Any Policy

**Mistake:** Relying on browser default

**Problem:** Full URLs with sensitive parameters leaked

**Fix:**
```
Referrer-Policy: strict-origin-when-cross-origin
```

---

### 2. Using unsafe-url

**Mistake:**
```
Referrer-Policy: unsafe-url
```

**Problem:** Defeats entire purpose, worse than default

**Fix:** Use `strict-origin-when-cross-origin` or `no-referrer`

---

### 3. Conflicting with Meta Tag

**Mistake:** Different policies in header vs meta tag
```html
<!-- Meta tag -->
<meta name="referrer" content="no-referrer">
```
```http
<!-- HTTP header -->
Referrer-Policy: unsafe-url
```

**Problem:** Meta tag takes precedence (unexpected behavior)

**Fix:** Be consistent or prefer HTTP header

---

### 4. Breaking Analytics

**Mistake:** Setting `no-referrer` without considering analytics

**Problem:** Analytics can't track referral sources

**Fix:** Use `strict-origin-when-cross-origin` for balance, or configure analytics to use other tracking methods

---

## Implementation Guide

### Step 1: Choose Policy

**Decision Matrix:**

| Need | Recommended Policy |
|------|-------------------|
| Maximum privacy | `no-referrer` |
| Balanced (recommended) | `strict-origin-when-cross-origin` |
| Analytics important | `origin-when-cross-origin` |
| Internal tools only | `same-origin` |

### Step 2: Configure Web Server

**Nginx:**
```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

**Apache:**
```apache
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

**Node.js (Express):**
```javascript
app.use((req, res, next) => {
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});
```

**Django:**
```python
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
```

### Step 3: Test Configuration

**Using curl:**
```bash
curl -I https://yourdomain.com | grep Referrer-Policy
```

**Expected:**
```
Referrer-Policy: strict-origin-when-cross-origin
```

**Manual test:**
1. Visit your site
2. Click external link
3. Check Network tab → See referrer sent to external site

---

## Browser Compatibility

| Browser | Version | Support |
|---------|---------|---------|
| Chrome  | 61+     | Full    |
| Firefox | 52+     | Full    |
| Safari  | 11.1+   | Full    |
| Edge    | 79+     | Full    |
| IE      | None    | Not supported |

**Coverage:** 95%+ of modern browsers

**Fallback:** Browsers that don't support use their default behavior

---

## Additional Resources

### Standards
- [W3C Referrer Policy](https://www.w3.org/TR/referrer-policy/)
- [MDN Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)

### Tools
- [Referrer Policy Test](https://securityheaders.com/) - Test your site
- This analyzer tool

### Related Headers
- [CSP](CSP.md) - Can also control referrer via directives

---

## See Also

- [Analyzer Implementation](../ANALYZERS.md#referrer-policy)
- [Best Practices](../SecurityHeadersBestPractices.md#referrer-policy)
- [Privacy Guide](../ATTACK_SCENARIOS.md#information-leakage)

---

**Last Updated:** 2025-12-12
**Status:** Active
**Severity:** High
