# X-Frame-Options Security Header

## Quick Reference

**Header:** `X-Frame-Options`
**Purpose:** Prevents clickjacking by controlling iframe embedding
**Severity if Missing:** **HIGH**
**Complexity:** Easy

**Best Practice Configuration:**
```
X-Frame-Options: DENY
```

---

## What It Does

X-Frame-Options prevents your web page from being embedded in an `<iframe>`, `<frame>`, or `<object>` tag on another website. This stops **clickjacking attacks** where attackers trick users into clicking on hidden or disguised elements.

When this header is set, browsers refuse to display your page within a frame unless the framing site meets your specified criteria.

---

## How It Works

### Header Syntax

```
X-Frame-Options: DENY | SAMEORIGIN | ALLOW-FROM https://example.com
```

**Values:**

- **`DENY`** - Never allow framing (most secure)
- **`SAMEORIGIN`** - Only allow framing by same origin
- **`ALLOW-FROM <uri>`** - ⚠️ Deprecated, use CSP instead

---

## Real-World Attack Scenarios

### Attack 1: Clickjacking for Unauthorized Actions

**Without X-Frame-Options:**

**Step 1:** Attacker creates malicious page
```html
<!-- attacker.com/trick.html -->
<iframe src="https://bank.com/transfer" style="opacity: 0.1"></iframe>
<div style="position: absolute; top: 100px;">
    Click here to win a prize!
</div>
```

**Step 2:** Victim visits attacker.com while logged into bank.com

**Step 3:** Page shows "Click to win" button positioned over hidden iframe

**Step 4:** Victim clicks "prize" button

**Step 5:** Click actually hits "Transfer Money" button in hidden iframe

**Result:** Money transferred to attacker without user knowledge

---

**With X-Frame-Options: DENY:**

**Step 1-2:** Same as above

**Step 3:** Browser blocks iframe loading
```
Refused to display 'https://bank.com/transfer' in a frame
because it set 'X-Frame-Options' to 'DENY'
```

**Result:** Attack prevented, iframe shows error

---

### Attack 2: Like-Jacking on Social Media

**Without Protection:**

**Attacker creates:**
```html
<iframe src="https://facebook.com/malicious-page" style="opacity: 0"></iframe>
<button style="position: absolute">Download Free Movie!</button>
```

**User clicks download button → Actually clicks "Like" on hidden Facebook page**

**Result:** Malicious content spreads to user's friends

---

**With X-Frame-Options:**

Facebook sets: `X-Frame-Options: DENY`

**Result:** Page cannot be framed, attack fails

---

### Attack 3: Password Theft via Framed Login

**Without Protection:**

```html
<!-- Attacker overlays fake password reset form on top of real login iframe -->
<iframe src="https://targetsite.com/login"></iframe>
<form style="opacity: 0.8">
    <input type="password" placeholder="Enter new password">
    <!-- Captures password while real form is visible underneath -->
</form>
```

**Result:** User enters password into attacker's form

---

**With X-Frame-Options: SAMEORIGIN:**

**Result:** Login page refuses to load in attacker's frame

---

## Configuration Examples

### Good Configuration ✅

```
X-Frame-Options: DENY
```

**Why it's good:**
- Blocks ALL framing attempts
- Maximum protection against clickjacking
- No exceptions, no edge cases

**Use case:** Most websites that don't need to be embedded

---

### Acceptable Configuration ⚠️

```
X-Frame-Options: SAMEORIGIN
```

**Why it's acceptable:**
- Allows framing only by same origin
- Useful if you need to embed your own pages
- Still protects against external attackers

**Use case:** Internal dashboards, documentation sites that embed their own content

**Example:** `docs.example.com` can frame its own pages but `attacker.com` cannot

---

### Deprecated Configuration ❌

```
X-Frame-Options: ALLOW-FROM https://trusted.com
```

**Why it's deprecated:**
- Not supported by Chrome/Safari
- Inconsistent browser support
- Replaced by CSP `frame-ancestors`

**Fix:** Use Content-Security-Policy instead:
```
Content-Security-Policy: frame-ancestors https://trusted.com
```

---

### Invalid Configuration ❌

```
X-Frame-Options: ALLOW
```

**Why it's wrong:**
- `ALLOW` is not a valid value
- Header will be ignored
- Site remains vulnerable

**Fix:** Use `SAMEORIGIN` or omit header if framing is intentional

---

## Common Mistakes

### 1. Using ALLOW-FROM

**Mistake:**
```
X-Frame-Options: ALLOW-FROM https://partner.com
```

**Problem:** Not supported by Chrome, Safari, or Edge

**Fix:** Use CSP frame-ancestors:
```
Content-Security-Policy: frame-ancestors https://partner.com
```

---

### 2. Setting Multiple Values

**Mistake:**
```
X-Frame-Options: DENY, SAMEORIGIN
```

**Problem:** Some browsers reject header with multiple values

**Fix:** Choose one value:
```
X-Frame-Options: DENY
```

---

### 3. Conflicting with CSP

**Mistake:** Setting both and making them conflict
```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors *
```

**Problem:** Browser uses most restrictive (DENY wins, but confusing)

**Fix:** Be consistent or prefer CSP:
```
Content-Security-Policy: frame-ancestors 'none'
```

---

### 4. Not Setting for API Endpoints

**Mistake:** Only setting on HTML pages

**Problem:** APIs might return HTML error pages vulnerable to framing

**Fix:** Set header globally for all responses

---

## Implementation Guide

### Step 1: Determine Your Needs

**Questions:**
- Do you need to embed your pages in iframes? → Use `SAMEORIGIN`
- Do third parties need to embed your content? → Use CSP `frame-ancestors`
- Otherwise → Use `DENY`

### Step 2: Configure Web Server

**Nginx:**
```nginx
add_header X-Frame-Options "DENY" always;
```

**Apache:**
```apache
Header always set X-Frame-Options "DENY"
```

**Node.js (Express):**
```javascript
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    next();
});
```

**Django:**
```python
X_FRAME_OPTIONS = 'DENY'
```

### Step 3: Test Configuration

**Using curl:**
```bash
curl -I https://yourdomain.com | grep X-Frame-Options
```

**Expected:**
```
X-Frame-Options: DENY
```

**Using this tool:**
```bash
python -m sha https://yourdomain.com
```

### Step 4: Verify in Browser

Create test page:
```html
<iframe src="https://yourdomain.com"></iframe>
```

Open in browser → Should show error:
```
Refused to display in a frame because it set 'X-Frame-Options' to 'DENY'
```

---

## Browser Compatibility

| Browser | Version | Support |
|---------|---------|---------|
| Chrome  | 4+      | Full    |
| Firefox | 3.6+    | Full    |
| Safari  | 4+      | Full    |
| Edge    | 12+     | Full    |
| IE      | 8+      | Full    |

**Coverage:** 99%+ of all browsers

---

## Migration to CSP

### Why Migrate?

CSP `frame-ancestors` is more flexible and supports multiple domains:

```
Content-Security-Policy: frame-ancestors 'self' https://trusted.com https://partner.com
```

### Migration Strategy

**Phase 1:** Add both headers
```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

**Phase 2:** Monitor for conflicts (6+ months)

**Phase 3:** Remove X-Frame-Options, keep CSP

### Compatibility

Use both during transition for IE11 support (CSP frame-ancestors not supported in IE)

---

## Additional Resources

### Standards
- [RFC 7034](https://tools.ietf.org/html/rfc7034) - X-Frame-Options Specification
- [MDN X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [OWASP Clickjacking](https://owasp.org/www-community/attacks/Clickjacking)

### Tools
- [Clickjack Test](https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet#Testing) - Manual testing guide
- This tool's analyzer

### Related Headers
- [CSP](CSP.md) - frame-ancestors directive (modern replacement)

---

## See Also

- [Analyzer Implementation](../ANALYZERS.md#x-frame-options)
- [Best Practices](../SecurityHeadersBestPractices.md#x-frame-options)
- [Attack Scenarios](../ATTACK_SCENARIOS.md#clickjacking)

---

**Last Updated:** 2025-12-12
**Status:** Active (consider migrating to CSP)
**Severity:** High
