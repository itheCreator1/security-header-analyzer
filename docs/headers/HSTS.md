# HSTS (Strict-Transport-Security) Security Header

## Quick Reference

**Header:** `Strict-Transport-Security`
**Purpose:** Forces HTTPS connections to prevent protocol downgrade attacks
**Severity if Missing:** **CRITICAL**
**Complexity:** Medium

**Best Practice Configuration:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---

## What It Does

HSTS (HTTP Strict Transport Security) tells browsers to **only** connect to your website over HTTPS, never HTTP. Once a browser sees this header, it will automatically upgrade all future requests to HTTPS for the specified time period, even if the user types "http://" in the address bar or clicks an HTTP link.

This prevents attackers from downgrading secure HTTPS connections to insecure HTTP connections, which would expose sensitive data like passwords, session cookies, and personal information to eavesdropping and tampering.

Without HSTS, even if your site uses HTTPS, users can still be tricked into connecting over HTTP on their first visit or after clearing browser data. Attackers exploit this vulnerability through SSL stripping attacks.

---

## How It Works

### Header Syntax

```
Strict-Transport-Security: max-age=<seconds>; [includeSubDomains]; [preload]
```

**Directives:**

- **`max-age=<seconds>`** (required) - How long (in seconds) the browser should remember to only use HTTPS
  - Minimum recommended: 10,886,400 seconds (126 days)
  - Best practice: 31,536,000 seconds (1 year)

- **`includeSubDomains`** (optional but recommended) - Apply HSTS to all subdomains
  - Example: If set on `example.com`, also applies to `www.example.com`, `api.example.com`, etc.
  - Protects entire domain infrastructure

- **`preload`** (optional) - Allows inclusion in browser HSTS preload lists
  - Browsers ship with built-in list of HSTS-enabled sites
  - Protects users even on their very first visit
  - Requires submission to [hstspreload.org](https://hstspreload.org/)

### Browser Behavior

1. **First visit** - Browser receives HSTS header over HTTPS
2. **Header cached** - Browser stores HSTS policy for `max-age` duration
3. **All future requests** - Browser automatically upgrades HTTP to HTTPS
4. **After expiry** - Policy expires after `max-age` seconds (unless refreshed)

---

## Real-World Attack Scenarios

### Attack 1: SSL Stripping (Man-in-the-Middle)

**Without HSTS:**

**Step 1:** User connects to coffee shop WiFi (attacker-controlled)

**Step 2:** User types "bank.com" in browser (no https://)
```
Browser → http://bank.com
```

**Step 3:** Attacker intercepts and maintains HTTP connection
```
User's Browser ←HTTP→ Attacker ←HTTPS→ Real Bank
```

**Step 4:** User's login credentials transmitted in plain text
```http
POST /login HTTP/1.1
Host: bank.com
Content-Type: application/x-www-form-urlencoded

username=victim&password=secret123
```

**Step 5:** Attacker captures username and password

**Result:** Complete account compromise

---

**With HSTS:**

**Step 1:** User previously visited bank.com over HTTPS and received HSTS header
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

**Step 2:** User types "bank.com" again (even without https://)

**Step 3:** Browser automatically upgrades to HTTPS **before** making any request
```
Browser → https://bank.com  (automatic upgrade)
```

**Step 4:** Attacker cannot intercept HTTPS connection (requires valid certificate)

**Result:** Attack prevented

---

### Attack 2: Protocol Downgrade via Malicious Link

**Without HSTS:**

**Step 1:** Attacker sends phishing email with HTTP link
```html
<a href="http://accounts.google.com/login">
    Reset your password
</a>
```

**Step 2:** User clicks link, browser connects over HTTP

**Step 3:** Attacker's proxy serves fake login page over HTTP

**Step 4:** User enters credentials on HTTP page

**Result:** Credentials stolen

---

**With HSTS (includeSubDomains):**

**Step 1:** User previously visited google.com, which set HSTS with `includeSubDomains`

**Step 2:** User clicks malicious `http://accounts.google.com` link

**Step 3:** Browser detects "accounts.google.com" is a subdomain

**Step 4:** Browser automatically upgrades to `https://accounts.google.com`

**Step 5:** Legitimate Google server shows valid cert, fake site blocked

**Result:** Attack prevented

---

### Attack 3: Network-Level Injection

**Without HSTS:**

```
1. ISP or attacker injects HTTP redirect
   HTTP 302 → http://malicious.com

2. User follows redirect over HTTP
   Sensitive data exposed

3. Malware downloaded via HTTP
   Device compromised
```

**With HSTS:**

```
1. Browser refuses HTTP connections entirely
   ERR_SSL_PROTOCOL_ERROR

2. User sees error, cannot proceed
   Attack fails
```

---

## Configuration Examples

### Good Configuration ✅

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Why it's good:**
- `max-age=31536000` - 1 year duration (strong commitment)
- `includeSubDomains` - Protects all subdomains
- `preload` - Eligible for browser preload lists
- Maximum protection against all downgrade attacks

**Use case:** Production websites with HTTPS fully deployed

---

### Acceptable Configuration ⚠️

```
Strict-Transport-Security: max-age=10886400; includeSubDomains
```

**Why it's acceptable:**
- `max-age=10886400` - 126 days (minimum recommended)
- `includeSubDomains` - Subdomain protection enabled
- Missing `preload` - Not on preload lists (first visit vulnerable)

**Use case:** Websites transitioning to HSTS, not yet ready for preload commitment

---

### Weak Configuration ❌

```
Strict-Transport-Security: max-age=300
```

**Why it's bad:**
- `max-age=300` - Only 5 minutes (way too short)
- Missing `includeSubDomains` - Subdomains remain vulnerable
- Missing `preload` - No preload protection
- Policy expires quickly, minimal protection

**Never use this because:** Short duration means browsers forget quickly, leaving users vulnerable after just 5 minutes

---

### Invalid Configuration ❌

```
Strict-Transport-Security: includeSubDomains
```

**Why it's bad:**
- Missing `max-age` directive entirely
- Header is malformed and ignored by browsers
- No protection whatsoever

**Error:** Browsers will reject this header

---

## Common Mistakes

### 1. Setting HSTS Too Short

**Mistake:**
```
Strict-Transport-Security: max-age=86400  # Only 1 day
```

**Fix:**
```
Strict-Transport-Security: max-age=31536000  # 1 year
```

**Why:** Short durations mean the policy expires quickly. Users are vulnerable again after the policy expires. Use at least 126 days (10,886,400 seconds).

---

### 2. Sending HSTS Over HTTP

**Mistake:**
```http
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000
```

**Fix:**
Only send HSTS over HTTPS connections. Browsers **ignore** HSTS headers received over HTTP (by design, to prevent attackers from breaking HTTPS).

---

### 3. Forgetting includeSubDomains

**Mistake:**
```
Strict-Transport-Security: max-age=31536000
```

**Fix:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

**Why:** Without `includeSubDomains`, attackers can target vulnerable subdomains (api.example.com, admin.example.com) even if the main domain is protected.

---

###4. Applying HSTS Before Full HTTPS Deployment

**Mistake:** Setting HSTS when some pages/subdomains still use HTTP

**Result:** Users cannot access HTTP-only resources (broken site)

**Fix:**
1. First, deploy HTTPS everywhere
2. Test thoroughly
3. Then enable HSTS
4. Start with low max-age (e.g., 300) for testing
5. Gradually increase to 31536000

---

## Implementation Guide

### Step 1: Deploy HTTPS Everywhere

Before enabling HSTS, ensure:
- [ ] Valid SSL/TLS certificate installed
- [ ] All pages accessible via HTTPS
- [ ] All subdomains support HTTPS (if using `includeSubDomains`)
- [ ] No mixed content warnings
- [ ] All redirects go to HTTPS versions

### Step 2: Configure Web Server

**Nginx:**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

**Apache:**
```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

**Node.js (Express):**
```javascript
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security',
        'max-age=31536000; includeSubDomains; preload');
    next();
});
```

**Django:**
```python
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

### Step 3: Test Configuration

**Using curl:**
```bash
curl -I https://yourdomain.com | grep Strict-Transport
```

**Expected output:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Using this tool:**
```bash
python -m sha https://yourdomain.com
```

### Step 4: Submit to Preload List (Optional)

1. Go to [hstspreload.org](https://hstspreload.org/)
2. Enter your domain
3. Verify requirements met
4. Submit for inclusion
5. Wait for browser vendors to update (can take months)

---

## Browser Compatibility

| Browser | Version | Support |
|---------|---------|---------|
| Chrome  | 4+      | Full    |
| Firefox | 4+      | Full    |
| Safari  | 7+      | Full    |
| Edge    | 12+     | Full    |
| IE      | 11+     | Full    |
| Opera   | 12+     | Full    |

**Coverage:** 99%+ of all browsers support HSTS

---

## Additional Resources

### Standards & Specifications
- [RFC 6797](https://tools.ietf.org/html/rfc6797) - HSTS Specification
- [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) - Comprehensive reference
- [OWASP HSTS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

### Tools & Testing
- [hstspreload.org](https://hstspreload.org/) - Preload list submission
- [SSL Labs](https://www.ssllabs.com/ssltest/) - Full SSL/TLS + HSTS testing
- [SecurityHeaders.com](https://securityheaders.com/) - Quick header scan

### Related Headers
- [Expect-CT](Expect-CT.md) - Certificate Transparency enforcement (deprecated)
- [CSP](CSP.md) - upgrade-insecure-requests directive

---

## See Also

- [Analyzer Implementation](../ANALYZERS.md#strict-transport-security) - How we validate HSTS
- [Best Practices Guide](../SecurityHeadersBestPractices.md#hsts) - Configuration recommendations
- [Attack Scenarios](../ATTACK_SCENARIOS.md#ssl-stripping) - More attack examples
- [API Usage](../API.md#hsts-analyzer) - Programmatic HSTS analysis

---

**Last Updated:** 2025-12-12
**Status:** Active
**Severity:** Critical
