# Permissions-Policy Security Header

## Quick Reference

**Header:** `Permissions-Policy`
**Purpose:** Controls browser feature access (camera, geolocation, etc.)
**Severity if Missing:** Low
**Complexity:** Hard

**Best Practice:**
```
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

---

## What It Does

Permissions-Policy (formerly Feature-Policy) allows you to control which browser features and APIs your site and embedded iframes can use. This provides defense-in-depth by denying unnecessary permissions.

---

## How It Works

**Syntax:**
```
Permissions-Policy: feature=(allowlist)
```

**Common Features:**
- `camera` - Camera access
- `microphone` - Microphone access
- `geolocation` - Location API
- `payment` - Payment Request API
- `usb` - WebUSB API
- `accelerometer`, `gyroscope` - Motion sensors

**Allowlist Values:**
- `()` - Deny all (including current origin)
- `self` - Allow current origin only
- `*` - Allow all origins
- `("https://example.com")` - Allow specific origin

---

## Real-World Attack Scenarios

### Attack: Malicious Ad Accesses Camera

**Without Permissions-Policy:**

Malicious third-party ad iframe:
```html
<iframe src="https://evil-ad.com"></iframe>
```

Ad requests camera access → User approves → Ad spies on user.

---

**With Permissions-Policy:**

```http
Permissions-Policy: camera=()
```

Camera access denied for all iframes → Attack prevented.

---

## Configuration Examples

### Good (Deny Unused Features) ✅
```
Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=()
```

Denies all unused features.

### Acceptable (Allow Self) ⚠️
```
Permissions-Policy: camera=(self), microphone=(self)
```

Allows current origin but not iframes.

### Allow Trusted Iframe ✅
```
Permissions-Policy: camera=(self "https://trusted-video.com")
```

Allows specific trusted embed.

### Bad (Too Permissive) ❌
```
Permissions-Policy: camera=*, microphone=*
```

Allows all origins - no protection.

---

## Common Mistakes

**1. Denying Needed Features**
Test before deploying - don't break functionality.

**2. Using Old Feature-Policy Syntax**
```http
Feature-Policy: camera 'none'  # Old syntax
```
**Fix:** Use Permissions-Policy with new syntax.

**3. Not Denying Unused Features**
Explicitly deny features you don't use.

---

## Implementation

**Nginx:**
```nginx
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

**Apache:**
```apache
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
```

**Node.js:**
```javascript
res.setHeader('Permissions-Policy', 'camera=(), microphone=()');
```

---

## Browser Compatibility

| Browser | Version | Support |
|---------|---------|---------|
| Chrome  | 88+     | Full |
| Firefox | 74+     | Partial |
| Safari  | 11.1+   | Partial |
| Edge    | 88+     | Full |

---

## See Also

- [MDN Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy)
- [Feature List](https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md)

---

**Last Updated:** 2025-12-12
**Status:** Active
**Recommendation:** Deny unused features for defense-in-depth
