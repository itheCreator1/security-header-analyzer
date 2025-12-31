# X-Content-Type-Options Security Header

## Quick Reference

**Header:** `X-Content-Type-Options`
**Purpose:** Prevents MIME type sniffing attacks
**Severity if Missing:** Medium
**Complexity:** Easy

**Best Practice:**
```
X-Content-Type-Options: nosniff
```

---

## What It Does

This header tells browsers to strictly follow the `Content-Type` header declared by the server, rather than trying to guess ("sniff") the content type by inspecting the actual content. This prevents MIME confusion attacks where attackers exploit browser content-type detection to execute malicious code.

---

## How It Works

**Only valid value:**
```
X-Content-Type-Options: nosniff
```

When set, browsers will:
- Refuse to load stylesheets if `Content-Type` is not `text/css`
- Refuse to execute scripts if `Content-Type` is not a JavaScript MIME type
- Block downloads if MIME type mismatches

---

## Real-World Attack Scenarios

### Attack: MIME Confusion XSS

**Without X-Content-Type-Options:**

**Step 1:** Attacker uploads "image.jpg" containing JavaScript:
```javascript
alert(document.cookie); // Malicious code in "image"
```

**Step 2:** Server serves with wrong Content-Type:
```http
Content-Type: image/jpeg
```

**Step 3:** Attacker tricks browser to execute as script:
```html
<script src="/uploads/image.jpg"></script>
```

**Step 4:** Old browsers sniff content, detect JavaScript, execute it

**Result:** XSS attack succeeds

---

**With X-Content-Type-Options: nosniff:**

Browser refuses to execute because Content-Type doesn't match:
```
Refused to execute script from '/uploads/image.jpg'
because MIME type ('image/jpeg') is not executable
```

**Result:** Attack prevented

---

## Configuration Examples

### Good ✅
```
X-Content-Type-Options: nosniff
```
Always use this. Only valid value.

### Bad ❌
```
X-Content-Type-Options: sniff
```
Invalid - header will be ignored.

---

## Common Mistakes

**1. Wrong Value**
```
X-Content-Type-Options: off
```
**Fix:** Use `nosniff` (only valid value)

**2. Not Setting for All Responses**
Set globally, not just for HTML pages.

---

## Implementation

**Nginx:**
```nginx
add_header X-Content-Type-Options "nosniff" always;
```

**Apache:**
```apache
Header always set X-Content-Type-Options "nosniff"
```

**Node.js:**
```javascript
res.setHeader('X-Content-Type-Options', 'nosniff');
```

---

## Browser Compatibility

| Browser | Support |
|---------|---------|
| All modern browsers | Full |
| IE 8+ | Full |

**Coverage:** 99%+

---

## See Also

- [CSP](CSP.md) - Complementary XSS protection
- [Analyzer Docs](../analyzer-reference.md#x-content-type-options)

---

**Last Updated:** 2025-12-12
**Status:** Active
