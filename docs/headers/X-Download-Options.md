# X-Download-Options Security Header

## Quick Reference

**Header:** `X-Download-Options`
**Purpose:** Prevents IE from executing downloads in site context
**Severity if Missing:** Low
**Complexity:** Easy
**Browsers:** Internet Explorer 8+ only

**Best Practice:**
```
X-Download-Options: noopen
```

---

## What It Does

This header prevents Internet Explorer from directly opening downloaded files in the browser context of your site. Instead, IE must save the file first before opening it.

**Relevance:** IE-specific header, minimal impact on modern web security.

---

## How It Works

**Only valid value:**
```
X-Download-Options: noopen
```

**Without header:**
IE can open downloads (like PDFs, Office docs) directly in browser with access to your site's cookies/session.

**With header:**
IE forces "Save As" dialog, file opens separately without site context.

---

## Real-World Attack (Historical)

**Without X-Download-Options:**

1. User downloads malicious file from your site
2. IE opens file directly in browser
3. Malicious file has access to your site's cookies/DOM
4. File steals session data

**With noopen:**

1. User must save file first
2. File opens outside browser context
3. No access to site data

---

## Configuration Examples

### Good ✅
```
X-Download-Options: noopen
```

Only valid value - forces save before open.

### Invalid ❌
```
X-Download-Options: open
```

Not a valid value.

---

## Implementation

**Nginx:**
```nginx
add_header X-Download-Options "noopen" always;
```

**Apache:**
```apache
Header always set X-Download-Options "noopen"
```

---

## Browser Compatibility

| Browser | Support |
|---------|---------|
| IE 8+ | Yes |
| Edge | Legacy mode only |
| Others | Ignored |

**Modern relevance:** Very low (IE deprecated).

---

## See Also

- [CSP](CSP.md) - Modern security approach
- [Best Practices](../SecurityHeadersBestPractices.md)

---

**Last Updated:** 2025-12-12
**Status:** Legacy (IE-specific)
**Recommendation:** Set for defense-in-depth if supporting IE
