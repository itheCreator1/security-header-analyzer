# COEP (Cross-Origin-Embedder-Policy) Security Header

## Quick Reference

**Header:** `Cross-Origin-Embedder-Policy`
**Purpose:** Controls cross-origin resource embedding
**Severity if Missing:** Low
**Complexity:** Medium

**Best Practice:**
```
Cross-Origin-Embedder-Policy: require-corp
```

---

## What It Does

COEP ensures that cross-origin resources explicitly opt-in to being loaded by your page. This is required to enable powerful browser features like `SharedArrayBuffer` and helps mitigate Spectre attacks.

---

## How It Works

**Values:**
- **`require-corp`** - Cross-origin resources need CORP header
- **`unsafe-none`** - No restrictions (default)
- **`credentialless`** - Load without credentials (experimental)

**Use with:**
- Must combine with `Cross-Origin-Opener-Policy` (COOP)
- Resources need `Cross-Origin-Resource-Policy` (CORP)

---

## Real-World Context

### Why It Exists: Spectre Mitigation

**Spectre attack:**
Can leak cross-origin data using timing attacks and shared memory.

**COEP + COOP:**
Creates cross-origin isolated environment → Enables `SharedArrayBuffer` safely → Mitigates Spectre risks.

---

## Configuration Examples

### Good (Enable Isolation) ✅
```
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
```

Enables cross-origin isolation.

### Default ⚠️
```
Cross-Origin-Embedder-Policy: unsafe-none
```

No isolation, no protection.

---

## Common Mistakes

**1. Setting COEP Without COOP**
Both headers needed for cross-origin isolation.

**2. Breaking Third-Party Resources**
External images/scripts need CORP header.

**3. Not Testing First**
Use report-only mode initially:
```
Cross-Origin-Embedder-Policy-Report-Only: require-corp
```

---

## Implementation

**Nginx:**
```nginx
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
```

**Check isolation:**
```javascript
if (crossOriginIsolated) {
    // Can use SharedArrayBuffer
}
```

---

## Browser Compatibility

| Browser | Version | Support |
|---------|---------|---------|
| Chrome  | 88+     | Full |
| Firefox | 79+     | Full |
| Safari  | 15.2+   | Full |
| Edge    | 88+     | Full |

---

## See Also

- [COOP](COOP.md) - Companion header
- [CORP](CORP.md) - Resource policy
- [MDN COEP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy)

---

**Last Updated:** 2025-12-12
**Status:** Active
**Use Case:** Advanced applications needing SharedArrayBuffer
