# Security Headers Best Practices

## 1. Strict-Transport-Security (HSTS)

**Purpose:** Forces HTTPS-only communication, preventing downgrade attacks and man-in-the-middle interception.

**Best Practice:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
- `max-age=31536000`: One year in seconds. Long duration signals serious HTTPS commitment.
- `includeSubDomains`: Applies HSTS to all subdomains, closing gaps in coverage.
- `preload`: Allows inclusion in browser HSTS preload lists for maximum protection.

**Acceptable:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
Preload is optional if the site chooses not to participate in preload lists.

**Bad/Missing:**
- Header not present on HTTPS site
- `max-age` less than 10886400 (126 days) - too short to be effective
- `max-age=0` - explicitly disables HSTS

**Severity if Missing/Bad:** Critical

**Reasoning:** A site serving HTTPS without HSTS is vulnerable to downgrade attacks on initial connection. This is one of the most important headers.

---

## 2. X-Frame-Options

**Purpose:** Prevents clickjacking attacks by controlling whether the page can be framed on other websites.

**Best Practice:**
```
X-Frame-Options: DENY
```
Blocks framing on any external site. Most secure default.

**Acceptable:**
```
X-Frame-Options: SAMEORIGIN
```
Allows framing only on pages from the same origin. Acceptable if the application intentionally needs to frame itself or serves as a component.

**Bad/Missing:**
- Header not present (allows framing from anywhere)
- `X-Frame-Options: ALLOW-FROM` (deprecated and not reliably supported)
- Overly permissive configurations that allow external framing

**Severity if Missing:** High

**Reasoning:** Without this header, attackers can overlay your site in an invisible iframe and trick users into clicking on malicious content. The header is simple and has high impact.

---

## 3. X-Content-Type-Options

**Purpose:** Prevents MIME-type sniffing attacks where browsers guess the content type of files, potentially executing malicious content.

**Best Practice:**
```
X-Content-Type-Options: nosniff
```
There is only one meaningful value for this header.

**Acceptable:**
Same as best practice. This header has only one correct value.

**Bad/Missing:**
- Header not present (browsers will sniff MIME types)
- Any value other than `nosniff`

**Severity if Missing:** Medium-High

**Reasoning:** Without this header, an attacker could upload a .jpg file containing malicious JavaScript. The browser might execute it as script if it detects JavaScript signatures. This is a simple, zero-cost protection.

---

## 4. Content-Security-Policy (CSP)

**Purpose:** Defines a whitelist of trusted sources for scripts, stylesheets, images, and other resources. Prevents inline script injection and XSS attacks.

**Best Practice:**
```
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-cdn.example.com; style-src 'self' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://api.example.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self';
```

Key principles for a good CSP:
- `default-src 'self'`: Restricts all content to same-origin by default
- `script-src`: Explicitly whitelist only necessary script sources. Avoid `'unsafe-inline'` and `'unsafe-eval'`
- `style-src`: Similarly restrict stylesheets
- `img-src`, `font-src`, `connect-src`: Be specific about external resources
- `frame-ancestors 'none'`: Prevent clickjacking (alternative to X-Frame-Options)
- `base-uri 'self'`: Prevent base tag injection
- `form-action 'self'`: Restrict form submission targets

**Acceptable:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;
```
- Simpler policy that still restricts most resource types
- May use `'unsafe-inline'` for styles only (less dangerous than scripts)
- Covers the main attack vectors even if not exhaustive

**Bad/Missing:**
- Header not present (allows inline scripts and external resources from anywhere)
- Policy is too permissive: `default-src *` or `script-src *` (defeats the purpose)
- Using `'unsafe-inline'` for scripts (defeats XSS protection)
- Using `'unsafe-eval'` for scripts (allows eval() and related functions)
- Overly specific policies that break functionality (defeats adoption)

**Severity if Missing:** Critical

**Reasoning:** CSP is the most powerful modern defense against XSS attacks. Its absence means any reflected or stored XSS vulnerability is immediately exploitable. A good CSP demonstrates deep security knowledge.

**Note on Complexity:** CSP is harder to evaluate than other headers because "good" depends on context. A very strict policy is theoretically best but might break the site. An acceptable CSP shows the developer understands the tradeoffs and has made deliberate security choices.

---

## 5. Referrer-Policy

**Purpose:** Controls how much referrer information is sent with requests. Prevents leaking sensitive data in URL parameters (session tokens, personal info) to third parties.

**Best Practice:**
```
Referrer-Policy: strict-origin
```
or
```
Referrer-Policy: no-referrer
```
- `strict-origin`: Sends only the origin (scheme, host, port) when making cross-origin requests over HTTPS. No referrer on HTTP downgrade.
- `no-referrer`: Never sends any referrer information. Maximum privacy but may break some analytics.

**Acceptable:**
```
Referrer-Policy: strict-origin-when-cross-origin
```
or
```
Referrer-Policy: same-origin
```
- `strict-origin-when-cross-origin`: Sends full URL for same-origin requests, only origin for cross-origin requests over HTTPS. This is the default in modern browsers and balances privacy with functionality.
- `same-origin`: Sends full URL only for same-origin requests, no referrer for cross-origin.
- `origin`: Sends only origin for all requests (weaker than strict-origin but still acceptable).

**Bad/Missing:**
- Header not present (uses browser default, which may leak full URLs)
- `unsafe-url`: Always sends full URL, even from HTTPS to HTTP (leaks sensitive URL parameters)
- `no-referrer-when-downgrade`: Sends full URL except on HTTP downgrade (still leaks URL parameters to third parties)

**Severity if Missing:** High

**Reasoning:** Many web applications include sensitive data in URL parameters (session IDs, authentication tokens, user IDs, search queries). Without this header, that information is sent to any third-party site linked from your pages. This has direct privacy and security implications, especially for applications handling sensitive data.

**Example of the Risk:**
A user visits: `https://mybank.com/account?session=abc123&account=9876543210`

Without Referrer-Policy, clicking any external link would send this full URL (including session token and account number) to the third-party site.

---

## Summary Table

| Header | Severity if Missing | Ease of Implementation | Security Impact |
|--------|-------------------|----------------------|-----------------|
| HSTS | Critical | Very Easy | Very High |
| X-Frame-Options | High | Very Easy | High |
| X-Content-Type-Options | Medium-High | Very Easy | High |
| CSP | Critical | Hard | Very High |
| Referrer-Policy | High | Very Easy | High |