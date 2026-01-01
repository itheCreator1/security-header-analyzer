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

## 6. X-XSS-Protection

**Purpose:** Legacy header that controlled browser XSS filters in Internet Explorer, Chrome, and Safari. Now deprecated in modern browsers.

**Best Practice:**
```
X-XSS-Protection: 0
```
Explicitly disables the XSS filter. This is the modern recommendation because these filters can introduce XSS vulnerabilities in otherwise safe websites.

**Acceptable:**
Not setting the header at all is acceptable for modern applications that implement a strong Content-Security-Policy.

**Bad/Missing:**
- `X-XSS-Protection: 1` (enables the filter without mode=block, can create vulnerabilities)
- `X-XSS-Protection: 1; mode=block` (legacy approach, filter can introduce bugs)

**Severity if Missing:** Low

**Reasoning:** Modern browsers have removed XSS filter functionality, and Content-Security-Policy provides superior protection. However, explicitly setting `0` prevents older browsers from using potentially buggy XSS filters. OWASP recommends either not setting this header or explicitly disabling it with `0` to avoid filter-based vulnerabilities.

**References:**
- [OWASP: X-XSS-Protection](https://owasp.org/www-project-secure-headers/)
- [MDN: X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)

---

## 7. X-Download-Options

**Purpose:** Internet Explorer 8+ specific header that prevents the browser from executing downloaded HTML files in the context of the site. Prevents Same Origin Policy violations during file downloads.

**Best Practice:**
```
X-Download-Options: noopen
```
Forces users to save the file before opening it, preventing execution in the site's security context.

**Acceptable:**
Same as best practice. This header has only one valid value: `noopen`.

**Bad/Missing:**
- Header not present when serving user-controllable HTML content with `Content-Disposition: attachment`
- Any value other than `noopen`

**Severity if Missing:** Low

**Reasoning:** When a user directly opens a downloaded HTML file in IE, scripts in that file can access cookies from the originating domain. This violates the Same Origin Policy by allowing the downloaded file to execute as if it were part of the website. Setting this header forces the save-then-open workflow, ensuring downloaded files execute in a local context. While IE-specific and legacy, this header is still recommended when serving downloadable HTML content.

**References:**
- [OWASP: X-Download-Options](https://owasp.org/www-project-secure-headers/)
- [Microsoft: X-Download-Options](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/)

---

## 8. X-Permitted-Cross-Domain-Policies

**Purpose:** Controls whether Adobe Flash Player, Adobe Acrobat, or PDF documents can load cross-domain policy files from the web server. Prevents untrusted Flash/PDF content from accessing site data.

**Best Practice:**
```
X-Permitted-Cross-Domain-Policies: none
```
Completely prohibits Flash and PDF clients from loading any cross-domain policy files. Most secure option.

**Acceptable:**
```
X-Permitted-Cross-Domain-Policies: master-only
```
Allows only the master policy file (`/crossdomain.xml`) to be loaded. Acceptable if you need to support legacy Flash/PDF content with controlled cross-domain access.

**Bad/Missing:**
- Header not present (allows policy files from any location)
- `all`: Allows policy files from anywhere on the server (very insecure)
- `by-content-type`: Allows policy files served with `Content-Type: text/x-cross-domain-policy` (too permissive)
- `by-ftp-filename`: Allows policy files with specific FTP filenames (legacy, insecure)

**Severity if Missing:** Medium

**Reasoning:** While Adobe Flash is deprecated (EOL December 2020), this header remains relevant for security audits and defense-in-depth. Without proper configuration, attackers could place a malicious `crossdomain.xml` file on your server, allowing Flash/PDF content from other domains to read your application's data and bypass CSRF protections. Many security scanners still check for this header. Setting it to `none` is a simple, zero-cost protection.

**References:**
- [OWASP: X-Permitted-Cross-Domain-Policies](https://owasp.org/www-project-secure-headers/)
- [Adobe: Cross-Domain Policy](https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/xdomain.html)

---

## 9. Set-Cookie

**Purpose:** Controls security attributes for HTTP cookies, protecting against session hijacking, CSRF, and XSS attacks.

**Best Practice:**
```
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
```
- `Secure`: Cookie only sent over HTTPS connections
- `HttpOnly`: Prevents JavaScript access, mitigating XSS cookie theft
- `SameSite=Strict`: Prevents CSRF attacks by blocking cross-site cookie transmission
- `Path=/`: Restricts cookie scope to specific paths
- `Max-Age`: Explicit expiration time

**Cookie Prefixes (Enhanced Security):**
```
Set-Cookie: __Secure-token=xyz; Secure; HttpOnly; SameSite=Strict
Set-Cookie: __Host-session=abc; Secure; HttpOnly; SameSite=Strict; Path=/
```
- `__Secure-` prefix: Requires `Secure` attribute
- `__Host-` prefix: Requires `Secure`, no `Domain` attribute, `Path=/`

**Acceptable:**
```
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Lax
```
- `SameSite=Lax`: Allows cookies on top-level navigation (acceptable for usability)
- Missing `Path` attribute (defaults to current path)

**Bad/Missing:**
- No `Secure` attribute on HTTPS sites (allows cookie transmission over HTTP)
- No `HttpOnly` on session/auth cookies (vulnerable to XSS cookie theft)
- `SameSite=None` without strong justification (enables CSRF)
- Missing `SameSite` entirely (browser-dependent behavior)
- Overly broad `Domain` attribute (cookies sent to all subdomains)

**Severity if Missing:** Medium-High

**Reasoning:** Cookies are the primary authentication mechanism for most web applications. Missing security attributes directly enable session hijacking, CSRF, and XSS attacks. Cookie prefixes (`__Secure-`, `__Host-`) provide additional guarantees that even compromised code cannot weaken cookie security.

---

## 10. Cache-Control

**Purpose:** Controls caching behavior to prevent sensitive data from being stored in browser caches, proxies, or CDNs.

**Best Practice (Sensitive/Private Data):**
```
Cache-Control: no-store, private, must-revalidate
```
- `no-store`: Prevents caching entirely (sensitive data never stored)
- `private`: Only browser cache allowed, no shared caches
- `must-revalidate`: Forces revalidation if cache is used

**Best Practice (Public Static Assets):**
```
Cache-Control: public, max-age=31536000, immutable
```
- `public`: Allows shared caching (CDNs, proxies)
- `max-age=31536000`: Cache for 1 year
- `immutable`: Content will never change (optimal for versioned assets)

**Acceptable:**
```
Cache-Control: private, max-age=3600
```
- Private caching with reasonable expiration for semi-sensitive data
- Appropriate for user-specific content that's not highly sensitive

**Bad/Missing:**
- No `Cache-Control` on sensitive pages (defaults vary, may cache)
- `public` on authenticated/sensitive endpoints (data leaked via shared caches)
- Conflicting directives: `public, private` or `no-store, max-age=3600`
- Long `max-age` without `must-revalidate` (stale sensitive data served)

**Severity if Missing:** Medium

**Reasoning:** Without proper cache controls, sensitive data (bank statements, medical records, personal information) can be stored in browser caches, shared proxies, or CDNs. This data persists after logout and can be accessed by other users on shared computers or via compromised intermediate caches. Cache poisoning attacks can also serve malicious content when caching is misconfigured.

---

## 11. Expect-CT

**Purpose:** Enforces Certificate Transparency (CT) requirements, detecting misissued SSL/TLS certificates.

**Best Practice:**
```
Expect-CT: max-age=86400, enforce, report-uri="https://example.com/ct-report"
```
- `max-age=86400`: Enforce CT for 24 hours
- `enforce`: Block connections if CT requirements not met
- `report-uri`: Send violation reports

**Acceptable:**
```
Expect-CT: max-age=86400, enforce
```
- Enforcement without reporting (acceptable if monitoring is not required)

**Note:** Expect-CT is **deprecated** as of Chrome 107+ (October 2022). Modern browsers enforce CT by default without requiring this header. However, it remains useful for legacy browser support and defense-in-depth.

**Bad/Missing:**
- Header not present (acceptable for modern deployments, CT enforced by browsers)
- `max-age` too short (<1 hour) for effective protection

**Severity if Missing:** Low (deprecated header, browsers enforce CT independently)

**Reasoning:** While Expect-CT helped protect against misissued certificates during the early adoption of Certificate Transparency, modern browsers now enforce CT requirements by default. Setting this header provides backward compatibility for older browsers but is no longer essential for security.

**References:**
- [MDN: Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT)
- [Chrome CT Enforcement](https://groups.google.com/a/chromium.org/g/ct-policy/c/78N3WusE_Ow)

---

## 12. Permissions-Policy

**Purpose:** Controls which browser features and APIs can be used by the page and embedded iframes, reducing attack surface and protecting user privacy.

**Best Practice:**
```
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
```
- Explicitly deny high-risk features unless needed
- Use `()` (empty allowlist) to block feature entirely
- Use `self` to allow only same-origin usage

**Acceptable:**
```
Permissions-Policy: camera=(self), microphone=(self), geolocation=(self)
```
- Allow features for same-origin content (acceptable if application uses these features)

**Bad/Missing:**
- No header (all features allowed by default)
- Wildcard usage: `camera=*` (allows all origins to access camera)
- Enabling high-risk features without justification

**High-Risk Features to Control:**
- `camera`, `microphone`: Privacy invasion
- `geolocation`: User tracking
- `payment`: Financial data access
- `usb`, `serial`, `bluetooth`: Device access

**Severity if Missing:** Low

**Reasoning:** Without Permissions-Policy, embedded third-party content (ads, widgets, iframes) can request access to sensitive browser features like camera, microphone, and geolocation. This header prevents malicious or compromised third-party scripts from accessing these features, protecting user privacy and reducing attack surface.

**References:**
- [MDN: Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy)
- [W3C Permissions Policy](https://www.w3.org/TR/permissions-policy-1/)

---

## 13. Cross-Origin-Embedder-Policy (COEP)

**Purpose:** Prevents a document from loading cross-origin resources that don't explicitly grant permission. Required for enabling powerful features like `SharedArrayBuffer`.

**Best Practice:**
```
Cross-Origin-Embedder-Policy: require-corp
```
- Requires all cross-origin resources to opt-in via CORP header
- Enables cross-origin isolation when combined with COOP
- Necessary for `SharedArrayBuffer` and high-resolution timers

**Acceptable:**
```
Cross-Origin-Embedder-Policy: credentialless
```
- Loads cross-origin resources without credentials (cookies, auth headers)
- Provides weaker isolation but easier to deploy

**Bad/Missing:**
- No header when using `SharedArrayBuffer` or similar APIs (required for these features)
- Using `require-corp` without ensuring all cross-origin resources have appropriate CORP headers (breaks functionality)

**Severity if Missing:** Low (only needed for specific APIs)

**Reasoning:** COEP is primarily needed when using powerful features like `SharedArrayBuffer`, which require cross-origin isolation to mitigate Spectre-like attacks. For standard web applications not using these features, COEP is optional. However, when needed, it provides strong isolation guarantees.

**Cross-Origin Isolation:** Combining `COEP: require-corp` with `COOP: same-origin` enables full cross-origin isolation, which unlocks:
- `SharedArrayBuffer`
- `performance.measureUserAgentSpecificMemory()`
- High-resolution timers without jitter

**References:**
- [MDN: COEP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy)
- [Cross-Origin Isolation Guide](https://web.dev/cross-origin-isolation-guide/)

---

## 14. Cross-Origin-Opener-Policy (COOP)

**Purpose:** Prevents other origins from gaining references to your window object, protecting against cross-origin attacks and enabling process isolation.

**Best Practice:**
```
Cross-Origin-Opener-Policy: same-origin
```
- Prevents cross-origin windows from accessing your window
- Required for full cross-origin isolation (with COEP)
- Enables `SharedArrayBuffer` when combined with COEP

**Acceptable:**
```
Cross-Origin-Opener-Policy: same-origin-allow-popups
```
- Allows same-origin popups while maintaining isolation from cross-origin windows
- Useful when application legitimately opens popups

**Bad/Missing:**
- No header (allows cross-origin window references, potential security risks)
- Using `unsafe-none` (explicitly disables protection)

**Severity if Missing:** Low

**Reasoning:** COOP protects against attacks where malicious sites open your application in a popup and attempt to access its content or manipulate it. Without COOP, attackers can potentially detect user state, measure timing, or exploit side-channel vulnerabilities. When combined with COEP, COOP enables cross-origin isolation necessary for `SharedArrayBuffer`.

**References:**
- [MDN: COOP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)
- [COOP and COEP Explained](https://web.dev/coop-coep/)

---

## 15. Cross-Origin-Resource-Policy (CORP)

**Purpose:** Protects resources from being loaded by cross-origin pages, preventing side-channel attacks and unauthorized embedding.

**Best Practice:**
```
Cross-Origin-Resource-Policy: same-origin
```
- Only same-origin pages can load this resource
- Prevents cross-site embedding and side-channel leaks

**Acceptable:**
```
Cross-Origin-Resource-Policy: same-site
```
- Allows same-site (but different origin) access
- Useful for resources shared across subdomains

**When to Use `cross-origin`:**
```
Cross-Origin-Resource-Policy: cross-origin
```
- For public resources intentionally meant to be embedded (fonts, images, scripts served via CDN)
- Required when COEP is enabled on embedding page

**Bad/Missing:**
- Missing on sensitive resources (allows cross-origin inclusion)
- Using `cross-origin` on private/sensitive data

**Severity if Missing:** Low

**Reasoning:** CORP prevents Spectre-like attacks that exploit cross-origin resource loading to leak data via side channels. It also prevents unauthorized embedding of your resources in other sites. While not critical for all applications, it provides defense-in-depth against timing attacks and resource theft.

**References:**
- [MDN: CORP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy)
- [Resource Isolation Policy](https://resourcepolicy.fyi/)

---

## Summary Table

| Header | Severity if Missing | Ease of Implementation | Security Impact |
|--------|-------------------|----------------------|-----------------|
| HSTS | Critical | Very Easy | Very High |
| CSP | Critical | Hard | Very High |
| X-Frame-Options | High | Very Easy | High |
| Referrer-Policy | High | Very Easy | High |
| X-Content-Type-Options | Medium-High | Very Easy | High |
| Set-Cookie | Medium-High | Medium | High |
| Cache-Control | Medium | Medium | Medium-High |
| X-Permitted-Cross-Domain-Policies | Medium | Very Easy | Medium |
| Expect-CT | Low (deprecated) | Easy | Low |
| X-XSS-Protection | Low (deprecated) | Very Easy | Low |
| X-Download-Options | Low (legacy) | Very Easy | Low |
| Permissions-Policy | Low | Medium | Medium |
| COEP | Low (context-dependent) | Hard | High (when needed) |
| COOP | Low (context-dependent) | Easy | Medium |
| CORP | Low | Easy | Medium |