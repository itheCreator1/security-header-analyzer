# Quick Start Tutorial

5-minute hands-on tutorial to master Security Header Analyzer basics. Learn by doing with real examples.

## Prerequisites

- Python 3.7+ installed
- Internet connection
- Terminal/command line access

**Installation** (if not already installed):

```bash
pip install security-header-analyzer
```

## Tutorial Overview

You'll learn to:
1. Analyze a website's security headers
2. Interpret results and severity levels
3. Understand security implications
4. Export results for reporting

**Estimated time**: 5 minutes

## Step 1: Your First Security Scan

Let's analyze a popular website:

```bash
sha https://github.com
```

**What you'll see**:

```
Security Header Analysis for https://github.com
================================================

[✓] Strict-Transport-Security: GOOD
    max-age=31536000; includeSubDomains; preload

[✓] Content-Security-Policy: GOOD
    default-src 'none'; base-uri 'self'; ...

[~] X-Frame-Options: ACCEPTABLE
    SAMEORIGIN

...

Headers Found: 12/15
```

**Key observations**:
- `[✓]` (green checkmark) = Good configuration
- `[~]` (yellow wave) = Acceptable but could improve
- `[✗]` (red X) = Bad/insecure configuration
- `[!]` (red exclamation) = Missing header

## Step 2: Understanding Severity Levels

Each finding has a severity rating that indicates urgency:

| Severity | Color | Priority | Example |
|----------|-------|----------|---------|
| **CRITICAL** | 🔴 Red | Fix immediately | Missing HSTS on HTTPS site |
| **HIGH** | 🟠 Orange | Fix soon | Missing Content-Security-Policy |
| **MEDIUM** | 🟡 Yellow | Fix when possible | Weak caching policy |
| **LOW** | 🟢 Green | Nice to have | Missing legacy header |
| **INFO** | ⚪ Gray | No action needed | Properly configured |

**Try analyzing a less secure site**:

```bash
sha http://example.com
```

You'll see more MISSING headers with higher severity (HTTP sites cannot use HSTS).

## Step 3: Reading the Report

Each finding provides:

### 1. Header Name and Status

```
[✗] Content-Security-Policy: BAD (CRITICAL)
```

- **Header**: Content-Security-Policy
- **Status**: BAD (misconfigured)
- **Severity**: CRITICAL (fix immediately)

### 2. Actual Value (if present)

```
    default-src *; script-src *;
```

Shows what the server actually sent.

### 3. Security Message

```
    CSP allows unsafe-inline and wildcards - defeats XSS protection
```

Explains the security issue in plain language.

### 4. Recommendation

```
    Recommendation: Use strict CSP with nonces or hashes instead of unsafe-inline
```

Tells you how to fix it.

## Step 4: Analyzing Your Own Site

Now analyze your own website or development server:

```bash
# Production site
sha https://myapp.com

# Local development (if running a server)
sha http://localhost:3000
```

**What to look for**:

1. **Critical/High severity MISSING headers**:
   - `Strict-Transport-Security` (HSTS)
   - `Content-Security-Policy` (CSP)
   - `X-Frame-Options`

2. **BAD configurations**:
   - Headers with dangerous values
   - Conflicting directives

3. **Count**: How many headers found vs total (e.g., "8/15")

## Step 5: Exporting Results (JSON)

For reporting or automation, export as JSON:

```bash
sha https://github.com --json > github-headers.json
```

**View the JSON**:

```bash
cat github-headers.json | python -m json.tool
```

**JSON structure**:

```json
{
  "url": "https://github.com",
  "headers_found": 12,
  "total_headers": 15,
  "findings": [
    {
      "header_name": "Strict-Transport-Security",
      "status": "good",
      "severity": "info",
      "message": "HSTS is properly configured...",
      "actual_value": "max-age=31536000; includeSubDomains; preload",
      "recommendation": null
    }
  ]
}
```

**Extract specific information with jq** (if installed):

```bash
# Show only critical issues
sha https://mysite.com --json | jq '.findings[] | select(.severity == "critical")'

# Count missing headers
sha https://mysite.com --json | jq '[.findings[] | select(.status == "missing")] | length'
```

## Step 6: Compare Two Sites

Compare security posture of different sites:

```bash
# Analyze multiple sites
sha https://github.com --json > github.json
sha https://gitlab.com --json > gitlab.json

# Compare header counts
echo "GitHub: $(jq '.headers_found' github.json) headers"
echo "GitLab: $(jq '.headers_found' gitlab.json) headers"
```

## Real-World Example: Fixing Issues

Let's walk through fixing a critical issue.

### Problem Found

```bash
sha https://myapp.com
```

**Output**:

```
[!] Strict-Transport-Security: MISSING (CRITICAL)
    Missing HSTS allows SSL stripping attacks
    Recommendation: Add: Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### Understanding the Issue

- **Header**: HSTS (Strict-Transport-Security)
- **Problem**: Not sent by server
- **Risk**: Attackers can downgrade HTTPS to HTTP
- **Attack**: SSL stripping, man-in-the-middle

### Fixing It

Add the header to your web server configuration:

**Nginx**:

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

**Apache**:

```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

**Express.js** (Node.js):

```javascript
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
```

### Verify the Fix

```bash
sha https://myapp.com
```

**Expected output**:

```
[✓] Strict-Transport-Security: GOOD
    max-age=31536000; includeSubDomains
```

## Common Patterns You'll See

### Pattern 1: HTTP Site Missing HTTPS Headers

```bash
sha http://example.com
```

**Result**: Many MISSING headers (HSTS, etc.) - **expected** for HTTP sites.

**Action**: Migrate to HTTPS first, then add security headers.

### Pattern 2: Development Site with Relaxed Security

```bash
sha http://localhost:3000
```

**Result**: Missing headers, permissive CSP.

**Action**: Different headers for dev vs production (use environment variables).

### Pattern 3: Static Site (CDN/GitHub Pages)

```bash
sha https://username.github.io
```

**Result**: Some headers missing (limited control over CDN).

**Action**: Configure what you can (CSP in meta tags, etc.), accept limitations.

## Quick Reference Commands

```bash
# Basic analysis
sha https://example.com

# JSON output
sha https://example.com --json

# Save to file
sha https://example.com --json > results.json

# Check version
sha --version

# Get help
sha --help
```

## What to Do Next

### For Your First Scan

1. **Focus on CRITICAL/HIGH severity** issues first
2. **Read header-specific docs** to understand each header:
   - [docs/headers/hsts.md](headers/hsts.md)
   - [docs/headers/csp.md](headers/csp.md)
   - [docs/headers/x-frame-options.md](headers/x-frame-options.md)
3. **Fix one header at a time**, verify with re-scan
4. **Test thoroughly** after changes (functionality may break)

### Priority Order for Fixes

1. **Strict-Transport-Security (HSTS)** - Critical for HTTPS sites
2. **Content-Security-Policy (CSP)** - Prevents XSS attacks
3. **X-Frame-Options** - Prevents clickjacking
4. **X-Content-Type-Options** - Prevents MIME sniffing
5. Other headers based on your specific needs

## Troubleshooting

### Issue: Network Error

```
Error: Failed to fetch headers from https://example.com
```

**Solutions**:
- Check internet connection
- Verify URL is correct and accessible
- Try with `curl` to test: `curl -I https://example.com`

### Issue: SSRF Warning

```
Error: URL rejected by SSRF protection
```

**Cause**: Trying to scan private/internal IP addresses.

**Solution**: Tool blocks scanning private networks (127.0.0.1, 192.168.x.x, etc.) for security.

### Issue: Timeout

```
Error: Request timed out
```

**Solutions**:
- Server may be slow or unresponsive
- Try again later
- Check if site requires authentication

## Practice Exercises

Test your understanding:

### Exercise 1: Security Audit

Analyze three sites and rank them by security (best to worst):

```bash
sha https://github.com --json > github.json
sha https://example.com --json > example.json
sha https://yoursite.com --json > yoursite.json

# Compare headers_found values
```

### Exercise 2: Find the Issue

Analyze a site and identify:
1. Most critical missing header
2. Any BAD configurations
3. Total number of issues

### Exercise 3: Track Improvement

```bash
# Before fixes
sha https://mysite.com --json > before.json

# (Make your fixes)

# After fixes
sha https://mysite.com --json > after.json

# Compare
diff <(jq '.headers_found' before.json) <(jq '.headers_found' after.json)
```

## Congratulations!

You've completed the quick start tutorial. You can now:

- ✅ Scan websites for security header issues
- ✅ Interpret severity levels and statuses
- ✅ Export results in JSON format
- ✅ Understand basic security implications
- ✅ Know how to fix common issues

## Next Steps

- **Deep dive**: Read [real-world-attack-scenarios.md](real-world-attack-scenarios.md) to understand attacks
- **Advanced usage**: Explore [usage-guide.md](usage-guide.md) for CI/CD integration
- **Header specifics**: Study individual headers in [docs/headers/](headers/)
- **Contributing**: Help improve the tool at [CONTRIBUTING.md](../CONTRIBUTING.md)

## Additional Resources

- **Mozilla Observatory**: https://observatory.mozilla.org/
- **SecurityHeaders.com**: https://securityheaders.com/
- **OWASP Secure Headers**: https://owasp.org/www-project-secure-headers/

Happy scanning! 🔒
