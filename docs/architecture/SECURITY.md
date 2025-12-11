# Security Architecture

## Overview

Security Header Analyzer includes built-in protection against Server-Side Request Forgery (SSRF) attacks. This document details the security architecture, known vulnerabilities, and mitigation strategies.

---

## SSRF Protection

### What is SSRF?

**Server-Side Request Forgery** is an attack where an attacker tricks the server into making requests to unintended destinations, such as:
- Internal services (localhost, 192.168.x.x)
- Cloud metadata endpoints (169.254.169.254)
- Internal network resources (10.x.x.x, 172.16.x.x)

### Protection Strategy

Security Header Analyzer implements **multi-layer SSRF protection**:

1. **URL normalization** - Ensure proper protocol
2. **DNS validation** - Check resolved IP addresses
3. **Request execution** - Make HTTP request
4. **Redirect validation** - Re-check after redirects

---

## Implementation Details

### Layer 1: URL Normalization

**Function:** `normalize_url(url: str) -> str`

**Location:** `sha/fetcher.py`

**Process:**
```python
def normalize_url(url: str) -> str:
    """Add https:// if no protocol specified."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url
```

**Purpose:**
- Ensures URL has a valid protocol
- Defaults to HTTPS for security

---

### Layer 2: Pre-Request DNS Validation

**Function:** `validate_url_safety(url: str) -> None`

**Location:** `sha/fetcher.py`

**Checks:**
1. Parse URL and extract hostname
2. Resolve hostname to IP addresses
3. Check each IP against private ranges
4. Check hostname against localhost names

**Implementation:**
```python
def validate_url_safety(url: str) -> None:
    """
    Validate URL doesn't resolve to private IPs (SSRF protection).

    Raises:
        InvalidURLError: If URL is unsafe
    """
    parsed = urlparse(url)
    hostname = parsed.hostname

    # Check localhost names
    if hostname.lower() in LOCALHOST_NAMES:
        raise InvalidURLError(f"Blocked localhost: {hostname}")

    # Resolve DNS
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise InvalidURLError(f"Cannot resolve: {hostname}")

    # Check each resolved IP
    for family, _, _, _, sockaddr in addr_info:
        ip = sockaddr[0]
        if is_private_ip(ip):
            raise InvalidURLError(
                f"SSRF attempt blocked: {hostname} resolves to private IP {ip}"
            )
```

**Blocked IP Ranges:**

**IPv4:**
- `127.0.0.0/8` - Loopback
- `10.0.0.0/8` - Private class A
- `172.16.0.0/12` - Private class B
- `192.168.0.0/16` - Private class C
- `169.254.0.0/16` - Link-local (AWS metadata)

**IPv6:**
- `::1` - Loopback
- `fc00::/7` - Unique local addresses
- `fe80::/10` - Link-local

**Blocked Hostnames:**
- `localhost`
- `local`
- `localdomain`

---

### Layer 3: HTTP Request

After DNS validation passes, make the HTTP request:

```python
response = requests.head(
    url,
    timeout=timeout,
    allow_redirects=follow_redirects,
    max_redirects=max_redirects,
    headers={"User-Agent": user_agent},
    verify=True  # SSL/TLS certificate verification
)
```

**Security Features:**
- Configurable timeout (prevents hung requests)
- SSL/TLS certificate verification enabled
- User-Agent customizable
- Only HTTP HEAD requests (minimize data transfer)

---

### Layer 4: Post-Redirect DNS Validation

**Function:** `validate_redirect_destination(final_url: str) -> None`

**Location:** `sha/fetcher.py`

**Purpose:**
Prevent **DNS rebinding attacks** where:
1. Initial DNS resolves to public IP (passes validation)
2. Server redirects to internal URL
3. Attacker changes DNS to point to private IP
4. Follow-up request hits internal service

**Implementation:**
```python
def validate_redirect_destination(final_url: str) -> None:
    """
    Re-validate URL after redirects (DNS rebinding protection).

    Raises:
        InvalidURLError: If redirect destination is unsafe
    """
    if final_url != url:
        validate_url_safety(final_url)
```

**When Applied:**
- After HTTP request completes
- If `response.url != original_url`
- Re-runs full DNS validation on final URL

---

## Known Vulnerabilities

### TOCTOU (Time-of-Check-Time-of-Use)

**Vulnerability Type:** Race condition

**Description:**
There is a window between DNS validation and the actual HTTP request where DNS records can change:

```
Time 0: validate_url_safety("example.com")
        DNS resolves to 1.2.3.4 (public) ✓ PASS

Time 1: [Attacker changes DNS]

Time 2: requests.head("example.com")
        DNS resolves to 192.168.1.1 (private) ✗ ATTACK
```

**Impact:**
An attacker controlling DNS records could:
1. Pass initial validation with a public IP
2. Immediately change DNS to point to private IP
3. Actual request hits internal service

**Likelihood:** Low
- Requires attacker control of DNS
- Requires precise timing
- Most DNS resolvers cache records

**Mitigation Strategies:**

**Current:**
- Redirect validation catches some cases
- Fast execution minimizes window
- SSL/TLS verification prevents some attacks

**Potential (Not Implemented):**
1. **IP-based requests:** Resolve DNS once, make request to IP
   - Trade-off: Breaks virtual hosting and SSL validation

2. **DNS caching:** Cache resolution, use same IP
   - Trade-off: Complexity, TTL management

3. **Firewall rules:** Block private IPs at network level
   - Trade-off: Deployment-specific, not portable

**Recommendation:**
Do not expose this tool as a public API without additional network-level protections (firewall, egress filtering).

---

## Security Best Practices

### For Users

**✅ Do:**
- Use in trusted environments
- Run with minimal privileges
- Configure firewall rules
- Use short timeouts

**❌ Don't:**
- Expose as public API without additional protection
- Run as root/administrator
- Disable SSL verification
- Allow unlimited redirects

### For Developers

**✅ Do:**
- Keep SSRF protection up to date
- Add new private IP ranges as needed
- Document security considerations
- Test with malicious inputs

**❌ Don't:**
- Remove DNS validation
- Disable certificate verification
- Use synchronous requests in production API
- Expose internal URLs

---

## Testing Security Features

### SSRF Protection Tests

**Location:** `tests/test_fetcher.py`

**Test Cases:**
```python
def test_blocks_localhost():
    """Test that localhost is blocked."""
    with pytest.raises(InvalidURLError, match="localhost"):
        validate_url_safety("http://localhost:8080")

def test_blocks_private_ip():
    """Test that private IPs are blocked."""
    with pytest.raises(InvalidURLError, match="private IP"):
        validate_url_safety("http://192.168.1.1")

def test_blocks_cloud_metadata():
    """Test that cloud metadata endpoints are blocked."""
    with pytest.raises(InvalidURLError):
        validate_url_safety("http://169.254.169.254")

def test_allows_public_ip():
    """Test that public IPs are allowed."""
    # This should not raise
    validate_url_safety("http://1.1.1.1")
```

---

## Additional Security Features

### SSL/TLS Verification

**Always enabled:**
```python
response = requests.head(url, verify=True)
```

**Benefits:**
- Prevents man-in-the-middle attacks
- Validates server certificates
- Enforces secure connections

**Trade-off:**
- May fail with self-signed certificates
- No option to disable (by design)

### Timeout Protection

**Default:** 10 seconds

**Benefits:**
- Prevents hung connections
- Limits resource consumption
- Fast failure for offline targets

**Configurable:**
```bash
python -m sha https://example.com --timeout 5
```

### Request Method

**Uses HTTP HEAD only:**

**Benefits:**
- Minimal data transfer
- Faster responses
- Reduces server load
- Headers are the same as GET

**Limitation:**
- Some servers may not support HEAD
- Fallback not implemented

---

## Disclosure Policy

Security vulnerabilities should be reported according to [SECURITY.md](../../SECURITY.md):

1. **DO NOT** open public issues for vulnerabilities
2. Email security concerns privately
3. Allow reasonable time for fixes
4. Coordinate disclosure timing

---

## See Also

- [SECURITY.md](../../SECURITY.md) - Vulnerability reporting policy
- [Components](COMPONENTS.md) - Fetcher layer details
- [Data Flow](DATA_FLOW.md) - Request processing flow
- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) - SSRF attack details
