# Security Header Analyzer

A lightweight Python CLI tool that fetches and analyzes HTTP security headers against industry best practices.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/security-header-analyzer.git
cd security-header-analyzer

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Or install in development mode
pip install -e .
```

**Requirements:** Python 3.8 or higher

## Usage

```bash
# Basic usage
python -m sha https://example.com
python -m sha example.com        # Defaults to HTTPS

# Advanced options
python -m sha https://example.com --json
python -m sha https://example.com --timeout 30
python -m sha https://example.com --no-redirects
python -m sha https://example.com --user-agent "CustomBot/1.0"
python -m sha https://example.com --debug
```

## What It Does

1. Fetches security headers from a URL using HEAD requests
2. Compares them against security standards (HSTS, X-Frame-Options, etc.)
3. Reports findings with severity levels
4. Supports JSON output for automation

## Headers Analyzed

- **Strict-Transport-Security (HSTS)** - Forces HTTPS communication
- **X-Frame-Options** - Prevents clickjacking attacks
- **X-Content-Type-Options** - Prevents MIME-type sniffing
- **Content-Security-Policy** - Prevents XSS attacks
- **Referrer-Policy** - Controls referrer information leakage

## Example Output

```
======================================================================
SECURITY HEADER ANALYSIS REPORT
======================================================================

URL: https://example.com
Timestamp: 2025-11-17T17:30:00.000Z

SUMMARY
----------------------------------------------------------------------
Critical Issues: 0
High Issues:     0
Medium Issues:   0
Low Issues:      0

DETAILED FINDINGS
----------------------------------------------------------------------

[Info] Strict-Transport-Security
Status: good
Message: HSTS header is properly configured
Value: max-age=31536000; includeSubDomains; preload

[Info] X-Frame-Options
Status: good
Message: X-Frame-Options is set to DENY (best practice)
Value: DENY
```

## Security Considerations

### SSRF Protection Limitations

This tool includes SSRF (Server-Side Request Forgery) protection to prevent scanning internal networks. However, there are known limitations:

**Time-of-Check-Time-of-Use (TOCTOU) Vulnerability:**
- DNS resolution happens before the request
- An attacker controlling DNS could pass validation with a public IP, then change DNS to point to a private IP
- The tool validates redirect destinations as additional protection, but this is not foolproof

**DNS Rebinding Attacks:**
- While the tool re-validates IPs after redirects, sophisticated attacks may still bypass protections
- DNS resolution is cached by the OS and can change between checks

### Responsible Use Guidelines

⚠️ **Legal and Ethical Considerations:**

1. **Authorization Required**: Only scan websites you own or have explicit permission to test
2. **Respect Rate Limits**: The tool can make rapid requests; ensure you're not overwhelming target servers
3. **Privacy**: Headers may contain sensitive information; handle results appropriately
4. **Third-Party Services**: Scanning third-party websites without permission may violate:
   - Computer Fraud and Abuse Act (CFAA) in the US
   - Computer Misuse Act in the UK
   - Similar laws in other jurisdictions

### Trust Considerations

- **DNS Trust**: The tool trusts DNS responses for SSRF protection; compromised DNS can bypass security
- **Certificate Validation**: SSL/TLS certificates are validated by the requests library
- **Redirect Trust**: The tool follows up to 5 redirects by default; malicious redirects could be used in attacks

### Recommendations for Safe Use

```bash
# For production use, consider:
# 1. Limit redirects
python -m sha https://example.com --max-redirects 2

# 2. Set reasonable timeouts
python -m sha https://example.com --timeout 10

# 3. Use explicit protocols
python -m sha https://example.com  # Not just "example.com"

# 4. Disable redirects for maximum security
python -m sha https://example.com --no-redirects
```

## Project Structure

```
security-header-analyzer/
├── sha/
│   ├── __init__.py
│   ├── main.py              # CLI entry point
│   ├── fetcher.py           # Fetch headers from URL (with SSRF protection)
│   ├── analyzer.py          # Coordinate header analysis
│   ├── reporter.py          # Generate reports
│   ├── config.py            # Shared configuration and exceptions
│   └── analyzers/           # Individual header analyzer modules
│       ├── __init__.py      # Analyzer registry
│       ├── hsts.py          # HSTS analyzer
│       ├── xframe.py        # X-Frame-Options analyzer
│       ├── content_type.py  # X-Content-Type-Options analyzer
│       ├── csp.py           # CSP analyzer
│       └── referrer_policy.py  # Referrer-Policy analyzer
├── tests/
│   └── test_analyzer.py     # Unit tests (96% coverage)
├── docs/
│   └── SecurityHeadersBestPractices.md
├── requirements.txt
├── pyproject.toml
├── README.md
└── .gitignore
```

## License

MIT
