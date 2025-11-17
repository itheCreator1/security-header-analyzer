# Security Header Analyzer

A lightweight Python CLI tool that fetches and analyzes HTTP security headers against industry best practices.

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python sha/main.py https://example.com
python sha/main.py example.com        # Defaults to HTTPS
python sha/main.py https://example.com --json
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

## Project Structure

```
security-header-analyzer/
├── sha/
│   ├── __init__.py
│   ├── main.py              # CLI entry point
│   ├── fetcher.py           # Fetch headers from URL
│   ├── analyzer.py          # Evaluate headers
│   ├── reporter.py          # Generate reports
│   └── config.py            # Security standards
├── tests/
│   └── test_analyzer.py     # Unit tests
├── requirements.txt
├── README.md
└── .gitignore
```

## License

MIT
