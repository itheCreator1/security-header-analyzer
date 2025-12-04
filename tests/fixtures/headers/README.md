# Security Header Fixtures

This directory contains HTTP security header fixtures captured from real production websites and fictional test scenarios. These fixtures are used for realistic testing of the security header analyzer.

## Purpose

- **Real-world testing**: Validate analyzers against actual production configurations
- **Regression testing**: Ensure analyzers handle complex real-world headers correctly
- **Baseline comparison**: Compare security postures across different sites
- **Edge case validation**: Test against headers we might not think to manually create

## Fixture Format

Each fixture is a JSON file with the following structure:

```json
{
  "site": "example.com",
  "url": "https://example.com",
  "captured_date": "2025-12-04",
  "status_code": 200,
  "headers": {
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "content-security-policy": "...",
    "x-frame-options": "deny"
  },
  "expected_analysis": {
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 1,
    "low_count": 0,
    "notes": "Optional description of expected results"
  }
}
```

### Fields

- **site**: Domain name
- **url**: Full URL (may differ from site if redirected)
- **captured_date**: When headers were captured (YYYY-MM-DD)
- **status_code**: HTTP status code
- **headers**: Dict of response headers (lowercase keys for consistency)
- **expected_analysis** (optional): Expected analyzer results for validation

## Available Fixtures

### Production Sites

Real headers captured from live websites:

- **github_com.json** - GitHub's headers (excellent security posture)
- **google_com.json** - Google's headers (complex CSP)
- **cloudflare_com.json** - Cloudflare's headers (modern configuration)
- **mozilla_org.json** - Mozilla's headers (security-focused organization)
- **aws_amazon_com.json** - AWS CloudFront defaults

### Test Scenarios

Fictional sites for specific test cases:

- **weak_site.json** - Site with minimal/no security headers
- **missing_critical.json** - Site missing only HSTS and CSP

## Usage

### In Tests

```python
from tests.fixtures.headers import load_headers_fixture

def test_with_real_headers():
    # Load GitHub's real headers
    github_data = load_headers_fixture('github_com')
    headers = github_data['headers']

    # Use in your test
    findings = analyze_headers(headers)
    assert len(findings) == 12
```

### With Fixtures

```python
def test_github_security(github_headers):
    """Uses pytest fixture defined in conftest.py"""
    findings = analyze_headers(github_headers)
    # GitHub should have excellent security
    assert all(f['severity'] not in ['critical', 'high'] for f in findings)
```

## Updating Fixtures

### Capture New Headers

Use the fetch script to capture headers from websites:

```bash
# Capture from all predefined sites
python tests/fixtures/scripts/fetch_real_headers.py --all

# Capture from specific sites
python tests/fixtures/scripts/fetch_real_headers.py github.com example.com

# List predefined sites
python tests/fixtures/scripts/fetch_real_headers.py --list
```

### Add Custom Sites

Edit `tests/fixtures/scripts/fetch_real_headers.py` and add to `PREDEFINED_SITES`:

```python
PREDEFINED_SITES = [
    "github.com",
    "google.com",
    "your-site.com",  # Add here
]
```

## Best Practices

1. **Keep fixtures up-to-date**: Re-capture headers periodically as sites change
2. **Normalize keys**: All header keys should be lowercase for consistency
3. **Add expected results**: Include `expected_analysis` to validate test assertions
4. **Document changes**: Note significant changes when updating fixtures
5. **Test coverage**: Ensure all fixtures are used in at least one test

## Maintenance

- **Update frequency**: Quarterly or when major security header changes occur
- **Validation**: Run tests after updating fixtures to catch breaking changes
- **Cleanup**: Remove fixtures for sites that no longer exist or are irrelevant

## Privacy & Legal

- Headers are HTTP metadata, publicly accessible
- No authentication or private data is captured
- Respects robots.txt and rate limits
- Only captures headers, not page content
