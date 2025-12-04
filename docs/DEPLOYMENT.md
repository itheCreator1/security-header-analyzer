# Deployment and Integration Guide

## Installation Methods

### From Source (Development)

```bash
git clone https://github.com/itheCreator1/security-header-analyzer
cd security-header-analyzer
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

### Production Install

```bash
pip install git+https://github.com/itheCreator1/security-header-analyzer.git
```

### Verify Installation

```bash
python -m sha --help
sha --help  # If installed system-wide
```

## Configuration

### Environment Variables

Currently not used. All configuration via CLI arguments.

### CLI Arguments

```bash
python -m sha <url> [options]

Options:
  --json               Output in JSON format
  --timeout SECONDS    Request timeout (default: 10)
  --no-redirects       Don't follow HTTP redirects
  --max-redirects N    Maximum redirects (default: 5)
  --user-agent STRING  Custom User-Agent
  --debug              Show debug information
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Headers Check
on: [push, pull_request]

jobs:
  security-headers:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install tool
        run: |
          pip install git+https://github.com/itheCreator1/security-header-analyzer.git
      - name: Check headers
        run: |
          python -m sha https://staging.example.com --json > results.json
          # Parse JSON and fail if high-severity issues found
```

### GitLab CI

```yaml
security-headers:
  image: python:3.12
  script:
    - pip install git+https://github.com/itheCreator1/security-header-analyzer.git
    - python -m sha https://staging.example.com
  only:
    - main
    - develop
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Check Security Headers') {
            steps {
                sh '''
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install git+https://github.com/itheCreator1/security-header-analyzer.git
                    python -m sha https://production.example.com --json > headers.json
                '''
            }
        }
    }
}
```

## Docker Usage

### Dockerfile

```dockerfile
FROM python:3.12-slim

RUN pip install git+https://github.com/itheCreator1/security-header-analyzer.git

ENTRYPOINT ["python", "-m", "sha"]
CMD ["--help"]
```

### Build and Run

```bash
# Build image
docker build -t security-header-analyzer .

# Run analysis
docker run security-header-analyzer https://example.com

# JSON output
docker run security-header-analyzer https://example.com --json
```

## Automation Scripts

### Bash Script

```bash
#!/bin/bash
# check-headers.sh

URLS=(
    "https://production.example.com"
    "https://staging.example.com"
    "https://api.example.com"
)

for url in "${URLS[@]}"; do
    echo "Checking $url..."
    python -m sha "$url" --json > "results-$(echo $url | sed 's/https:\/\///g' | sed 's/\//-/g').json"
done

echo "Analysis complete. Check results-*.json files."
```

### Python Script

```python
#!/usr/bin/env python3
"""Batch analyze multiple URLs."""

import json
import sys
from sha.fetcher import fetch_headers_safe
from sha.analyzer import analyze_headers

URLS = [
    "https://production.example.com",
    "https://staging.example.com",
    "https://api.example.com",
]

def main():
    results = {}
    
    for url in URLS:
        print(f"Analyzing {url}...", file=sys.stderr)
        headers, error = fetch_headers_safe(url, timeout=10)
        
        if error:
            results[url] = {"error": str(error)}
            continue
        
        findings = analyze_headers(headers)
        high_severity = [
            f for f in findings
            if f["severity"] in ["critical", "high"]
        ]
        
        results[url] = {
            "total_findings": len(findings),
            "high_severity_count": len(high_severity),
            "findings": findings
        }
    
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
```

## Integration Examples

### Slack Notifications

```python
import requests
from sha.fetcher import fetch_headers
from sha.analyzer import analyze_headers

def send_slack(message):
    webhook = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    requests.post(webhook, json={"text": message})

headers = fetch_headers("https://production.example.com")
findings = analyze_headers(headers)
high_issues = [f for f in findings if f["severity"] in ["critical", "high"]]

if high_issues:
    send_slack(f"⚠️ {len(high_issues)} high-severity header issues found!")
```

### Prometheus Metrics

```python
from prometheus_client import Gauge, push_to_gateway
from sha.fetcher import fetch_headers
from sha.analyzer import analyze_headers

headers = fetch_headers("https://example.com")
findings = analyze_headers(headers)

# Create metrics
high_issues = Gauge('security_headers_high_issues', 'High severity issues')
medium_issues = Gauge('security_headers_medium_issues', 'Medium severity issues')

# Set values
high_count = len([f for f in findings if f["severity"] == "high"])
medium_count = len([f for f in findings if f["severity"] == "medium"])

high_issues.set(high_count)
medium_issues.set(medium_count)

# Push to Prometheus
push_to_gateway('localhost:9091', job='security_headers', registry=...)
```

## Monitoring and Alerting

### Cron Job

```bash
# Add to crontab
0 */6 * * * /usr/bin/python3 -m sha https://production.example.com --json > /var/log/security-headers.json 2>&1
```

### Systemd Timer

```ini
# /etc/systemd/system/security-headers.timer
[Unit]
Description=Security Header Check Timer

[Timer]
OnCalendar=*-*-* 00:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/security-headers.service
[Unit]
Description=Security Header Check

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -m sha https://production.example.com
User=monitoring
```

## Troubleshooting

### Common Issues

**1. Import Error**
```bash
# Problem
ModuleNotFoundError: No module named 'sha'

# Solution
pip install -e .
# or
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**2. Timeout Errors**
```bash
# Increase timeout
python -m sha https://example.com --timeout 30
```

**3. SSRF Protection Blocking Valid URLs**
```python
# If legitimate URL is blocked, check DNS resolution
import socket
print(socket.getaddrinfo("example.com", None))

# Consider using --no-redirects if redirects are problematic
python -m sha https://example.com --no-redirects
```

## Performance Tuning

### Optimize for Speed

```bash
# Short timeout, no redirects
python -m sha https://example.com --timeout 5 --no-redirects
```

### Batch Processing

Use the safe wrapper for multiple URLs:

```python
from sha.fetcher import fetch_headers_safe

urls = [...]  # Many URLs
for url in urls:
    headers, error = fetch_headers_safe(url, timeout=5)
    if error:
        continue
    # Process headers...
```

## Security Considerations

### Running in Production

1. **Isolate the tool**: Run in containerized environment
2. **Network policies**: Restrict outbound connections
3. **Rate limiting**: Don't overwhelm target servers
4. **Logging**: Log all analysis attempts
5. **Authentication**: Require auth for API access

### SSRF Mitigation

- Tool has built-in SSRF protection
- Additional network-level controls recommended
- See [SECURITY.md](../SECURITY.md) for details

## Scaling

### Parallel Analysis

```python
from concurrent.futures import ThreadPoolExecutor
from sha.fetcher import fetch_headers_safe
from sha.analyzer import analyze_headers

def analyze_url(url):
    headers, error = fetch_headers_safe(url)
    if error:
        return url, None, error
    findings = analyze_headers(headers)
    return url, findings, None

urls = [...]  # Many URLs

with ThreadPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(analyze_url, urls))
```

## Further Reading

- [API Documentation](./API.md)
- [Architecture](./ARCHITECTURE.md)
- [Testing Guide](./TESTING.md)
