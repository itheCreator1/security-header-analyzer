# Usage Guide

Comprehensive guide to using Security Header Analyzer from the command line for security assessments, automation, and integration.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Command-Line Options](#command-line-options)
- [Output Formats](#output-formats)
- [Advanced Usage Patterns](#advanced-usage-patterns)
- [CI/CD Integration](#cicd-integration)
- [Exit Codes](#exit-codes)

## Basic Usage

### Analyze a Single URL

```bash
sha https://example.com
```

**Output**: Text report showing security header analysis with status, severity, and recommendations.

### Quick Security Check

```bash
# Check if critical headers are present
sha https://myapp.com | grep -E "critical|high"
```

### Analyze HTTPS vs HTTP

```bash
# HTTPS (recommended)
sha https://example.com

# HTTP (allowed but will flag missing Strict-Transport-Security)
sha http://example.com
```

## Command-Line Options

### `--json` - JSON Output

Output results in machine-readable JSON format:

```bash
sha https://example.com --json
```

**JSON Structure**:

```json
{
  "url": "https://example.com",
  "headers_found": 8,
  "total_headers": 15,
  "findings": [
    {
      "header_name": "Strict-Transport-Security",
      "status": "good",
      "severity": "info",
      "message": "HSTS is properly configured...",
      "actual_value": "max-age=31536000; includeSubDomains",
      "recommendation": null
    }
  ]
}
```

**Use cases**:
- Automated security scanning
- Integration with monitoring tools
- Parsing with `jq` for filtering
- CI/CD pipeline processing

### `--version` - Version Information

Display installed version:

```bash
sha --version
```

Output: `security-header-analyzer version X.Y.Z`

### `--help` - Help Documentation

Show usage help:

```bash
sha --help
```

## Output Formats

### Text Format (Default)

Human-readable report with color-coded severity levels:

```bash
sha https://example.com
```

**Example Output**:

```
Security Header Analysis for https://example.com
=================================================

[✓] Strict-Transport-Security: GOOD
    max-age=31536000; includeSubDomains

[!] Content-Security-Policy: MISSING (CRITICAL)
    Missing CSP exposes site to XSS attacks
    Recommendation: Add Content-Security-Policy header

Headers Found: 8/15
```

**Status Indicators**:
- `[✓]` GOOD - Header properly configured
- `[~]` ACCEPTABLE - Header present but could be improved
- `[✗]` BAD - Header misconfigured or dangerous
- `[!]` MISSING - Header not found

### JSON Format

Machine-readable structured data:

```bash
sha https://example.com --json
```

**Parsing with jq**:

```bash
# Extract all critical/high severity issues
sha https://example.com --json | jq '.findings[] | select(.severity == "critical" or .severity == "high")'

# Count missing headers
sha https://example.com --json | jq '.findings[] | select(.status == "missing")' | jq -s 'length'

# Get all recommendations
sha https://example.com --json | jq -r '.findings[].recommendation | select(. != null)'
```

## Advanced Usage Patterns

### Batch Analysis with Scripts

Analyze multiple domains:

**Bash script**:

```bash
#!/bin/bash
# analyze-domains.sh

DOMAINS=(
  "https://example.com"
  "https://example.org"
  "https://example.net"
)

for domain in "${DOMAINS[@]}"; do
  echo "Analyzing $domain..."
  sha "$domain" --json > "results/$(echo $domain | sed 's|https://||').json"
done
```

**Run**:

```bash
chmod +x analyze-domains.sh
mkdir -p results
./analyze-domains.sh
```

### Filtering Results

**Show only critical issues**:

```bash
sha https://example.com --json | jq '.findings[] | select(.severity == "critical")'
```

**Show only missing headers**:

```bash
sha https://example.com --json | jq '.findings[] | select(.status == "missing")'
```

**Count headers by status**:

```bash
sha https://example.com --json | jq '[.findings[] | .status] | group_by(.) | map({status: .[0], count: length})'
```

### Monitoring and Alerting

**Check for regressions** (compare against baseline):

```bash
#!/bin/bash
# check-headers.sh

BASELINE="baseline.json"
CURRENT=$(sha https://myapp.com --json)

# Store baseline on first run
if [ ! -f "$BASELINE" ]; then
  echo "$CURRENT" > "$BASELINE"
  echo "Baseline created"
  exit 0
fi

# Compare header counts
BASELINE_COUNT=$(jq '.headers_found' "$BASELINE")
CURRENT_COUNT=$(echo "$CURRENT" | jq '.headers_found')

if [ "$CURRENT_COUNT" -lt "$BASELINE_COUNT" ]; then
  echo "ERROR: Headers decreased from $BASELINE_COUNT to $CURRENT_COUNT"
  exit 1
fi

echo "OK: $CURRENT_COUNT headers found (baseline: $BASELINE_COUNT)"
```

## CI/CD Integration

### GitHub Actions

Add header checks to pull requests:

**.github/workflows/security-headers.yml**:

```yaml
name: Security Header Check

on: [pull_request, push]

jobs:
  check-headers:
    runs-on: ubuntu-latest
    steps:
      - name: Install security-header-analyzer
        run: pip install security-header-analyzer

      - name: Check production headers
        run: |
          sha https://myapp.com --json > results.json

          # Fail if critical/high severity issues found
          CRITICAL_COUNT=$(jq '[.findings[] | select(.severity == "critical" or .severity == "high")] | length' results.json)

          if [ "$CRITICAL_COUNT" -gt 0 ]; then
            echo "ERROR: Found $CRITICAL_COUNT critical/high severity issues"
            jq '.findings[] | select(.severity == "critical" or .severity == "high")' results.json
            exit 1
          fi

          echo "OK: No critical/high severity issues found"

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: security-header-results
          path: results.json
```

### GitLab CI

**.gitlab-ci.yml**:

```yaml
security_headers:
  stage: test
  image: python:3.9
  script:
    - pip install security-header-analyzer
    - sha https://myapp.com --json > headers.json
    - |
      CRITICAL=$(jq '[.findings[] | select(.severity == "critical")] | length' headers.json)
      if [ "$CRITICAL" -gt 0 ]; then
        echo "CRITICAL security header issues found"
        exit 1
      fi
  artifacts:
    paths:
      - headers.json
    expire_in: 1 week
```

### Jenkins

**Jenkinsfile**:

```groovy
pipeline {
    agent any

    stages {
        stage('Security Header Check') {
            steps {
                sh 'pip install security-header-analyzer'
                sh 'sha https://myapp.com --json > headers.json'

                script {
                    def results = readJSON file: 'headers.json'
                    def critical = results.findings.findAll {
                        it.severity == 'critical' || it.severity == 'high'
                    }

                    if (critical.size() > 0) {
                        error "Found ${critical.size()} critical/high severity issues"
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'headers.json', fingerprint: true
        }
    }
}
```

### Docker Integration

**Dockerfile for automated scanning**:

```dockerfile
FROM python:3.9-slim

RUN pip install security-header-analyzer

ENTRYPOINT ["sha"]
```

**Build and run**:

```bash
# Build image
docker build -t sha-scanner .

# Run analysis
docker run sha-scanner https://example.com --json
```

## Exit Codes

Security Header Analyzer uses specific exit codes for automation:

| Exit Code | Meaning | Description |
|-----------|---------|-------------|
| `0` | Success | Analysis completed successfully |
| `1` | Network Error | Failed to fetch headers (DNS, timeout, connection) |
| `2` | Invalid Input | Invalid URL or SSRF blocked |
| `3` | HTTP Error | Server returned 4xx/5xx status code |
| `130` | User Interrupt | User pressed Ctrl+C |

**Example usage in scripts**:

```bash
#!/bin/bash
sha https://example.com

case $? in
  0)
    echo "Analysis successful"
    ;;
  1)
    echo "Network error - check connectivity"
    exit 1
    ;;
  2)
    echo "Invalid URL or blocked by SSRF protection"
    exit 1
    ;;
  3)
    echo "HTTP error - server returned error status"
    exit 1
    ;;
  130)
    echo "Analysis interrupted"
    exit 130
    ;;
  *)
    echo "Unknown error"
    exit 1
    ;;
esac
```

## Common Workflows

### Pre-Deployment Check

Check headers before deploying to production:

```bash
#!/bin/bash
# pre-deploy-check.sh

STAGING_URL="https://staging.myapp.com"

echo "Checking security headers on staging..."
sha "$STAGING_URL" --json > staging-headers.json

# Check for any BAD or MISSING critical headers
ISSUES=$(jq '[.findings[] | select(.status == "bad" or (.status == "missing" and .severity == "critical"))] | length' staging-headers.json)

if [ "$ISSUES" -gt 0 ]; then
  echo "ERROR: Found $ISSUES critical security issues"
  jq '.findings[] | select(.status == "bad" or (.status == "missing" and .severity == "critical"))' staging-headers.json
  echo "Fix these issues before deploying to production"
  exit 1
fi

echo "OK: Staging headers pass security check"
exit 0
```

### Periodic Monitoring

Run periodic header checks with cron:

```bash
# Add to crontab (crontab -e)
# Run every day at 2 AM
0 2 * * * /usr/local/bin/sha https://myapp.com --json > /var/log/security-headers/$(date +\%Y-\%m-\%d).json
```

### Comparative Analysis

Compare headers between environments:

```bash
#!/bin/bash
# compare-environments.sh

sha https://staging.myapp.com --json > staging.json
sha https://production.myapp.com --json > production.json

STAGING_COUNT=$(jq '.headers_found' staging.json)
PRODUCTION_COUNT=$(jq '.headers_found' production.json)

echo "Staging: $STAGING_COUNT headers"
echo "Production: $PRODUCTION_COUNT headers"

if [ "$STAGING_COUNT" -ne "$PRODUCTION_COUNT" ]; then
  echo "WARNING: Header count mismatch between environments"
fi
```

## Tips and Best Practices

1. **Use JSON for automation**: Always use `--json` flag when integrating with scripts or CI/CD

2. **Check exit codes**: Use exit codes to determine success/failure in automated pipelines

3. **Filter critical issues**: Focus on `critical` and `high` severity findings first

4. **Baseline comparisons**: Store baseline results and compare against them to detect regressions

5. **Environment-specific checks**: Different headers may be acceptable in staging vs production

6. **Regular scans**: Schedule periodic header checks (daily/weekly) to catch configuration drift

7. **Alert on changes**: Set up notifications when header configuration changes unexpectedly

## Next Steps

- Review [quick-start-tutorial.md](quick-start-tutorial.md) for step-by-step walkthrough
- Read [real-world-attack-scenarios.md](real-world-attack-scenarios.md) to understand security implications
- Explore [docs/headers/](headers/) for header-specific configuration guidance

## Getting Help

- **Documentation**: [docs/](../docs/)
- **Issues**: [GitHub Issues](https://github.com/yourusername/security-header-analyzer/issues)
- **Examples**: [examples/](../examples/)
