# Security Policy

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Security Header Analyzer seriously. If you believe you have found a security vulnerability, please report it to us responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **Email**: Send details to [your-email@example.com] (replace with actual email)
2. **GitHub Security Advisories**: Use the "Security" tab on our GitHub repository
3. **Direct Message**: Contact the maintainers privately through GitHub

### What to Include

Please include the following information in your report:

- **Description**: A clear description of the vulnerability
- **Impact**: What an attacker could achieve by exploiting this vulnerability
- **Reproduction Steps**: Detailed steps to reproduce the issue
- **Affected Versions**: Which versions are affected
- **Proof of Concept**: If possible, include a minimal PoC
- **Suggested Fix**: If you have ideas on how to fix it (optional)

### Response Timeline

- **Initial Response**: Within 48 hours of report
- **Confirmation**: Within 7 days, we'll confirm if it's a valid vulnerability
- **Fix Timeline**: Critical issues will be patched within 14 days
- **Public Disclosure**: After fix is released, coordinated with reporter

## Security Considerations for Users

### Known Limitations

This tool has several known security limitations that users should be aware of:

#### 1. SSRF Protection Limitations

**Time-of-Check-Time-of-Use (TOCTOU) Vulnerability:**
- DNS resolution happens before the HTTP request
- An attacker controlling DNS could pass validation with a public IP, then change DNS to point to a private IP
- The tool validates redirect destinations as additional protection, but this is not foolproof

**Mitigation:**
- Use the tool in isolated environments when scanning untrusted URLs
- Consider network-level controls to prevent access to internal resources
- Use `--no-redirects` flag when scanning untrusted domains

#### 2. DNS Rebinding Attacks

While the tool re-validates IPs after redirects, sophisticated DNS rebinding attacks may still bypass protections:

**Mitigation:**
- Run the tool in sandboxed or containerized environments
- Use network policies to restrict outbound connections
- Monitor network traffic when scanning untrusted URLs

#### 3. Request Behavior

**Default Behavior:**
- Makes HEAD requests by default (no body download)
- Follows up to 5 redirects by default
- 10-second timeout by default
- Validates SSL/TLS certificates

**Security Best Practices:**
```bash
# For maximum security when scanning untrusted URLs:
python -m sha https://example.com --no-redirects --timeout 5

# For testing internal/development URLs:
# DO NOT use this tool to scan internal networks without authorization
```

## Security Features

### Input Validation

- URL scheme validation (only http/https)
- Hostname validation
- Private IP address blocking (RFC 1918, localhost)
- IPv6 private range blocking
- Redirect destination validation

### Network Security

- SSRF protection against private IP ranges:
  - 127.0.0.0/8 (localhost)
  - 10.0.0.0/8 (private)
  - 172.16.0.0/12 (private)
  - 192.168.0.0/16 (private)
  - 169.254.0.0/16 (link-local)
  - ::1/128 (IPv6 localhost)
  - fc00::/7 (IPv6 unique local)
  - fe80::/10 (IPv6 link-local)

### Dependencies

- Single production dependency: `requests>=2.28.0`
- Minimal attack surface
- Regular dependency audits via pip-audit in CI/CD
- Automated security scanning with bandit

## Responsible Use

### Legal Considerations

⚠️ **WARNING**: Only scan websites you own or have explicit permission to test.

Unauthorized scanning may violate:
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom
- Similar laws in other jurisdictions

### Ethical Guidelines

1. **Authorization Required**: Always obtain written permission before scanning third-party websites
2. **Respect Rate Limits**: Don't overwhelm target servers with rapid requests
3. **Data Privacy**: Handle results appropriately; headers may contain sensitive information
4. **Good Faith Testing**: Use the tool for legitimate security assessment only
5. **Responsible Disclosure**: If you find vulnerabilities, report them responsibly

## Security Audit Trail

### Automated Security Checks

Our CI/CD pipeline includes:
- **Bandit**: Python security linting
- **pip-audit**: Dependency vulnerability scanning
- **MyPy**: Static type checking to prevent type-related bugs
- **Pre-commit hooks**: Automated security checks before commits

### Manual Security Reviews

- Code reviews required for all pull requests
- Security-focused review for changes to fetcher.py (network code)
- Review of dependency updates for security implications

## Security Update Process

When a security vulnerability is confirmed:

1. **Assessment**: Evaluate severity and impact
2. **Fix Development**: Develop and test fix in private branch
3. **Review**: Security-focused code review
4. **Testing**: Comprehensive testing including regression tests
5. **Release**: Create patched version following semantic versioning
6. **Notification**: Notify users through GitHub Security Advisories
7. **Disclosure**: Publish details after users have time to update

### Severity Levels

- **Critical**: Remote code execution, authentication bypass
- **High**: Information disclosure, SSRF bypass
- **Medium**: Denial of service, logic errors
- **Low**: Minor security improvements

## Security-Related Configuration

### Environment Variables

Currently, the tool does not use environment variables. All configuration is via CLI arguments.

### File Permissions

The tool does not create or modify files by default. Output is to stdout unless redirected.

## Contact

For security concerns, questions, or responsible disclosure:

- **Security Email**: [your-email@example.com] (replace with actual email)
- **GitHub**: [Create a private security advisory](https://github.com/yourusername/security-header-analyzer/security/advisories/new)

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Contributors who report valid security issues will be acknowledged in our release notes (unless they prefer to remain anonymous).

---

**Last Updated**: 2025-12-04
**Version**: 1.0.0
