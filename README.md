# Security Header Analyzer

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-478%20passing-success.svg)](https://github.com/itheCreator1/security-header-analyzer/actions)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen.svg)](https://github.com/itheCreator1/security-header-analyzer)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A lightweight Python CLI tool that fetches and analyzes HTTP security headers according to Mozilla and OWASP best practices. This tool is designed for developers, penetration testers, and system administrators who want a quick, reliable way to evaluate the security posture of a website's HTTP response headers.

## 🚀 Features

* **15 Security Header Analyzers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Set-Cookie, Cache-Control, Expect-CT, Permissions-Policy, COEP, COOP, CORP, X-XSS-Protection, X-Download-Options, X-Permitted-Cross-Domain-Policies
* **SSRF Protection**: Built-in safeguards against Server-Side Request Forgery attacks
* **Multiple Output Formats**: Human-readable text or JSON for automation
* **Severity Classification**: Issues categorized as Critical, High, Medium, or Low
* **96% Test Coverage**: 478 comprehensive tests ensuring reliability
* **Type Safety**: Full type hints with mypy support
* **CI/CD Ready**: Easy integration with GitHub Actions, GitLab CI, Jenkins
* **Extensible**: Add new header analyzers with minimal code changes

## 📦 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/itheCreator1/security-header-analyzer
cd security-header-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Optionally install in development mode:

```bash
pip install -e .
```

## 🔍 Usage

Run the analyzer from the command line:

```bash
python -m sha https://example.com
```

### Useful options

```
--json               Outputs results in JSON format
--timeout 10         Sets request timeout
--no-redirects       Disables following HTTP redirects
--user-agent "MyBot"  Uses a custom User-Agent
--debug              Shows verbose debug logs
```

## 📖 Documentation

- **[Architecture Guide](docs/architecture-overview.md)** - System design, components, and extensibility
- **[API Documentation](docs/api-reference.md)** - Library usage and programmatic access
- **[Analyzer Reference](docs/analyzer-reference.md)** - Detailed header analysis specifications
- **[Testing Guide](docs/testing-guide.md)** - Running and writing tests
- **[Deployment Guide](docs/deployment-guide.md)** - CI/CD integration and production deployment
- **[Contributing](CONTRIBUTING.md)** - Development workflow and guidelines
- **[Security Policy](SECURITY.md)** - Vulnerability reporting and security considerations
- **[Changelog](CHANGELOG.md)** - Version history and release notes

## 📁 Project Structure

```
security-header-analyzer/
├── sha/                  # Main package
│   ├── __init__.py       # Package initialization
│   ├── __main__.py       # Module entry point
│   ├── main.py           # CLI entry point
│   ├── fetcher.py        # HTTP header fetching with SSRF protection
│   ├── analyzer.py       # Analysis orchestration
│   ├── reporter.py       # Report generation (text/JSON)
│   ├── config.py         # Configuration and exceptions
│   └── analyzers/        # Individual header analyzers (15 total)
├── tests/                # Comprehensive test suite (478 tests, 96% coverage)
├── docs/                 # Documentation
└── .github/              # CI/CD workflows
```

## 💻 Library Usage

Use as a Python library in your own code:

```python
from sha.fetcher import fetch_headers
from sha.analyzer import analyze_headers
from sha.reporter import generate_report

# Fetch and analyze
headers = fetch_headers("https://example.com")
findings = analyze_headers(headers)

# Generate report
report = generate_report(findings, url="https://example.com", format="json")
print(report)
```

See [API Documentation](docs/api-reference.md) for complete reference.

## 🛡 Security Notes

The analyzer follows guidance from:

* **Mozilla Web Security Guidelines**
* **OWASP Secure Headers Project**

**Security Features:**
- SSRF protection against private IP ranges
- DNS rebinding validation
- SSL/TLS certificate verification

**Known Limitations:**
- TOCTOU vulnerability in DNS resolution (documented in [SECURITY.md](SECURITY.md))
- Do not expose as public API without additional safety measures

## 🧪 Running Tests

```bash
# Run all tests
pytest

# With coverage
pytest --cov=sha --cov-report=html

# Run specific test
pytest tests/test_hsts.py -v
```

See [Testing Guide](docs/testing-guide.md) for details.

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Coding standards
- Testing requirements
- Pull request process

## 📊 Project Status

- **Version**: 1.0.0
- **Python**: 3.8, 3.9, 3.10, 3.11, 3.12
- **Tests**: 291 passing
- **Coverage**: 96%
- **License**: MIT

## 🔗 Links

- [GitHub Repository](https://github.com/itheCreator1/security-header-analyzer)
- [Issue Tracker](https://github.com/itheCreator1/security-header-analyzer/issues)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## 📄 License

MIT License - See [LICENSE](LICENSE) for details

---

**Made with security in mind** 🔒
