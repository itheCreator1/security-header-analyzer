# Security Header Analyzer

A lightweight Python CLI tool that fetches and analyzes HTTP security headers according to Mozilla and OWASP best practices. This tool is designed for developers, penetration testers, and system administrators who want a quick, reliable way to evaluate the security posture of a website’s HTTP response headers.

## 🚀 Features

* Fetches HTTP response headers from a target URL
* Analyzes security-related headers:

  * Strict-Transport-Security (HSTS)
  * Content-Security-Policy (CSP)
  * X-Frame-Options
  * X-Content-Type-Options
  * Referrer-Policy
* Provides categorized findings: **Critical**, **High**, **Medium**, **Low**
* JSON output option for automation pipelines
* Custom User-Agent support
* Optional redirect blocking
* Timeout and error handling
* Clean, structured terminal reports

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

## 📁 Project Structure

```
security-header-analyzer/
├── sha/                  # Main package
│   ├── cli.py            # CLI entry point
│   ├── fetcher.py        # HTTP fetching logic
│   ├── analyzer.py       # Header analysis engine
│   ├── reporter.py       # Formatting and reporting
│   └── headers/          # Individual header analyzers
└── tests/                # Unit tests (~96% coverage)
```

## 🛡 Security Notes

The analyzer follows guidance from:

* **Mozilla Web Security Guidelines**
* **OWASP Secure Headers Project**

While it includes basic SSRF protections, DNS rebinding and TOCTOU-style attacks may bypass certain checks. Do not expose this tool as a public API without additional safety measures.

## 🧪 Running Tests

```
pytest
```

## 📄 License

MIT License
