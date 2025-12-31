# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Automatic retry logic** with exponential backoff for transient failures (429, 503, timeouts)
- **Verbose and quiet modes** (`-v/--verbose`, `-q/--quiet`) for better output control
- **JSON schema versioning** for backwards compatibility tracking
- **Enhanced SSRF protection** with intermediate redirect validation (not just final destination)
- **Robust analyzer validation** - runtime validation of all analyzer return values
- **Maximum timeout validation** - prevents extremely long hangs (300s max)
- **CSP DoS protection** - 10KB size limit to prevent memory exhaustion attacks
- GitHub Actions CI/CD pipeline for automated testing across Python 3.8-3.12
- Pre-commit hooks configuration with black, isort, flake8, mypy, and bandit
- Comprehensive security policy (SECURITY.md) with vulnerability disclosure process
- Contributing guidelines (CONTRIBUTING.md) for external contributors
- Development tool configurations in pyproject.toml (black, isort, mypy, bandit, coverage)
- 18 new edge case tests (IPv6 URLs, malformed CSP, timeout boundaries, schema version)

### Changed
- **CSP parser hardening** - gracefully handles empty directives, duplicates, and malformed input
- **Exception handling improvements** - specific exception types instead of broad catches
- **HTTP error handling** - preserves exit code 3 even when analysis fails during error
- Enhanced pyproject.toml with dev dependencies and tool configurations
- Updated test suite from 478 to 494 tests (97% coverage)
- `fetch_headers_with_retry()` now used by default instead of `fetch_headers()`

### Fixed
- Set-Cookie exception handling now catches specific exceptions only
- CSP parser no longer crashes on extremely long policies (raises ValueError instead)
- Timeout parameter now properly validated with upper bound
- Mock objects in tests properly handled by redirect validation code

## [1.0.0] - 2024-12-04

### Added
- Initial release of Security Header Analyzer
- Core CLI tool for analyzing HTTP security headers
- Support for 9 security headers:
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Content-Security-Policy (CSP)
  - Referrer-Policy
  - Permissions-Policy
  - Cross-Origin-Embedder-Policy (COEP)
  - Cross-Origin-Opener-Policy (COOP)
  - Cross-Origin-Resource-Policy (CORP)

### Security Features
- SSRF (Server-Side Request Forgery) protection
  - Private IP address blocking (RFC 1918, localhost)
  - IPv6 private range blocking
  - Redirect destination validation
  - DNS rebinding attack mitigation
- SSL/TLS certificate validation
- Configurable timeouts and redirect limits

### Header Analysis Features
- **HSTS Analysis:**
  - max-age validation (minimum 10886400 seconds / 126 days)
  - includeSubDomains directive checking
  - preload directive detection

- **X-Frame-Options Analysis:**
  - DENY/SAMEORIGIN validation
  - Deprecated ALLOW-FROM detection

- **Content-Security-Policy Analysis:**
  - unsafe-inline/unsafe-eval detection
  - Wildcard source detection
  - Nonce and hash support validation
  - strict-dynamic support detection

- **Referrer-Policy Analysis:**
  - Policy strictness evaluation
  - Best practice recommendations

- **Permissions-Policy Analysis:**
  - Feature directive parsing
  - Allowlist validation

- **Cross-Origin Headers:**
  - COEP: require-corp validation
  - COOP: isolation level checking
  - CORP: resource sharing policy validation

### CLI Features
- Text and JSON output formats
- Configurable timeout (default: 10 seconds)
- Redirect control (default: follow up to 5)
- Custom User-Agent support
- Debug mode with detailed error information
- Color-coded severity levels in text output

### Testing
- 291 comprehensive unit and integration tests
- 96% code coverage
- Mock-based testing (no external network calls)
- Edge case coverage for all analyzers
- Test fixtures for reusable test data

### Documentation
- Comprehensive README with installation and usage instructions
- Security considerations and SSRF limitations documented
- Responsible use guidelines
- Example outputs for both text and JSON formats
- Best practices documentation for each security header
- Project structure documentation

### Architecture
- Modular design with clear separation of concerns:
  - `fetcher.py`: HTTP header fetching with SSRF protection
  - `analyzer.py`: Analysis orchestration
  - `reporter.py`: Report generation (text/JSON)
  - `config.py`: Shared configuration and exceptions
  - `analyzers/`: Individual header analyzer modules
- Registry pattern for extensible analyzer system
- Custom exception hierarchy for error handling
- Type hints throughout codebase

### Dependencies
- Python 3.8+ required
- Single production dependency: `requests>=2.28.0`

### Development History (Pre-1.0.0)
- Initial project structure and analyzer framework
- Implemented core analyzers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy)
- Added advanced CSP analysis (nonces, hashes, strict-dynamic)
- Implemented cross-origin header analyzers (COEP, COOP, CORP, Permissions-Policy)
- Enhanced fetcher with DNS rebinding protection
- Comprehensive test suite development
- Edge case testing for all security headers
- CLI workflow and integration tests
- Configuration refactoring for better maintainability

## Version History Summary

### Security Updates
No security vulnerabilities fixed in this release.

### Breaking Changes
None - Initial release.

### Deprecations
None - Initial release.

### Known Issues
- TOCTOU vulnerability in SSRF protection (DNS can change between validation and request)
- DNS resolution timeout is OS-controlled (~30 seconds)
- No explicit timeout for socket.getaddrinfo()

See [SECURITY.md](SECURITY.md) for mitigation strategies.

---

## Release Notes Format

For future releases, we follow this format:

### [Version] - YYYY-MM-DD

#### Added
- New features

#### Changed
- Changes to existing functionality

#### Deprecated
- Features marked for removal

#### Removed
- Removed features

#### Fixed
- Bug fixes

#### Security
- Security fixes (disclosed responsibly)

---

**Maintainers:** When releasing a new version:
1. Update version in `sha/__init__.py`
2. Update version in `pyproject.toml`
3. Move unreleased changes to new version section
4. Add release date
5. Create git tag: `git tag -a v1.0.0 -m "Release version 1.0.0"`
6. Push tag: `git push origin v1.0.0`
