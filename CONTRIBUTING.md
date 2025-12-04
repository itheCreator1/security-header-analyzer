# Contributing to Security Header Analyzer

Thank you for your interest in contributing to Security Header Analyzer! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Adding New Header Analyzers](#adding-new-header-analyzers)
- [Documentation](#documentation)
- [Getting Help](#getting-help)

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow:

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what is best for the project and community
- Show empathy towards other community members

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/security-header-analyzer.git
   cd security-header-analyzer
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/ThodorhsPerros/security-header-analyzer.git
   ```

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv, virtualenv, or conda)

### Installation

1. **Create a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install the package in development mode with dev dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

   This installs:
   - The `sha` package in editable mode
   - All development tools (pytest, black, mypy, etc.)

3. **Install pre-commit hooks**:
   ```bash
   pre-commit install
   ```

4. **Verify installation**:
   ```bash
   pytest
   python -m sha --help
   ```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test improvements

### 2. Make Your Changes

- Write code following our [coding standards](#coding-standards)
- Add tests for new functionality
- Update documentation as needed
- Run pre-commit hooks: `pre-commit run --all-files`

### 3. Test Your Changes

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=sha --cov-report=term-missing

# Run specific test file
pytest tests/test_analyzer.py

# Run specific test
pytest tests/test_analyzer.py::TestAnalyzer::test_specific_case
```

### 4. Commit Your Changes

```bash
git add .
git commit -m "Brief description of changes

More detailed explanation if needed:
- What changed
- Why it changed
- Any breaking changes or migration notes
"
```

Commit message guidelines:
- Use present tense ("Add feature" not "Added feature")
- First line should be 50 characters or less
- Reference issues: "Fix #123: Description"
- Keep commits focused and atomic

### 5. Keep Your Branch Updated

```bash
git fetch upstream
git rebase upstream/main
```

### 6. Push to Your Fork

```bash
git push origin feature/your-feature-name
```

## Coding Standards

### Code Style

We use automated tools to enforce code style:

- **Black**: Code formatting (line length: 100)
- **isort**: Import sorting
- **flake8**: Style linting
- **mypy**: Static type checking

Run all checks:
```bash
# Format code
black sha/ tests/

# Sort imports
isort sha/ tests/

# Lint
flake8 sha/ tests/

# Type check
mypy sha/
```

### Type Hints

All functions must have type hints:

```python
def analyze_header(value: Optional[str]) -> Dict[str, Any]:
    """Analyze a security header value."""
    pass
```

### Docstrings

All public functions, classes, and modules must have docstrings:

```python
def fetch_headers(url: str, timeout: int = 10) -> Dict[str, str]:
    """
    Fetch HTTP headers from a URL using HEAD request.

    Args:
        url: Target URL to fetch headers from
        timeout: Request timeout in seconds (default: 10)

    Returns:
        Dictionary of headers with lowercase keys

    Raises:
        NetworkError: If the request fails
        InvalidURLError: If the URL is invalid

    Examples:
        >>> headers = fetch_headers("https://example.com")
        >>> print(headers.get("strict-transport-security"))
        max-age=31536000
    """
    pass
```

### Code Organization

- Keep functions small and focused (max 50 lines)
- Use meaningful variable and function names
- Avoid deep nesting (max 3-4 levels)
- Follow the single responsibility principle
- Add comments for complex logic only

## Testing Requirements

### Test Coverage

- Minimum 90% code coverage required
- All new features must include tests
- Bug fixes should include regression tests

### Test Structure

```python
import pytest
from sha.analyzer import analyze_header

class TestHeaderAnalyzer:
    """Tests for the header analyzer."""

    def test_valid_header(self):
        """Test analyzer with valid header value."""
        result = analyze_header("max-age=31536000")
        assert result["status"] == "good"

    def test_missing_header(self):
        """Test analyzer with missing header."""
        result = analyze_header(None)
        assert result["status"] == "missing"

    def test_invalid_header(self):
        """Test analyzer with invalid header value."""
        result = analyze_header("invalid")
        assert result["status"] == "bad"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=sha --cov-report=html

# Run specific test file
pytest tests/test_fetcher.py

# Run tests matching pattern
pytest -k "test_ssrf"
```

## Pull Request Process

### Before Submitting

- [ ] All tests pass locally
- [ ] Code is formatted with black
- [ ] Imports are sorted with isort
- [ ] No linting errors from flake8
- [ ] Type checking passes with mypy
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated (if applicable)
- [ ] Pre-commit hooks pass

### Submitting a PR

1. Push your branch to your fork
2. Open a pull request against `main` branch
3. Fill out the PR template completely
4. Link related issues (e.g., "Closes #123")
5. Wait for CI checks to pass
6. Respond to review feedback

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] All tests pass
- [ ] Coverage maintained/improved

## Checklist
- [ ] Code follows project style
- [ ] Self-reviewed code
- [ ] Commented complex code
- [ ] Updated documentation
- [ ] No new warnings
- [ ] Added tests
- [ ] All tests pass
```

## Adding New Header Analyzers

To add support for a new security header:

### 1. Create Analyzer Module

Create `sha/analyzers/your_header.py`:

```python
"""
Analyzer for Your-Header-Name security header.

This header does X, Y, Z for security purposes.
"""

from typing import Dict, Any, Optional

# Define header key (lowercase)
HEADER_KEY = "your-header-name"

# Define configuration
CONFIG = {
    "display_name": "Your-Header-Name",
    "severity_missing": "high",
    "description": "Brief description of what this header does",
    "validation": {
        "good": ["valid-value-1", "valid-value-2"],
        "acceptable": ["acceptable-value"],
        "bad": ["unsafe-value"],
    },
    "messages": {
        "good": "Header is properly configured",
        "acceptable": "Header is set but not optimal",
        "bad": "Header has unsafe value",
        "missing": "Header is not set",
    },
    "recommendations": {
        "missing": "Add 'Your-Header-Name: recommended-value' to your HTTP response headers",
        "bad": "Change value to 'recommended-value'",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Your-Header-Name header value.

    Args:
        value: The header value (None if missing)

    Returns:
        Finding dictionary with status, message, and recommendation
    """
    # Handle missing header
    if value is None:
        return {
            "header_name": CONFIG["display_name"],
            "status": "missing",
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"]["missing"],
            "actual_value": None,
            "recommendation": CONFIG["recommendations"]["missing"],
        }

    # Normalize value
    value_lower = value.lower().strip()

    # Check against validation rules
    if value_lower in CONFIG["validation"]["good"]:
        return {
            "header_name": CONFIG["display_name"],
            "status": "good",
            "severity": "info",
            "message": CONFIG["messages"]["good"],
            "actual_value": value,
            "recommendation": None,
        }

    # Add more validation logic...

    # Default to bad
    return {
        "header_name": CONFIG["display_name"],
        "status": "bad",
        "severity": "high",
        "message": CONFIG["messages"]["bad"],
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["bad"],
    }
```

### 2. Register Analyzer

Update `sha/analyzers/__init__.py`:

```python
from . import your_header

ANALYZER_REGISTRY[your_header.HEADER_KEY] = your_header.analyze
CONFIG_REGISTRY[your_header.HEADER_KEY] = your_header.CONFIG
```

### 3. Add Tests

Create `tests/test_your_header.py`:

```python
import pytest
from sha.analyzers.your_header import analyze, CONFIG

class TestYourHeaderAnalyzer:
    """Tests for Your-Header-Name analyzer."""

    def test_missing_header(self):
        """Test when header is missing."""
        result = analyze(None)
        assert result["status"] == "missing"
        assert result["severity"] == CONFIG["severity_missing"]

    def test_good_value(self):
        """Test with good header value."""
        result = analyze("valid-value-1")
        assert result["status"] == "good"
        assert result["severity"] == "info"

    # Add more tests...
```

### 4. Update Documentation

- Add header description to `docs/ANALYZERS.md`
- Update README.md if needed
- Add entry to CHANGELOG.md

## Documentation

### Documentation Structure

- `README.md` - Project overview and quick start
- `SECURITY.md` - Security policy and considerations
- `CONTRIBUTING.md` - This file
- `CHANGELOG.md` - Version history
- `docs/ARCHITECTURE.md` - System design and architecture
- `docs/API.md` - API documentation for library usage
- `docs/ANALYZERS.md` - Detailed analyzer documentation
- `docs/TESTING.md` - Testing guide
- `docs/DEPLOYMENT.md` - Deployment and integration guide

### Documentation Standards

- Use Markdown for all documentation
- Include code examples where appropriate
- Keep documentation up-to-date with code changes
- Use clear, concise language
- Include diagrams for complex concepts

## Getting Help

### Questions?

- **GitHub Discussions**: Ask questions in discussions
- **GitHub Issues**: Report bugs or request features
- **Documentation**: Check existing documentation

### Reporting Bugs

Use the bug report template:

```markdown
**Describe the bug**
Clear description of the bug

**To Reproduce**
Steps to reproduce:
1. Run command '...'
2. See error

**Expected behavior**
What you expected to happen

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Python version: [e.g., 3.12]
- Package version: [e.g., 1.0.0]

**Additional context**
Any other relevant information
```

### Requesting Features

Use the feature request template:

```markdown
**Is your feature request related to a problem?**
Description of the problem

**Describe the solution you'd like**
Clear description of desired functionality

**Describe alternatives you've considered**
Other solutions you've considered

**Additional context**
Any other relevant information
```

## Recognition

Contributors will be recognized in:
- CHANGELOG.md for their contributions
- GitHub contributors page
- Release notes (for significant contributions)

Thank you for contributing to Security Header Analyzer!
