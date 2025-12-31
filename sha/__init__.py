"""
Security Header Analyzer - Package Initialization

Module: sha

Purpose:
    Main package initialization for Security Header Analyzer. Exposes the primary
    entry point (main function) and version information for external use.

Overview:
    This package provides tools to fetch and analyze HTTP security headers from
    websites according to Mozilla and OWASP best practices. It's designed for
    developers, penetration testers, and system administrators who need to
    evaluate the security posture of web applications.

Key Exports:
    - main() -> NoReturn
      Primary entry point that runs the CLI analyzer workflow

    - __version__: str
      Current version of the package (semantic versioning)

Example Usage:
    >>> from sha import main, __version__
    >>> print(__version__)
    "1.0.0"
    >>> # Run analyzer programmatically
    >>> # main() will parse sys.argv and execute

Related Modules:
    - sha.main - CLI entry point and orchestration
    - sha.analyzer - Header analysis coordination
    - sha.fetcher - HTTP header fetching with SSRF protection
    - sha.reporter - Report generation (text/JSON formats)

See Also:
    - docs/API.md - Library usage and programmatic access
    - docs/architecture/components.md - Package structure details
    - README.md - Project overview and quick start
"""

__version__ = "1.0.0"

from .main import main

__all__ = ["main", "__version__"]
