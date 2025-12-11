"""
Module Entry Point - Enables execution as python -m sha

Module: sha.__main__

Purpose:
    Provides the entry point when the package is executed as a module using
    `python -m sha`. This is the standard Python pattern for making packages
    executable from the command line.

Overview:
    When you run `python -m sha https://example.com`, Python executes this
    __main__.py file, which imports and calls the main() function from sha.main
    to start the CLI analyzer workflow.

Key Functions:
    - main() (imported)
      Orchestrates the entire analysis: argument parsing, header fetching,
      analysis execution, and report generation

Usage:
    From command line:
        python -m sha https://example.com
        python -m sha https://example.com --json
        python -m sha https://example.com --timeout 5

    This is equivalent to:
        sha https://example.com  (if installed via pip install -e .)

Related Modules:
    - sha.main - Contains the main() function implementation
    - sha.analyzer - Header analysis orchestration
    - sha.fetcher - HTTP header fetching

See Also:
    - docs/USAGE.md - Command-line usage examples
    - docs/INSTALLATION.md - Installation and setup guide
    - docs/architecture/COMPONENTS.md#cli-layer - CLI architecture
"""

from .main import main

if __name__ == "__main__":
    main()
