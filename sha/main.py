"""
CLI Entry Point - Command-line interface and workflow orchestration

Module: sha.main

Purpose:
    Provides the main() function that orchestrates the complete workflow: parsing
    command-line arguments, fetching headers, analyzing them, generating reports,
    and handling errors with appropriate exit codes.

Overview:
    This module is the heart of the CLI tool. It coordinates all major components
    (fetcher, analyzer, reporter) and provides a clean command-line interface with
    comprehensive error handling. The main() function follows a pipeline pattern:
    parse args → fetch headers → analyze → generate report → output & exit.

Key Functions:
    - main() -> NoReturn
      Primary entry point that orchestrates the entire analysis workflow.
      Never returns (always calls sys.exit with appropriate code).

    - parse_args() -> argparse.Namespace
      Parses and validates command-line arguments. Supports URL input, JSON output,
      timeout configuration, redirect control, custom User-Agent, and debug mode.

Exit Codes:
    0  - Success (analysis completed)
    1  - Network error (timeout, connection failed, SSL error)
    2  - Invalid input (malformed URL, invalid arguments, SSRF blocked)
    3  - HTTP error (4xx, 5xx responses from server)
    130 - User interruption (Ctrl+C / KeyboardInterrupt)

Security Considerations:
    - SSRF protection enforced through fetcher.validate_url_safety()
    - All exceptions caught and mapped to appropriate exit codes
    - No sensitive data logged in normal mode (use --debug cautiously)

Related Modules:
    - sha.fetcher - HTTP header fetching with SSRF protection
    - sha.analyzer - Coordinates analysis across all registered analyzers
    - sha.reporter - Formats findings as text or JSON
    - sha.config - Configuration constants and exception definitions

Example Usage:
    >>> from sha.main import main
    >>> # When called, main() reads sys.argv:
    >>> # $ python -m sha https://example.com --json
    >>> main()  # Executes full workflow and exits with code 0

See Also:
    - docs/USAGE.md - Complete CLI usage guide with examples
    - docs/architecture/components.md#cli-layer - Architecture details
    - docs/architecture/DATA_FLOW.md - Pipeline workflow explained
"""

import argparse
import sys
from typing import NoReturn

from . import __version__
from .analyzer import analyze_headers
from .config import (
    DEFAULT_MAX_REDIRECTS,
    DEFAULT_TIMEOUT,
    MAX_REDIRECTS,
    MAX_TIMEOUT,
    HTTPError,
    InvalidURLError,
    NetworkError,
)
from .fetcher import fetch_headers_with_retry
from .reporter import generate_report


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        prog="sha",
        description="Security Header Analyzer - Analyze HTTP security headers against best practices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s example.com --json
  %(prog)s https://example.com --timeout 30
  %(prog)s https://example.com --json > report.json

Exit codes:
  0 - Success
  1 - Network error (connection failed, timeout, etc.)
  2 - Invalid input (malformed URL, invalid arguments)
  3 - HTTP error (4xx, 5xx response)
        """,
    )

    parser.add_argument(
        "url",
        help="URL to analyze (https:// will be added if no protocol specified)",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format instead of human-readable text",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )

    parser.add_argument(
        "--no-redirects",
        dest="follow_redirects",
        action="store_false",
        default=True,
        help="Do not follow HTTP redirects",
    )

    parser.add_argument(
        "--max-redirects",
        type=int,
        default=DEFAULT_MAX_REDIRECTS,
        metavar="N",
        help=f"Maximum number of redirects to follow (default: {DEFAULT_MAX_REDIRECTS})",
    )

    parser.add_argument(
        "--user-agent",
        type=str,
        default=None,
        metavar="STRING",
        help="Custom User-Agent string",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output (show detailed progress)",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress all output except errors and final report",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode (show full error tracebacks)",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    # Validate arguments
    if args.verbose and args.quiet:
        parser.error("--verbose and --quiet are mutually exclusive")

    if args.timeout <= 0:
        parser.error("timeout must be positive")

    if args.timeout > MAX_TIMEOUT:
        parser.error(f"timeout cannot exceed {MAX_TIMEOUT} seconds")

    if args.max_redirects < 0:
        parser.error("max-redirects must be non-negative")

    if args.max_redirects > MAX_REDIRECTS:
        parser.error(f"max-redirects cannot exceed {MAX_REDIRECTS}")

    return args


def main() -> NoReturn:
    """
    Main entry point for the CLI.

    Orchestrates the entire analysis workflow:
    1. Parse arguments
    2. Fetch headers
    3. Analyze headers
    4. Generate and print report
    5. Exit with appropriate code

    Exit codes:
        0: Success
        1: Network error
        2: Invalid input
        3: HTTP error
    """
    try:
        args = parse_args()
    except SystemExit as e:
        # argparse calls sys.exit() on error or --help
        sys.exit(e.code if e.code is not None else 0)

    url = args.url
    output_format = "json" if args.json else "text"

    try:
        # Fetch headers from URL (with retry logic for transient failures)
        headers = fetch_headers_with_retry(
            url=url,
            timeout=args.timeout,
            follow_redirects=args.follow_redirects,
            max_redirects=args.max_redirects,
            user_agent=args.user_agent,
        )

        # Analyze headers
        findings = analyze_headers(headers)

        # Generate report
        report = generate_report(url, findings, format=output_format)

        # Print report to stdout
        print(report)

        # Exit successfully
        sys.exit(0)

    except InvalidURLError as e:
        # Invalid URL or SSRF attempt
        print(f"Error: Invalid URL - {e}", file=sys.stderr)
        sys.exit(2)

    except NetworkError as e:
        # Network-related errors (connection, timeout, DNS, SSL)
        print(f"Error: Network error - {e}", file=sys.stderr)
        sys.exit(1)

    except HTTPError as e:
        # HTTP error responses (4xx, 5xx)
        # Special handling: if we got headers despite the error, still analyze them
        if e.headers:
            try:
                print(
                    f"Warning: HTTP {e.status_code} error, but analyzing available headers",
                    file=sys.stderr,
                )

                # Analyze the headers we did get
                findings = analyze_headers(e.headers)
                report = generate_report(url, findings, format=output_format)
                print(report)

            except Exception as analyze_error:
                # If analysis fails, report original HTTP error
                print(f"Error: HTTP error - {e}", file=sys.stderr)
                if args.debug:
                    print(f"Analysis also failed: {analyze_error}", file=sys.stderr)

            # Always exit with HTTP error code
            sys.exit(3)
        else:
            # No headers available
            print(f"Error: HTTP error - {e}", file=sys.stderr)
            sys.exit(3)

    except KeyboardInterrupt:
        # User interrupted with Ctrl+C
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)  # Standard exit code for SIGINT

    except Exception as e:
        # Unexpected error
        print(f"Error: Unexpected error - {e}", file=sys.stderr)
        if args.debug:
            # Show traceback in debug mode
            import traceback

            traceback.print_exc()
        sys.exit(1)


# Allow running as a module: python -m sha.main
if __name__ == "__main__":
    main()
