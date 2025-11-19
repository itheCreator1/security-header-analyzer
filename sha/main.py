"""
Main CLI module for Security Header Analyzer.

This module provides the command-line interface and orchestrates
the fetching, analysis, and reporting of security headers.
"""

import sys
import argparse
from typing import NoReturn

from . import __version__
from .config import (
    DEFAULT_TIMEOUT,
    DEFAULT_MAX_REDIRECTS,
    NetworkError,
    InvalidURLError,
    HTTPError,
)
from .fetcher import fetch_headers
from .analyzer import analyze_headers
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
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    # Validate arguments
    if args.timeout <= 0:
        parser.error("timeout must be positive")

    if args.max_redirects < 0:
        parser.error("max-redirects must be non-negative")

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
        # Fetch headers from URL
        headers = fetch_headers(
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
            print(
                f"Warning: HTTP {e.status_code} error, but analyzing available headers",
                file=sys.stderr,
            )

            # Analyze the headers we did get
            findings = analyze_headers(e.headers)
            report = generate_report(url, findings, format=output_format)
            print(report)

            # Still exit with error code
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
        if "--debug" in sys.argv:
            # Show traceback in debug mode
            import traceback
            traceback.print_exc()
        sys.exit(1)


# Allow running as a module: python -m sha.main
if __name__ == "__main__":
    main()
