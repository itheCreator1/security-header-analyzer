#!/usr/bin/env python3
"""
Script to fetch real security headers from websites.

This script captures HTTP headers from production websites for use
as test fixtures. Headers are stored with metadata and can be used
to test the analyzer against real-world configurations.

Usage:
    python fetch_real_headers.py github.com google.com
    python fetch_real_headers.py --all  # Fetch predefined list
    python fetch_real_headers.py --list # Show predefined sites
"""

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Dict, Optional

import requests

# Predefined list of interesting sites to capture
PREDEFINED_SITES = [
    "github.com",
    "google.com",
    "cloudflare.com",
    "mozilla.org",
    "aws.amazon.com",
]

# Output directory (relative to script location)
SCRIPT_DIR = Path(__file__).parent
FIXTURES_DIR = SCRIPT_DIR.parent / "headers"


def fetch_headers(domain: str, timeout: int = 10) -> Optional[Dict]:
    """Fetch headers from a domain.

    Args:
        domain: Domain name (e.g., 'github.com')
        timeout: Request timeout in seconds

    Returns:
        Dict with site data and headers, or None on error
    """
    url = f"https://{domain}"
    print(f"Fetching headers from {url}...", end=" ", flush=True)

    try:
        response = requests.head(url, allow_redirects=True, timeout=timeout)

        # Normalize headers to lowercase for consistency
        normalized_headers = {k.lower(): v for k, v in response.headers.items()}

        data = {
            "site": domain,
            "url": response.url,  # May differ if redirected
            "captured_date": str(date.today()),
            "status_code": response.status_code,
            "headers": normalized_headers,
        }

        print(f"✓ ({response.status_code})")
        return data

    except requests.exceptions.SSLError as e:
        print(f"✗ SSL Error: {e}")
        return None
    except requests.exceptions.Timeout:
        print(f"✗ Timeout after {timeout}s")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"✗ Connection Error: {e}")
        return None
    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def save_fixture(data: dict, output_dir: Path) -> None:
    """Save fixture to JSON file.

    Args:
        data: Fixture data dict
        output_dir: Directory to save fixture in
    """
    filename = f"{data['site'].replace('.', '_')}.json"
    filepath = output_dir / filename

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, sort_keys=False)

    print(f"  Saved to {filepath.relative_to(output_dir.parent.parent)}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Fetch security headers from websites for test fixtures"
    )
    parser.add_argument(
        "domains",
        nargs="*",
        help="Domain names to fetch (e.g., github.com google.com)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=f"Fetch headers from all predefined sites: {', '.join(PREDEFINED_SITES)}",
    )
    parser.add_argument("--list", action="store_true", help="List predefined sites and exit")
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=FIXTURES_DIR,
        help="Output directory (default: ../headers/)",
    )

    args = parser.parse_args()

    # Handle --list
    if args.list:
        print("Predefined sites:")
        for site in PREDEFINED_SITES:
            print(f"  - {site}")
        return 0

    # Determine which domains to fetch
    if args.all:
        domains = PREDEFINED_SITES
    elif args.domains:
        domains = args.domains
    else:
        parser.error("Provide domain names or use --all")

    # Ensure output directory exists
    args.output.mkdir(parents=True, exist_ok=True)

    print(f"\nFetching headers from {len(domains)} site(s)...\n")

    success_count = 0
    for domain in domains:
        data = fetch_headers(domain, timeout=args.timeout)
        if data:
            save_fixture(data, args.output)
            success_count += 1
        print()  # Blank line between sites

    print(f"Complete: {success_count}/{len(domains)} sites captured successfully")
    return 0 if success_count == len(domains) else 1


if __name__ == "__main__":
    sys.exit(main())
