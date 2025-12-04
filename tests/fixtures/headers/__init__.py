"""Utilities for loading real-world header fixtures.

This module provides utilities to load security header fixtures captured from
real production websites. Fixtures are stored as JSON files and include the
headers, expected analysis results, and metadata.
"""

import json
from pathlib import Path
from typing import Any, Dict

FIXTURES_DIR = Path(__file__).parent


def load_headers_fixture(site_name: str) -> Dict[str, Any]:
    """Load headers fixture for a site.

    Args:
        site_name: Name like 'github', 'google', 'cloudflare', etc.
                  (without .json extension)

    Returns:
        Dict with site data including:
        - site: Domain name
        - url: Full URL captured
        - captured_date: When headers were captured
        - status_code: HTTP status code
        - headers: Dict of response headers (lowercase keys)
        - expected_analysis: (optional) Expected analyzer results

    Raises:
        FileNotFoundError: If no fixture exists for the site name
    """
    fixture_file = FIXTURES_DIR / f"{site_name}.json"
    if not fixture_file.exists():
        raise FileNotFoundError(
            f"No fixture for '{site_name}'. "
            f"Available fixtures: {', '.join(get_available_fixtures())}"
        )

    with open(fixture_file) as f:
        return json.load(f)


def get_all_fixtures() -> Dict[str, Dict[str, Any]]:
    """Load all available header fixtures.

    Returns:
        Dict mapping site names to their fixture data
    """
    fixtures = {}
    for json_file in FIXTURES_DIR.glob("*.json"):
        site_name = json_file.stem
        try:
            fixtures[site_name] = load_headers_fixture(site_name)
        except json.JSONDecodeError:
            # Skip invalid JSON files
            continue
    return fixtures


def get_available_fixtures() -> list[str]:
    """Get list of available fixture names.

    Returns:
        List of fixture names (without .json extension)
    """
    return sorted([f.stem for f in FIXTURES_DIR.glob("*.json")])


__all__ = [
    "load_headers_fixture",
    "get_all_fixtures",
    "get_available_fixtures",
    "FIXTURES_DIR",
]
