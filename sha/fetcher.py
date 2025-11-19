"""
Fetcher module for Security Header Analyzer.

This module handles fetching HTTP headers from URLs with proper error handling
and security protections (SSRF prevention).
"""

import socket
import ipaddress
from typing import Dict, Optional
from urllib.parse import urlparse
import requests

from .config import (
    DEFAULT_TIMEOUT,
    DEFAULT_MAX_REDIRECTS,
    DEFAULT_USER_AGENT,
    PRIVATE_IP_RANGES,
    LOCALHOST_NAMES,
    NetworkError,
    InvalidURLError,
    HTTPError,
)


def normalize_url(url: str) -> str:
    """
    Normalize URL by adding HTTPS protocol if missing.

    Args:
        url: URL string (may or may not include protocol)

    Returns:
        Normalized URL with protocol

    Examples:
        >>> normalize_url("example.com")
        "https://example.com"
        >>> normalize_url("http://example.com")
        "http://example.com"
        >>> normalize_url("https://example.com")
        "https://example.com"
    """
    url = url.strip()

    # If no protocol specified, default to HTTPS
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    return url


def is_private_ip(ip_str: str) -> bool:
    """
    Check if an IP address is in a private range.

    Args:
        ip_str: IP address string (IPv4 or IPv6)

    Returns:
        True if IP is private/local, False otherwise

    Raises:
        ValueError: If IP address is invalid
    """
    try:
        ip = ipaddress.ip_address(ip_str)

        # Check against configured private ranges
        for range_str in PRIVATE_IP_RANGES:
            network = ipaddress.ip_network(range_str)
            if ip in network:
                return True

        return False
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {ip_str}") from e


def validate_url_safety(url: str) -> None:
    """
    Validate that a URL is safe to fetch (SSRF protection).

    Checks:
    1. URL is properly formatted
    2. Hostname doesn't resolve to private IP addresses
    3. Hostname is not localhost or similar

    Args:
        url: URL to validate

    Raises:
        InvalidURLError: If URL is invalid or unsafe
    """
    try:
        parsed = urlparse(url)

        # Validate scheme
        if parsed.scheme not in ("http", "https"):
            raise InvalidURLError(f"Invalid URL scheme: {parsed.scheme}. Only http and https are supported.")

        # Validate hostname exists
        if not parsed.hostname:
            raise InvalidURLError("URL must contain a hostname")

        hostname = parsed.hostname.lower()

        # Check for localhost names
        if hostname in LOCALHOST_NAMES:
            raise InvalidURLError(f"Cannot fetch from localhost: {hostname}")

        # Resolve hostname to IP and check if it's private
        try:
            # Get all IP addresses for this hostname
            addr_info = socket.getaddrinfo(hostname, None)

            for info in addr_info:
                ip_str = info[4][0]

                # Check if this IP is in a private range
                if is_private_ip(ip_str):
                    raise InvalidURLError(
                        f"URL resolves to private IP address {ip_str}. "
                        f"Fetching from private networks is not allowed (SSRF protection)."
                    )

        except socket.gaierror as e:
            raise InvalidURLError(f"Failed to resolve hostname {hostname}: {e}")

    except ValueError as e:
        raise InvalidURLError(f"Malformed URL: {e}")


def fetch_headers(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    user_agent: Optional[str] = None,
) -> Dict[str, str]:
    """
    Fetch HTTP headers from a URL using HEAD request.

    Args:
        url: Target URL (will be normalized if no protocol specified)
        timeout: Request timeout in seconds
        follow_redirects: Whether to follow HTTP redirects
        max_redirects: Maximum number of redirects to follow
        user_agent: Custom User-Agent string (uses default if None)

    Returns:
        Dictionary of headers with lowercase keys
        Example: {"strict-transport-security": "max-age=31536000", ...}

    Raises:
        InvalidURLError: If URL is invalid or unsafe (SSRF)
        NetworkError: If network request fails
        HTTPError: If server returns error status code (4xx, 5xx)

    Notes:
        - All header names are converted to lowercase for consistency
        - Uses HEAD request for efficiency (no body download)
        - Even on HTTPError, headers may still be available in the exception
    """
    # Normalize URL (add https:// if needed)
    url = normalize_url(url)

    # SSRF Protection: Validate URL is safe to fetch
    validate_url_safety(url)

    # Prepare request headers
    headers = {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
    }

    try:
        # Create session to configure max_redirects
        session = requests.Session()
        session.max_redirects = max_redirects

        # Make HEAD request to fetch only headers
        response = session.head(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=follow_redirects,
        )

        # Check for HTTP errors
        if response.status_code >= 400:
            # Still return headers even on error, but raise exception
            normalized_headers = {k.lower(): v for k, v in response.headers.items()}
            raise HTTPError(
                f"HTTP {response.status_code} error for {url}",
                status_code=response.status_code,
                headers=normalized_headers,
            )

        # Normalize header names to lowercase for consistent access
        normalized_headers = {k.lower(): v for k, v in response.headers.items()}

        return normalized_headers

    except requests.exceptions.Timeout as e:
        raise NetworkError(f"Request timed out after {timeout} seconds: {url}") from e

    except requests.exceptions.TooManyRedirects as e:
        raise NetworkError(
            f"Too many redirects (max: {max_redirects}) while fetching {url}"
        ) from e

    except requests.exceptions.ConnectionError as e:
        raise NetworkError(f"Failed to connect to {url}: {e}") from e

    except requests.exceptions.SSLError as e:
        raise NetworkError(f"SSL/TLS error for {url}: {e}") from e

    except requests.exceptions.RequestException as e:
        raise NetworkError(f"Request failed for {url}: {e}") from e


def fetch_headers_safe(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    user_agent: Optional[str] = None,
) -> tuple[Dict[str, str], Optional[Exception]]:
    """
    Safely fetch headers without raising exceptions.

    This is a wrapper around fetch_headers() that returns errors instead
    of raising them. Useful for batch processing or when you want to
    handle errors differently.

    Args:
        Same as fetch_headers()

    Returns:
        Tuple of (headers_dict, error)
        - If successful: (headers, None)
        - If failed: ({}, error_exception)

    Examples:
        >>> headers, error = fetch_headers_safe("https://example.com")
        >>> if error:
        ...     print(f"Failed: {error}")
        ... else:
        ...     print(f"Got {len(headers)} headers")
    """
    try:
        headers = fetch_headers(
            url=url,
            timeout=timeout,
            follow_redirects=follow_redirects,
            max_redirects=max_redirects,
            user_agent=user_agent,
        )
        return headers, None

    except (InvalidURLError, NetworkError, HTTPError) as e:
        # For HTTPError, still return the headers if available
        if isinstance(e, HTTPError) and e.headers:
            return e.headers, e
        return {}, e


# Utility functions for testing and debugging

def get_final_url(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
) -> str:
    """
    Get the final URL after following redirects.

    Useful for debugging or understanding redirect chains.

    Args:
        url: Starting URL
        timeout: Request timeout
        max_redirects: Maximum redirects to follow

    Returns:
        Final URL after redirects

    Raises:
        Same exceptions as fetch_headers()
    """
    url = normalize_url(url)
    validate_url_safety(url)

    try:
        session = requests.Session()
        session.max_redirects = max_redirects

        response = session.head(
            url,
            timeout=timeout,
            allow_redirects=True,
        )
        return response.url

    except requests.exceptions.RequestException as e:
        raise NetworkError(f"Failed to get final URL for {url}: {e}") from e
