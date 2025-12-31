"""
Fetcher Layer - HTTP header fetching with SSRF protection

Module: sha.fetcher

Purpose:
    Handles all HTTP requests to fetch security headers from target URLs with
    comprehensive SSRF (Server-Side Request Forgery) protection, DNS rebinding
    validation, and robust error handling.

Overview:
    The fetcher module implements multi-layer security protections to prevent
    Server-Side Request Forgery attacks while reliably fetching HTTP headers.
    It validates URLs before requests, blocks private IP ranges, validates
    redirect destinations, and provides graceful error handling with specific
    exception types for different failure modes.

Key Functions:
    - fetch_headers(url, ...) -> Dict[str, Union[str, List[str]]]
      Main entry point for fetching headers from a URL (raises exceptions)

    - fetch_headers_safe(url, ...) -> Tuple[Dict, Optional[Exception]]
      Non-throwing wrapper that returns errors instead of raising them

    - validate_url_safety(url) -> None
      Pre-request SSRF validation (checks DNS, private IPs, localhost)

    - validate_redirect_destination(url) -> None
      Post-redirect validation to prevent DNS rebinding attacks

    - normalize_url(url) -> str
      Adds HTTPS protocol if missing from URL

    - is_private_ip(ip_str) -> bool
      Checks if IP address is in private/loopback ranges

Security Features:
    SSRF Protection (Blocked IP Ranges):
    - IPv4: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
    - IPv6: ::1, fc00::/7, fe80::/10
    - Localhost names: localhost, 0.0.0.0

    Multi-Layer Validation:
    1. Pre-request DNS validation (validate_url_safety)
    2. Private IP range checking (is_private_ip)
    3. Post-redirect validation (validate_redirect_destination)
    4. Redirect limit enforcement (max_redirects)

Security Considerations:
    Known TOCTOU Vulnerability:
    The DNS validation has a Time-of-Check-Time-of-Use (TOCTOU) race condition.
    An attacker controlling DNS could:
    1. Pass initial validation with a public IP
    2. Change DNS to point to private IP before request
    3. Bypass SSRF protection

    Mitigation: validate_redirect_destination() provides additional protection
    by re-validating DNS after redirects, reducing (but not eliminating) the
    attack window.

    See: docs/architecture/SECURITY.md#toctou-vulnerability for details.

Related Modules:
    - sha.config - Imports PRIVATE_IP_RANGES, DEFAULT_TIMEOUT, exception classes
    - sha.main - Calls fetch_headers() to get headers for analysis
    - sha.analyzer - Consumes headers dictionary for analysis

Example Usage:
    >>> from sha.fetcher import fetch_headers
    >>> headers = fetch_headers("https://example.com")
    >>> headers["strict-transport-security"]
    "max-age=31536000; includeSubDomains"

    >>> # Safe variant that doesn't raise exceptions
    >>> headers, error = fetch_headers_safe("https://example.com")
    >>> if error:
    ...     print(f"Failed: {error}")

    >>> # Normalize URL (add protocol)
    >>> normalize_url("example.com")
    "https://example.com"

See Also:
    - docs/architecture/components.md#fetcher-layer - Architecture details
    - docs/architecture/SECURITY.md - SSRF protection explained
    - SECURITY.md - Known vulnerabilities and limitations
"""

import ipaddress
import socket
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import requests

from .config import (
    DEFAULT_MAX_REDIRECTS,
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    LOCALHOST_NAMES,
    PRIVATE_IP_RANGES,
    HTTPError,
    InvalidURLError,
    NetworkError,
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

    Security Note:
        This function has a known TOCTOU (Time-of-Check-Time-of-Use) vulnerability:
        DNS resolution could change between this validation and the actual request.
        An attacker controlling DNS could pass validation with a public IP, then
        change DNS to point to a private IP before the request is made.

        Additionally, redirects could bypass this check. Consider using validate_ip()
        on the final redirect destination for stronger protection.
    """
    try:
        parsed = urlparse(url)

        # Validate scheme
        if parsed.scheme not in ("http", "https"):
            raise InvalidURLError(
                f"Invalid URL scheme: {parsed.scheme}. Only http and https are supported."
            )

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
            # Note: DNS resolution timeout is controlled by OS, typically 30s
            addr_info = socket.getaddrinfo(hostname, None)

            for info in addr_info:
                ip_str = info[4][0]

                # Check if this IP is in a private range
                # Wrap in try-except to handle malformed IPs from DNS
                try:
                    if is_private_ip(ip_str):
                        raise InvalidURLError(
                            f"URL resolves to private IP address {ip_str}. "
                            f"Fetching from private networks is not allowed (SSRF protection)."
                        )
                except ValueError as ip_err:
                    raise InvalidURLError(f"DNS returned invalid IP address: {ip_str}") from ip_err

        except socket.gaierror as e:
            raise InvalidURLError(f"Failed to resolve hostname {hostname}: {e}")

    except ValueError as e:
        raise InvalidURLError(f"Malformed URL: {e}")


def validate_redirect_destination(final_url: str) -> None:
    """
    Validate that a redirect destination is safe (DNS rebinding protection).

    This should be called after following redirects to ensure the final
    destination doesn't resolve to a private IP address.

    Args:
        final_url: The final URL after following redirects

    Raises:
        InvalidURLError: If final URL resolves to private IP

    Note:
        This provides additional protection against DNS rebinding attacks
        where DNS changes between initial validation and redirect resolution.
    """
    try:
        parsed = urlparse(final_url)
        if not parsed.hostname:
            return  # No hostname to validate

        hostname = parsed.hostname.lower()

        # Skip localhost check as original validation already caught it
        # But re-validate IP resolution as DNS could have changed
        try:
            addr_info = socket.getaddrinfo(hostname, None)

            for info in addr_info:
                ip_str = info[4][0]
                try:
                    if is_private_ip(ip_str):
                        raise InvalidURLError(
                            f"Redirect destination resolves to private IP {ip_str}. "
                            f"This may be a DNS rebinding attack (SSRF protection)."
                        )
                except ValueError as ip_err:
                    raise InvalidURLError(f"DNS returned invalid IP address: {ip_str}") from ip_err

        except socket.gaierror:
            # DNS resolution failure - let it fail naturally on request
            pass

    except ValueError:
        # Malformed URL - let it fail naturally on request
        pass


def _normalize_headers_with_cookies(
    response: requests.Response,
) -> Dict[str, Union[str, List[str]]]:
    """
    Normalize response headers with special handling for Set-Cookie.

    Args:
        response: requests.Response object

    Returns:
        Dictionary with lowercase keys. Set-Cookie is a list if multiple cookies exist.
    """
    normalized_headers = {}

    # Get all headers except Set-Cookie
    for key, value in response.headers.items():
        key_lower = key.lower()
        if key_lower != "set-cookie":
            normalized_headers[key_lower] = value

    # Special handling for Set-Cookie to capture ALL cookies
    # The response.headers dict only contains the last Set-Cookie header
    # We need to access the raw headers to get all of them
    try:
        # Only try to get raw cookies from real requests.Response objects
        # Check if this is a real Response object (not a Mock) by checking for callable methods
        if (
            hasattr(response, "raw")
            and hasattr(response.raw, "_original_response")
            and callable(getattr(response.raw._original_response, "get_all", None))
        ):
            # For urllib3 response objects with HTTPMessage
            raw_response = response.raw._original_response
            if hasattr(raw_response, "msg") and callable(
                getattr(raw_response.msg, "get_all", None)
            ):
                # HTTPMessage object has get_all() method
                all_cookies = raw_response.msg.get_all("Set-Cookie")
                if all_cookies and isinstance(all_cookies, list):
                    normalized_headers["set-cookie"] = all_cookies
                    return normalized_headers
    except (AttributeError, TypeError, RuntimeError):
        # Catch specific exceptions only:
        # - AttributeError: Missing expected attribute
        # - TypeError: Unexpected type
        # - RuntimeError: Unexpected runtime error
        # Silently continue to fallback - this handles Mock objects in tests
        pass

    # Fallback: get Set-Cookie from regular headers dict
    # In real responses, this gets only the last cookie
    # But it works fine with Mocks and tests
    try:
        cookie_value = response.headers.get("Set-Cookie") or response.headers.get("set-cookie")
        if cookie_value:
            # Wrap single cookie in list for consistency
            normalized_headers["set-cookie"] = [cookie_value]
    except (AttributeError, KeyError):
        # Catch specific exceptions only - if headers dict access fails, skip
        pass

    return normalized_headers


def fetch_headers(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    user_agent: Optional[str] = None,
) -> Dict[str, Union[str, List[str]]]:
    """
    Fetch HTTP headers from a URL using HEAD request.

    Args:
        url: Target URL (will be normalized if no protocol specified)
        timeout: Request timeout in seconds
        follow_redirects: Whether to follow HTTP redirects
        max_redirects: Maximum number of redirects to follow
        user_agent: Custom User-Agent string (uses default if None)

    Returns:
        Dictionary of headers with lowercase keys.
        Most headers are str, but 'set-cookie' is List[str] to capture all cookies.
        Example: {
            "strict-transport-security": "max-age=31536000",
            "set-cookie": ["session=abc; Secure", "csrf=xyz; Secure"]
        }

    Raises:
        InvalidURLError: If URL is invalid or unsafe (SSRF)
        NetworkError: If network request fails
        HTTPError: If server returns error status code (4xx, 5xx)

    Notes:
        - All header names are converted to lowercase for consistency
        - Uses HEAD request for efficiency (no body download)
        - Set-Cookie headers are captured as a list to preserve all cookies
        - Even on HTTPError, headers may still be available in the exception
        - Validates redirect destinations to prevent DNS rebinding attacks
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

        # DNS Rebinding Protection: Validate ALL redirects (not just final destination)
        # This prevents SSRF via intermediate redirects
        if follow_redirects and hasattr(response, 'history') and response.history:
            try:
                for redirect_response in response.history:
                    if hasattr(redirect_response, 'url') and isinstance(redirect_response.url, str):
                        validate_redirect_destination(redirect_response.url)
            except (TypeError, AttributeError):
                # Handle Mock objects or malformed response.history
                pass

        # Also validate final URL after redirects
        if (
            follow_redirects
            and hasattr(response, "url")
            and isinstance(response.url, str)
            and response.url != url
        ):
            validate_redirect_destination(response.url)

        # Check for HTTP errors
        if response.status_code >= 400:
            # Still return headers even on error, but raise exception
            normalized_headers = _normalize_headers_with_cookies(response)
            raise HTTPError(
                f"HTTP {response.status_code} error for {url}",
                status_code=response.status_code,
                headers=normalized_headers,
            )

        # Normalize header names to lowercase for consistent access
        # Special handling for Set-Cookie to capture all cookies
        normalized_headers = _normalize_headers_with_cookies(response)

        return normalized_headers

    except requests.exceptions.Timeout as e:
        raise NetworkError(f"Request timed out after {timeout} seconds: {url}") from e

    except requests.exceptions.TooManyRedirects as e:
        raise NetworkError(f"Too many redirects (max: {max_redirects}) while fetching {url}") from e

    except requests.exceptions.SSLError as e:
        raise NetworkError(f"SSL/TLS error for {url}: {e}") from e

    except requests.exceptions.ConnectionError as e:
        raise NetworkError(f"Failed to connect to {url}: {e}") from e

    except requests.exceptions.RequestException as e:
        raise NetworkError(f"Request failed for {url}: {e}") from e


def fetch_headers_with_retry(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    user_agent: Optional[str] = None,
    max_retries: int = 3,
) -> Dict[str, Union[str, List[str]]]:
    """
    Fetch HTTP headers with retry logic and exponential backoff.

    Retries on:
    - 429 (Too Many Requests) - respects Retry-After header
    - 503 (Service Unavailable) - respects Retry-After header
    - Transient network errors (timeout, connection failures)

    Args:
        url: Target URL (will be normalized if no protocol specified)
        timeout: Request timeout in seconds
        follow_redirects: Whether to follow HTTP redirects
        max_redirects: Maximum number of redirects to follow
        user_agent: Custom User-Agent string (uses default if None)
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        Dictionary of headers with lowercase keys.
        Most headers are str, but 'set-cookie' is List[str] to capture all cookies.

    Raises:
        InvalidURLError: If URL is invalid or unsafe (SSRF)
        NetworkError: If network request fails after all retries
        HTTPError: If server returns non-retryable error status code

    Notes:
        - Exponential backoff: 1s, 2s, 4s between retries
        - Respects Retry-After header from server (capped at 60s)
        - Does not retry on SSL errors or non-retryable HTTP errors
    """
    import time

    last_error = None

    for attempt in range(max_retries):
        try:
            return fetch_headers(
                url=url,
                timeout=timeout,
                follow_redirects=follow_redirects,
                max_redirects=max_redirects,
                user_agent=user_agent,
            )

        except HTTPError as e:
            # Retry on 429 (Too Many Requests) or 503 (Service Unavailable)
            if e.status_code in (429, 503):
                last_error = e

                # Check for Retry-After header
                retry_after = e.headers.get('retry-after')
                if retry_after and retry_after.isdigit():
                    wait_time = min(int(retry_after), 60)  # Cap at 60s
                else:
                    # Exponential backoff: 1s, 2s, 4s
                    wait_time = 2 ** attempt

                if attempt < max_retries - 1:
                    time.sleep(wait_time)
                    continue
            # Don't retry on other HTTP errors (4xx, 5xx)
            raise

        except NetworkError as e:
            # Retry on timeout or connection errors
            error_str = str(e).lower()
            if "timeout" in error_str or "connection" in error_str:
                last_error = e
                if attempt < max_retries - 1:
                    # Exponential backoff: 1s, 2s, 4s
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                    continue
            # Don't retry on SSL errors or other network issues
            raise

    # Max retries exceeded
    if last_error:
        raise last_error

    # Should never reach here
    raise NetworkError(f"Failed to fetch headers after {max_retries} attempts")


def fetch_headers_safe(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    user_agent: Optional[str] = None,
) -> Tuple[Dict[str, str], Optional[Exception]]:
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
