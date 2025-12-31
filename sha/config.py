"""
Configuration Module - Shared constants and exceptions

Module: sha.config

Purpose:
    Centralizes all configuration constants and custom exception classes used
    throughout the Security Header Analyzer. This includes HTTP request settings,
    SSRF protection IP ranges, severity levels, status constants, and the exception
    hierarchy for error handling.

Overview:
    This module serves as the single source of truth for configuration values that
    are shared across multiple modules. Individual header-specific configurations
    (validation rules, messages) live in their respective analyzer modules, while
    global system configuration lives here. The exception hierarchy provides
    structured error handling with appropriate exit code mapping in main.py.

Key Constants:
    HTTP Configuration:
    - DEFAULT_TIMEOUT: int = 10 seconds
    - DEFAULT_MAX_REDIRECTS: int = 5
    - DEFAULT_USER_AGENT: str (includes version and repo URL)

    SSRF Protection:
    - PRIVATE_IP_RANGES: List[str] (IPv4 and IPv6 private/loopback ranges)
    - LOCALHOST_NAMES: Set[str] (localhost, 0.0.0.0)

    Severity System:
    - SEVERITY_LEVELS: List[str] (ordered: critical → high → medium → low → info)
    - SEVERITY_RANK: Dict[str, int] (for sorting findings)

    Status Constants:
    - STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING

Exception Classes:
    - SecurityHeaderAnalyzerError (base class)
      ├── NetworkError (timeout, connection, SSL) → exit code 1
      ├── InvalidURLError (malformed URL, SSRF) → exit code 2
      └── HTTPError (4xx, 5xx responses) → exit code 3

Security Considerations:
    SSRF Protection IP Ranges:
    - 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (IPv4 private)
    - 169.254.0.0/16 (link-local, AWS metadata endpoint)
    - ::1/128, fc00::/7, fe80::/10 (IPv6 loopback/private/link-local)

Related Modules:
    - sha.fetcher - Uses HTTP config and SSRF protection constants
    - sha.main - Uses exception classes for error handling and exit codes
    - sha.analyzer - Uses severity levels and status constants
    - sha.analyzers.* - Use status constants in their CONFIG dictionaries

Example Usage:
    >>> from sha.config import DEFAULT_TIMEOUT, PRIVATE_IP_RANGES
    >>> print(DEFAULT_TIMEOUT)
    10
    >>> len(PRIVATE_IP_RANGES)
    8

    >>> from sha.config import NetworkError
    >>> raise NetworkError("Connection timeout")

See Also:
    - docs/architecture/components.md#configuration-module - Architecture details
    - docs/architecture/SECURITY.md#ssrf-protection - SSRF protection explained
    - SECURITY.md - Security considerations and known limitations
"""

from typing import Any, Dict, List

# Version information (imported from __init__.py at runtime)
VERSION = "1.0.0"

# HTTP Request Configuration
DEFAULT_TIMEOUT = 10  # seconds
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_USER_AGENT = (
    f"SecurityHeaderAnalyzer/{VERSION} (https://github.com/ThodorhsPerros/security-header-analyzer)"
)

# Private IP ranges for SSRF protection
PRIVATE_IP_RANGES = [
    "127.0.0.0/8",  # Loopback
    "10.0.0.0/8",  # Private network
    "172.16.0.0/12",  # Private network
    "192.168.0.0/16",  # Private network
    "169.254.0.0/16",  # Link-local
    "::1/128",  # IPv6 loopback
    "fc00::/7",  # IPv6 private
    "fe80::/10",  # IPv6 link-local
]

LOCALHOST_NAMES = ["localhost", "0.0.0.0"]

# Severity levels in order of importance
SEVERITY_LEVELS = ["critical", "high", "medium-high", "medium", "low", "info"]

# Status types for header evaluation
STATUS_GOOD = "good"
STATUS_ACCEPTABLE = "acceptable"
STATUS_BAD = "bad"
STATUS_MISSING = "missing"


# Custom Exception Classes


class SecurityHeaderAnalyzerError(Exception):
    """Base exception for all Security Header Analyzer errors."""

    pass


class NetworkError(SecurityHeaderAnalyzerError):
    """
    Raised when network-related errors occur.

    This includes:
    - Connection failures
    - DNS resolution failures
    - Timeouts
    - Too many redirects
    - SSL/TLS errors
    """

    pass


class InvalidURLError(SecurityHeaderAnalyzerError):
    """
    Raised when the provided URL is invalid or malformed.

    This includes:
    - Malformed URL syntax
    - Missing or invalid components
    - URLs targeting private IP addresses (SSRF protection)
    """

    pass


class HTTPError(SecurityHeaderAnalyzerError):
    """
    Raised when HTTP request returns an error status code.

    This includes:
    - 4xx client errors
    - 5xx server errors

    Note: The analyzer may still attempt to analyze headers even
    when this error occurs, as security headers may be present
    in error responses.
    """

    def __init__(self, message: str, status_code: int = None, headers: Dict = None):
        """
        Initialize HTTPError with additional context.

        Args:
            message: Error message
            status_code: HTTP status code
            headers: Response headers (if available)
        """
        super().__init__(message)
        self.status_code = status_code
        self.headers = headers or {}


# Utility functions for backward compatibility with old config structure
# These now delegate to the analyzer registry


def get_header_config(header_name: str) -> Dict[str, Any]:
    """
    Get configuration for a specific header.

    Args:
        header_name: Header name (case-insensitive)

    Returns:
        Header configuration dictionary

    Raises:
        KeyError: If header name is not found in configuration
    """
    from .analyzers import get_config

    return get_config(header_name.lower())


def get_all_header_names() -> List[str]:
    """
    Get list of all configured security header names (lowercase).

    Returns:
        List of header names
    """
    from .analyzers import get_all_header_keys

    return get_all_header_keys()


def get_severity_rank(severity: str) -> int:
    """
    Get numeric rank for severity level (lower is more severe).

    Args:
        severity: Severity level string

    Returns:
        Numeric rank (0 = most severe)

    Raises:
        ValueError: If severity level is not recognized
    """
    try:
        return SEVERITY_LEVELS.index(severity.lower())
    except ValueError:
        raise ValueError(f"Unknown severity level: {severity}")


def is_valid_severity(severity: str) -> bool:
    """
    Check if a severity level is valid.

    Args:
        severity: Severity level string

    Returns:
        True if valid, False otherwise
    """
    return severity.lower() in SEVERITY_LEVELS


# Backward compatibility: SECURITY_HEADERS dict
# This uses a custom __getattr__ at module level (Python 3.7+)
# to lazily load from analyzer configs when accessed
def __getattr__(name):
    if name == "SECURITY_HEADERS":
        from .analyzers import CONFIG_REGISTRY

        return CONFIG_REGISTRY
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
