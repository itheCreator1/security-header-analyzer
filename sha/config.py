"""
Configuration module for Security Header Analyzer.

This module defines shared constants and exceptions used throughout the application.
Individual header configurations have been moved to their respective analyzer modules.
"""

from typing import Dict, List, Any

# Version information (imported from __init__.py at runtime)
VERSION = "1.0.0"

# HTTP Request Configuration
DEFAULT_TIMEOUT = 10  # seconds
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_USER_AGENT = f"SecurityHeaderAnalyzer/{VERSION} (https://github.com/yourusername/security-header-analyzer)"

# Private IP ranges for SSRF protection
PRIVATE_IP_RANGES = [
    "127.0.0.0/8",      # Loopback
    "10.0.0.0/8",       # Private network
    "172.16.0.0/12",    # Private network
    "192.168.0.0/16",   # Private network
    "169.254.0.0/16",   # Link-local
    "::1/128",          # IPv6 loopback
    "fc00::/7",         # IPv6 private
    "fe80::/10",        # IPv6 link-local
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
