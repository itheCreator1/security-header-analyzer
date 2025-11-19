"""
Configuration module for Security Header Analyzer.

This module defines security header standards, validation rules, and constants
used throughout the application. Based on industry best practices and OWASP
recommendations.
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

# Security Header Standards
# Based on SecurityHeadersBestPractices.md and OWASP recommendations
SECURITY_HEADERS: Dict[str, Dict[str, Any]] = {
    "strict-transport-security": {
        "display_name": "Strict-Transport-Security",
        "severity_missing": "critical",
        "description": "Enforces HTTPS connections to prevent man-in-the-middle attacks",
        "validation": {
            # Minimum max-age: 126 days (10886400 seconds)
            "min_max_age": 10886400,
            # Best practice max-age: 1 year (31536000 seconds)
            "best_max_age": 31536000,
            # Required directives for best practice
            "required_directives": ["includesubdomains"],
            # Optional but recommended directives
            "recommended_directives": ["preload"],
        },
        "messages": {
            STATUS_GOOD: "HSTS is properly configured with strong security settings",
            STATUS_ACCEPTABLE: "HSTS is present but could be improved",
            STATUS_BAD: "HSTS is present but improperly configured",
            STATUS_MISSING: "HSTS header is missing - connections vulnerable to downgrade attacks",
        },
        "recommendations": {
            "missing": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "low_max_age": "Increase max-age to at least 10886400 (126 days), preferably 31536000 (1 year)",
            "no_subdomains": "Add includeSubDomains directive to protect all subdomains",
            "no_preload": "Consider adding preload directive and submitting to HSTS preload list",
        },
    },

    "x-frame-options": {
        "display_name": "X-Frame-Options",
        "severity_missing": "high",
        "description": "Prevents clickjacking attacks by controlling iframe embedding",
        "validation": {
            "best_values": ["deny"],
            "acceptable_values": ["sameorigin"],
            "deprecated_values": ["allow-from"],
        },
        "messages": {
            STATUS_GOOD: "X-Frame-Options is properly configured to prevent clickjacking",
            STATUS_ACCEPTABLE: "X-Frame-Options allows same-origin framing (acceptable for most use cases)",
            STATUS_BAD: "X-Frame-Options is using deprecated or insecure configuration",
            STATUS_MISSING: "X-Frame-Options header is missing - site vulnerable to clickjacking attacks",
        },
        "recommendations": {
            "missing": "Add: X-Frame-Options: DENY (or SAMEORIGIN if iframe embedding is needed)",
            "allow_from": "Replace deprecated ALLOW-FROM with Content-Security-Policy frame-ancestors directive",
            "use_deny": "Consider using DENY instead of SAMEORIGIN for maximum protection",
        },
    },

    "x-content-type-options": {
        "display_name": "X-Content-Type-Options",
        "severity_missing": "medium-high",
        "description": "Prevents MIME-type sniffing attacks",
        "validation": {
            "required_value": "nosniff",
        },
        "messages": {
            STATUS_GOOD: "X-Content-Type-Options is properly configured",
            STATUS_ACCEPTABLE: "X-Content-Type-Options is properly configured",
            STATUS_BAD: "X-Content-Type-Options has incorrect value",
            STATUS_MISSING: "X-Content-Type-Options header is missing - browser may perform MIME-type sniffing",
        },
        "recommendations": {
            "missing": "Add: X-Content-Type-Options: nosniff",
            "wrong_value": "Set value to: nosniff",
        },
    },

    "content-security-policy": {
        "display_name": "Content-Security-Policy",
        "severity_missing": "critical",
        "description": "Prevents XSS and other injection attacks by controlling resource loading",
        "validation": {
            # Dangerous patterns that indicate insecure CSP
            "dangerous_patterns": {
                "unsafe_inline_script": {
                    "directives": ["script-src", "default-src"],
                    "values": ["'unsafe-inline'"],
                    "severity": "high",
                    "message": "CSP allows unsafe-inline for scripts, defeating XSS protection",
                },
                "unsafe_eval": {
                    "directives": ["script-src", "default-src"],
                    "values": ["'unsafe-eval'"],
                    "severity": "medium",
                    "message": "CSP allows unsafe-eval, which can enable some XSS attacks",
                },
                "wildcard_script": {
                    "directives": ["script-src"],
                    "values": ["*", "data:", "http:", "https:"],
                    "severity": "high",
                    "message": "CSP allows scripts from any source (wildcard)",
                },
                "wildcard_default": {
                    "directives": ["default-src"],
                    "values": ["*"],
                    "severity": "high",
                    "message": "CSP default-src is wildcard, allowing resources from any source",
                },
            },
            # Good patterns that indicate secure CSP
            "good_patterns": {
                "restrictive_default": ["'self'", "'none'"],
                "security_directives": ["frame-ancestors", "base-uri", "form-action"],
            },
        },
        "messages": {
            STATUS_GOOD: "CSP is properly configured with restrictive policy",
            STATUS_ACCEPTABLE: "CSP is present but could be more restrictive",
            STATUS_BAD: "CSP is present but contains dangerous directives",
            STATUS_MISSING: "CSP header is missing - site vulnerable to XSS and injection attacks",
        },
        "recommendations": {
            "missing": "Add a Content-Security-Policy header with restrictive directives",
            "unsafe_inline": "Remove 'unsafe-inline' from script-src and use nonces or hashes instead",
            "unsafe_eval": "Remove 'unsafe-eval' from script-src if possible",
            "too_permissive": "Restrict source lists to specific trusted domains instead of wildcards",
            "add_directives": "Consider adding security directives: frame-ancestors, base-uri, form-action",
            "example": "Example: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        },
    },
}


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


# Utility functions for config validation

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
    return SECURITY_HEADERS[header_name.lower()]


def get_all_header_names() -> List[str]:
    """
    Get list of all configured security header names (lowercase).

    Returns:
        List of header names
    """
    return list(SECURITY_HEADERS.keys())


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
