"""
Analyzer module for Security Header Analyzer.

This module provides the main analyze_headers function that coordinates
analysis across all registered security header analyzers.
"""

from typing import Dict, List, Any

from .analyzers import ANALYZER_REGISTRY, get_all_header_keys


# Type alias for finding result
Finding = Dict[str, Any]


def analyze_headers(headers: Dict[str, str]) -> List[Finding]:
    """
    Analyze all security headers and generate findings.

    Args:
        headers: Dictionary of HTTP headers (lowercase keys)

    Returns:
        List of findings, each containing:
        {
            "header_name": str,        # Display name
            "status": str,              # good/acceptable/bad/missing
            "severity": str,            # critical/high/medium/low/info
            "message": str,             # Detailed explanation
            "actual_value": str|None,  # Actual header value (if present)
            "recommendation": str|None # How to fix (if not good)
        }

    Example:
        >>> headers = {"strict-transport-security": "max-age=31536000"}
        >>> findings = analyze_headers(headers)
        >>> findings[0]["status"]
        "acceptable"
    """
    findings = []

    # Analyze each registered security header using the registry
    for header_key in get_all_header_keys():
        header_value = headers.get(header_key)

        # Get the analyzer function from the registry
        analyzer_func = ANALYZER_REGISTRY[header_key]

        # Run the analysis
        finding = analyzer_func(header_value)
        findings.append(finding)

    return findings


# Export backward-compatible functions from individual analyzers
# This allows existing test code to continue working
from .analyzers.hsts import analyze as analyze_hsts, parse_hsts
from .analyzers.xframe import analyze as analyze_xframe
from .analyzers.content_type import analyze as analyze_content_type_options
from .analyzers.csp import (
    analyze as analyze_csp,
    parse_csp,
    check_csp_dangerous_patterns,
    check_csp_restrictive_default,
    check_csp_security_directives,
    has_nonces_or_hashes,
    has_strict_dynamic,
)
from .analyzers.referrer_policy import analyze as analyze_referrer_policy


__all__ = [
    "analyze_headers",
    "Finding",
    # Backward compatibility exports
    "analyze_hsts",
    "analyze_xframe",
    "analyze_content_type_options",
    "analyze_csp",
    "analyze_referrer_policy",
    "parse_hsts",
    "parse_csp",
    "check_csp_dangerous_patterns",
    "check_csp_restrictive_default",
    "check_csp_security_directives",
    "has_nonces_or_hashes",
    "has_strict_dynamic",
]
