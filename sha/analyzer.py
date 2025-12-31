"""
Analyzer Layer - Coordinates header analysis across all registered analyzers

Module: sha.analyzer

Purpose:
    Provides the analyze_headers() function that orchestrates analysis across all
    registered security header analyzers using the registry pattern. This module
    acts as the central dispatcher that loops through all known headers and
    aggregates their findings.

Overview:
    The analyzer module implements the registry pattern to dynamically dispatch
    header values to appropriate analyzer functions. It maintains no header-specific
    logic itself - all validation rules live in individual analyzer modules under
    sha/analyzers/. This design makes the system highly extensible: adding a new
    header requires zero changes to this file.

Key Functions:
    - analyze_headers(headers: Dict) -> List[Finding]
      Main entry point that coordinates analysis across all registered analyzers.
      Loops through ANALYZER_REGISTRY, calls each analyzer, aggregates findings.

Data Structures:
    - Finding: Dict[str, Any]
      TypedDict-style dictionary containing: header_name, status, severity,
      message, actual_value, recommendation

Pattern Implementation:
    Uses ANALYZER_REGISTRY from sha.analyzers to dynamically dispatch:
    for header_key, analyze_func in ANALYZER_REGISTRY.items():
        value = headers.get(header_key)
        finding = analyze_func(value)  # Call registered analyzer
        findings.append(finding)

Related Modules:
    - sha.analyzers - Contains ANALYZER_REGISTRY and all analyzer implementations
    - sha.fetcher - Provides headers input for analysis
    - sha.reporter - Consumes findings output for report generation
    - sha.main - Orchestrates the overall workflow

Example Usage:
    >>> from sha.analyzer import analyze_headers
    >>> headers = {
    ...     "strict-transport-security": "max-age=31536000",
    ...     "x-frame-options": "DENY"
    ... }
    >>> findings = analyze_headers(headers)
    >>> len(findings)  # Returns findings for all 15 registered headers
    15
    >>> findings[0]["header_name"]
    'Strict-Transport-Security'

See Also:
    - docs/architecture/components.md#analyzer-layer - Architecture details
    - docs/architecture/REGISTRY_PATTERN.md - Registry pattern explained
    - docs/API.md#analyzer-module - API reference
"""

from typing import Any, Dict, List, Union

from .analyzers import ANALYZER_REGISTRY, get_all_header_keys

# Type alias for finding result
Finding = Dict[str, Any]


def analyze_headers(headers: Dict[str, Union[str, List[str]]]) -> List[Finding]:
    """
    Analyze all security headers and generate findings.

    Args:
        headers: Dictionary of HTTP headers (lowercase keys).
                 Most values are strings, but 'set-cookie' can be a list of strings.

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


from .analyzers.content_type import analyze as analyze_content_type_options
from .analyzers.csp import analyze as analyze_csp
from .analyzers.csp import (
    check_csp_dangerous_patterns,
    check_csp_restrictive_default,
    check_csp_security_directives,
    has_nonces_or_hashes,
    has_strict_dynamic,
    parse_csp,
)

# Export backward-compatible functions from individual analyzers
# This allows existing test code to continue working
from .analyzers.hsts import analyze as analyze_hsts
from .analyzers.hsts import parse_hsts
from .analyzers.referrer_policy import analyze as analyze_referrer_policy
from .analyzers.xframe import analyze as analyze_xframe

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
