"""
Analyzer Registry - Dynamic analyzer registration and dispatch

Module: sha.analyzers

Purpose:
    Implements the registry pattern for dynamically dispatching header values to
    appropriate analyzer functions. Maintains ANALYZER_REGISTRY and CONFIG_REGISTRY
    dictionaries that map header keys to their analysis functions and configurations.

Overview:
    This module is the central nervous system of the analyzer architecture. It imports
    all 15 individual analyzer modules (hsts, csp, xframe, etc.) and builds two
    registries: ANALYZER_REGISTRY (maps header_key → analyze function) and
    CONFIG_REGISTRY (maps header_key → CONFIG dict). The main analyzer.py module
    loops through these registries to analyze all headers without knowing specific
    header details.

Key Components:
    - ANALYZER_REGISTRY: Dict[str, Callable]
      Maps header keys (e.g., "strict-transport-security") to analyzer functions
      (e.g., hsts.analyze). Used by analyze_headers() to dispatch analysis.

    - CONFIG_REGISTRY: Dict[str, Dict[str, Any]]
      Maps header keys to their CONFIG dictionaries containing validation rules,
      status messages, and display metadata.

    - get_all_header_keys() -> List[str]
      Returns list of all registered header keys (15 total)

    - get_analyzer(header_key) -> Callable
      Retrieves analyzer function for a specific header

    - get_config(header_key) -> Dict
      Retrieves configuration dictionary for a specific header

Registry Pattern Benefits:
    1. **Extensibility**: Add new analyzers by creating a module and adding to registry
    2. **Decoupling**: analyzer.py doesn't need to import or know about specific headers
    3. **Consistency**: All analyzers follow the same interface (analyze(value) -> Finding)
    4. **Maintainability**: Header-specific logic lives in isolated modules
    5. **Testability**: Each analyzer can be tested independently

Registered Analyzers (15 total):
    Priority 1 (Critical):
    - strict-transport-security (HSTS)
    - content-security-policy (CSP)

    Priority 2 (High):
    - x-frame-options
    - referrer-policy
    - x-content-type-options
    - set-cookie
    - cache-control
    - expect-ct

    Priority 3 (Medium-Low):
    - x-permitted-cross-domain-policies
    - x-xss-protection (deprecated)
    - x-download-options
    - permissions-policy
    - cross-origin-embedder-policy (COEP)
    - cross-origin-opener-policy (COOP)
    - cross-origin-resource-policy (CORP)

Adding New Analyzers:
    1. Create analyzer module in sha/analyzers/ (e.g., new_header.py)
    2. Define HEADER_KEY, CONFIG, and analyze() function
    3. Import module in this file
    4. Add to ANALYZER_REGISTRY and CONFIG_REGISTRY dictionaries
    5. No changes needed to analyzer.py or main.py!

    See: docs/architecture/EXTENSIBILITY.md for step-by-step guide

Related Modules:
    - sha.analyzer - Loops through ANALYZER_REGISTRY to analyze all headers
    - sha.analyzers.* - Individual analyzer modules (hsts, csp, etc.)
    - sha.config - get_header_config() delegates to get_config() here

Example Usage:
    >>> from sha.analyzers import ANALYZER_REGISTRY, get_all_header_keys
    >>> len(ANALYZER_REGISTRY)
    15
    >>> get_all_header_keys()
    ['strict-transport-security', 'x-frame-options', ...]

    >>> # Get analyzer for specific header
    >>> from sha.analyzers import get_analyzer
    >>> analyze_hsts = get_analyzer("strict-transport-security")
    >>> finding = analyze_hsts("max-age=31536000")
    >>> finding["status"]
    "acceptable"

See Also:
    - docs/architecture/REGISTRY_PATTERN.md - Registry pattern explained
    - docs/architecture/EXTENSIBILITY.md - Adding new analyzers
    - docs/architecture/COMPONENTS.md#analyzer-layer - Architecture overview
"""

from typing import Any, Callable, Dict

# Import all analyzer modules
from . import (
    cache_control,
    coep,
    content_type,
    coop,
    corp,
    csp,
    expect_ct,
    hsts,
    permissions_policy,
    referrer_policy,
    set_cookie,
    x_download_options,
    x_permitted_cross_domain_policies,
    x_xss_protection,
    xframe,
)

# Registry mapping header keys to analyzer functions
ANALYZER_REGISTRY: Dict[str, Callable] = {
    hsts.HEADER_KEY: hsts.analyze,
    xframe.HEADER_KEY: xframe.analyze,
    content_type.HEADER_KEY: content_type.analyze,
    csp.HEADER_KEY: csp.analyze,
    referrer_policy.HEADER_KEY: referrer_policy.analyze,
    permissions_policy.HEADER_KEY: permissions_policy.analyze,
    coep.HEADER_KEY: coep.analyze,
    coop.HEADER_KEY: coop.analyze,
    corp.HEADER_KEY: corp.analyze,
    set_cookie.HEADER_KEY: set_cookie.analyze,
    cache_control.HEADER_KEY: cache_control.analyze,
    expect_ct.HEADER_KEY: expect_ct.analyze,
    x_xss_protection.HEADER_KEY: x_xss_protection.analyze,
    x_download_options.HEADER_KEY: x_download_options.analyze,
    x_permitted_cross_domain_policies.HEADER_KEY: x_permitted_cross_domain_policies.analyze,
}

# Registry mapping header keys to configurations
CONFIG_REGISTRY: Dict[str, Dict[str, Any]] = {
    hsts.HEADER_KEY: hsts.CONFIG,
    xframe.HEADER_KEY: xframe.CONFIG,
    content_type.HEADER_KEY: content_type.CONFIG,
    csp.HEADER_KEY: csp.CONFIG,
    referrer_policy.HEADER_KEY: referrer_policy.CONFIG,
    permissions_policy.HEADER_KEY: permissions_policy.CONFIG,
    coep.HEADER_KEY: coep.CONFIG,
    coop.HEADER_KEY: coop.CONFIG,
    corp.HEADER_KEY: corp.CONFIG,
    set_cookie.HEADER_KEY: set_cookie.CONFIG,
    cache_control.HEADER_KEY: cache_control.CONFIG,
    expect_ct.HEADER_KEY: expect_ct.CONFIG,
    x_xss_protection.HEADER_KEY: x_xss_protection.CONFIG,
    x_download_options.HEADER_KEY: x_download_options.CONFIG,
    x_permitted_cross_domain_policies.HEADER_KEY: x_permitted_cross_domain_policies.CONFIG,
}


def get_all_header_keys():
    """Get list of all registered header keys."""
    return list(ANALYZER_REGISTRY.keys())


def get_analyzer(header_key: str) -> Callable:
    """
    Get analyzer function for a specific header.

    Args:
        header_key: The header key (lowercase with hyphens)

    Returns:
        The analyzer function

    Raises:
        KeyError: If header_key is not registered
    """
    return ANALYZER_REGISTRY[header_key]


def get_config(header_key: str) -> Dict[str, Any]:
    """
    Get configuration for a specific header.

    Args:
        header_key: The header key (lowercase with hyphens)

    Returns:
        The configuration dictionary

    Raises:
        KeyError: If header_key is not registered
    """
    return CONFIG_REGISTRY[header_key]


# Export for backward compatibility
__all__ = [
    "ANALYZER_REGISTRY",
    "CONFIG_REGISTRY",
    "get_all_header_keys",
    "get_analyzer",
    "get_config",
    # Direct exports from modules
    "hsts",
    "xframe",
    "content_type",
    "csp",
    "referrer_policy",
    "permissions_policy",
    "coep",
    "coop",
    "corp",
    "set_cookie",
    "cache_control",
    "expect_ct",
    "x_xss_protection",
    "x_download_options",
    "x_permitted_cross_domain_policies",
]
