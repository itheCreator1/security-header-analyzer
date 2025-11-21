"""
Security Header Analyzers Registry.

This module provides a registry of all available header analyzers
and exports them for use by the main analyzer module.
"""

from typing import Dict, Callable, Any

# Import all analyzer modules
from . import hsts
from . import xframe
from . import content_type
from . import csp
from . import referrer_policy
from . import permissions_policy
from . import coep
from . import coop
from . import corp


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
]
