"""
Permissions-Policy Header Analyzer.

This module contains configuration and analysis logic for the
Permissions-Policy header (formerly Feature-Policy) which controls
browser features and APIs.
"""

from typing import Dict, Optional, Any

from ..config import STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING


HEADER_KEY = "permissions-policy"

CONFIG = {
    "display_name": "Permissions-Policy",
    "severity_missing": "high",
    "description": "Controls which browser features and APIs can be used",
    "validation": {
        # Sensitive features that should be restricted
        "sensitive_features": [
            "camera",
            "microphone",
            "geolocation",
            "payment",
            "usb",
            "serial",
            "bluetooth",
        ],
        # Good restriction patterns
        "restrictive_values": ["()", "self"],
    },
    "messages": {
        STATUS_GOOD: "Permissions-Policy is properly configured with restrictive settings",
        STATUS_ACCEPTABLE: "Permissions-Policy is present with some restrictions",
        STATUS_BAD: "Permissions-Policy allows potentially dangerous features without restrictions",
        STATUS_MISSING: "Permissions-Policy header is missing - browser features are not restricted",
    },
    "recommendations": {
        "missing": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
        "too_permissive": "Restrict sensitive features like camera, microphone, and geolocation to specific origins or deny with ()",
        "example": "Example: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    },
}


def parse_permissions_policy(value: str) -> Dict[str, str]:
    """
    Parse Permissions-Policy header into feature directives.

    Args:
        value: Permissions-Policy header value

    Returns:
        Dictionary mapping feature names to their allowlist values

    Example:
        >>> parse_permissions_policy("camera=(), microphone=(self)")
        {"camera": "()", "microphone": "(self)"}

        >>> parse_permissions_policy("geolocation=(self 'https://example.com')")
        {"geolocation": "(self 'https://example.com')"}
    """
    features = {}

    # Split by comma to get individual feature directives
    for directive_str in value.split(','):
        directive_str = directive_str.strip()
        if not directive_str:
            continue

        # Split into feature name and allowlist
        if '=' in directive_str:
            parts = directive_str.split('=', 1)
            feature_name = parts[0].strip().lower()
            allowlist = parts[1].strip() if len(parts) > 1 else ""
            features[feature_name] = allowlist

    return features


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Permissions-Policy header.

    Validation rules:
    - Missing: High severity (modern feature, important for privacy)
    - Restricts sensitive features with () or self: Good
    - Has some restrictions: Acceptable
    - Allows sensitive features with *: Bad

    Args:
        value: Header value or None if missing

    Returns:
        Finding dictionary with keys:
        - header_name: str
        - status: str (good/acceptable/bad/missing)
        - severity: str (critical/high/medium/low/info)
        - message: str
        - actual_value: str or None
        - recommendation: str or None
    """
    header_name = CONFIG["display_name"]

    # Missing header
    if value is None:
        return {
            "header_name": header_name,
            "status": STATUS_MISSING,
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"][STATUS_MISSING],
            "actual_value": None,
            "recommendation": CONFIG["recommendations"]["missing"],
        }

    # Parse the policy
    features = parse_permissions_policy(value)

    if not features:
        # Policy is present but empty
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": "medium",
            "message": "Permissions-Policy is present but contains no directives",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["missing"],
        }

    # Check if sensitive features are restricted
    sensitive_features = CONFIG["validation"]["sensitive_features"]
    restrictive_values = CONFIG["validation"]["restrictive_values"]

    restricted_count = 0
    unrestricted_sensitive = []

    for feature in sensitive_features:
        if feature in features:
            allowlist = features[feature]
            # Check if it's restrictive (empty list or self only)
            if any(restrictive in allowlist for restrictive in restrictive_values):
                restricted_count += 1
            elif "*" in allowlist:
                unrestricted_sensitive.append(feature)
        # Feature not mentioned means it inherits default (usually allowed)

    # Evaluate the policy
    if restricted_count >= 3 and not unrestricted_sensitive:
        # Good: At least 3 sensitive features restricted, none unrestricted
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }
    elif unrestricted_sensitive:
        # Bad: Some sensitive features explicitly allowed with wildcard
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": "high",
            "message": f"{CONFIG['messages'][STATUS_BAD]}: {', '.join(unrestricted_sensitive)} allowed with wildcard",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["too_permissive"],
        }
    elif restricted_count > 0:
        # Acceptable: Some restrictions in place
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": "Consider adding more restrictive policies for additional sensitive features",
        }
    else:
        # Has directives but doesn't restrict sensitive features
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "medium",
            "message": "Permissions-Policy is present but doesn't restrict sensitive features",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["too_permissive"],
        }
