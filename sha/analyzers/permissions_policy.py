"""
Permissions-Policy Analyzer - Browser feature/API control

Module: sha.analyzers.permissions_policy

Purpose:
    Analyzes the Permissions-Policy header (formerly Feature-Policy) to control which
    browser features and APIs can be accessed. Validates restrictions on sensitive
    features (camera, microphone, geolocation, payment, USB, etc.) to prevent
    unauthorized access and reduce attack surface.

Overview:
    The Permissions-Policy analyzer parses comma-separated feature directives, validates
    restrictions on 7 sensitive features, and evaluates policy strictness. It checks for
    restrictive values (empty allowlist '()' or 'self' only) versus permissive wildcards.
    The analyzer recognizes that Permissions-Policy is crucial for privacy (camera,
    microphone, geolocation) and security (USB, serial, bluetooth access).

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that parses policy, counts restricted sensitive features,
      and determines overall security posture (good if >=3 restricted, bad if wildcards)

    - parse_permissions_policy(value) -> Dict[str, str]
      Parses Permissions-Policy into feature→allowlist mapping
      (e.g., {"camera": "()", "microphone": "(self)"})

Validation Rules:
    - Missing header: HIGH severity (modern feature, important for privacy)
    - Restricts >=3 sensitive features with ()/self, no wildcards: GOOD, info severity
    - Has sensitive features with * wildcard: BAD, HIGH severity
    - Some restrictions (1-2 features): ACCEPTABLE, low severity
    - No sensitive restrictions: ACCEPTABLE, medium severity

Attack Scenarios Prevented:
    - **Malicious Camera/Microphone Access**: Prevents embedded third-party iframes
      from accessing webcam/microphone without explicit permission (e.g., ad iframes
      recording users)
    - **Geolocation Tracking**: Blocks unauthorized location tracking by embedded
      content (tracking users without consent)
    - **USB/Bluetooth Device Access**: Prevents malicious scripts from accessing
      connected hardware devices (keyboards, security keys, printers)
    - **Payment Handler Hijacking**: Restricts which origins can register as payment
      handlers, preventing payment interception

Sensitive Features Tracked:
    - **camera**: Webcam access (privacy concern)
    - **microphone**: Audio recording (privacy/surveillance)
    - **geolocation**: User location tracking (privacy)
    - **payment**: Payment Request API (financial security)
    - **usb**: USB device access (security concern)
    - **serial**: Serial port access (hardware security)
    - **bluetooth**: Bluetooth device pairing (hardware security)

Policy Syntax:
    - feature=(): Deny to all origins (most restrictive)
    - feature=(self): Allow only same origin
    - feature=(self "https://example.com"): Allow self + specific origins
    - feature=*: Allow all origins (DANGEROUS - flagged as bad)

Configuration:
    - sensitive_features: 7 critical features to check (camera, mic, geo, payment, usb, serial, bluetooth)
    - restrictive_values: '()' or 'self' (good restriction patterns)

Related Modules:
    - sha.analyzers.__init__ - Registers analyzer in ANALYZER_REGISTRY
    - sha.config - Imports STATUS_* constants
    - docs/headers/Permissions-Policy.md - Detailed feature documentation

Example Usage:
    >>> from sha.analyzers.permissions_policy import analyze, parse_permissions_policy
    >>> # Good policy - restricts sensitive features
    >>> finding = analyze("camera=(), microphone=(), geolocation=(), payment=()")
    >>> finding["status"]
    "good"

    >>> # Parse policy
    >>> parsed = parse_permissions_policy("camera=(), microphone=(self)")
    >>> parsed["camera"]
    "()"

    >>> # Bad policy - wildcard allows all
    >>> finding = analyze("camera=*")
    >>> finding["status"]
    "bad"
    >>> finding["severity"]
    "high"

See Also:
    - docs/headers/Permissions-Policy.md - Technical explanation and attack scenarios
    - docs/architecture/extensibility-guide.md - Adding new analyzers
    - https://w3c.github.io/webappsec-permissions-policy/ - Specification
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

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
    for directive_str in value.split(","):
        directive_str = directive_str.strip()
        if not directive_str:
            continue

        # Split into feature name and allowlist
        if "=" in directive_str:
            parts = directive_str.split("=", 1)
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
