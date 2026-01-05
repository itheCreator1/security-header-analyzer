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
    restrictions on 19 sensitive features (7 high-risk, 7 medium-risk, 5 low-risk), and
    evaluates policy strictness. It checks for restrictive values (empty allowlist '()'
    or 'self' only) versus permissive wildcards. The analyzer uses risk categorization to
    provide targeted recommendations and detects deprecated Feature-Policy names. It
    recognizes that Permissions-Policy is crucial for privacy (camera, microphone,
    geolocation) and security (USB, serial, bluetooth access).

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

Sensitive Features Tracked (by Risk Level):
    **HIGH-RISK (7 features):**
    - **camera**: Webcam access (privacy concern)
    - **microphone**: Audio recording (privacy/surveillance)
    - **geolocation**: User location tracking (privacy)
    - **usb**: USB device access (security concern)
    - **serial**: Serial port access (hardware security)
    - **bluetooth**: Bluetooth device pairing (hardware security)
    - **display-capture**: Screen sharing/recording (privacy)

    **MEDIUM-RISK (7 features):**
    - **payment**: Payment Request API (financial security)
    - **fullscreen**: UI spoofing vector
    - **gyroscope**, **accelerometer**, **magnetometer**: Sensor tracking
    - **midi**: MIDI device access
    - **picture-in-picture**: Privacy concern

    **LOW-RISK (5 features):**
    - **web-share**: Data sharing control
    - **autoplay**: UX/security
    - **ambient-light-sensor**: Tracking vector
    - **encrypted-media**: DRM content
    - **document-domain**: Cross-origin security

Policy Syntax:
    - feature=(): Deny to all origins (most restrictive)
    - feature=(self): Allow only same origin
    - feature=(self "https://example.com"): Allow self + specific origins
    - feature=*: Allow all origins (DANGEROUS - flagged as bad)

Configuration:
    - high_risk_features: 7 critical features (camera, microphone, geolocation, usb, serial, bluetooth, display-capture)
    - medium_risk_features: 7 important features (payment, fullscreen, sensors, midi, picture-in-picture)
    - low_risk_features: 5 nice-to-have restrictions (web-share, autoplay, ambient-light-sensor, etc.)
    - restrictive_values: '()' or 'self' (good restriction patterns)
    - deprecated_features: Map of old Feature-Policy names to modern equivalents

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
        # HIGH-RISK features - should always be restricted (privacy/security critical)
        "high_risk_features": [
            "camera",  # Webcam access
            "microphone",  # Audio recording
            "geolocation",  # Location tracking
            "usb",  # USB device access
            "serial",  # Serial port access
            "bluetooth",  # Bluetooth pairing
            "display-capture",  # Screen sharing/recording
        ],
        # MEDIUM-RISK features - should be restricted in most cases
        "medium_risk_features": [
            "payment",  # Payment Request API
            "fullscreen",  # UI spoofing vector
            "gyroscope",  # Sensor tracking
            "accelerometer",  # Sensor tracking
            "magnetometer",  # Sensor tracking
            "midi",  # MIDI device access
            "picture-in-picture",  # Privacy concern
        ],
        # LOW-RISK features - nice to restrict but less critical
        "low_risk_features": [
            "web-share",  # Data sharing
            "autoplay",  # UX/security
            "ambient-light-sensor",  # Tracking vector
            "encrypted-media",  # DRM content
            "document-domain",  # Cross-origin security
        ],
        # Good restriction patterns
        "restrictive_values": ["()", "self"],
        # Deprecated Feature-Policy names (warn users)
        "deprecated_features": {
            "vr": "xr-spatial-tracking",  # Old name for XR
            "speaker": "speaker-selection",
            "vibrate": "vibrate",  # Removed from spec
        },
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


def detect_deprecated_features(features: Dict[str, str]) -> Dict[str, str]:
    """
    Detect deprecated Feature-Policy names in parsed policy.

    Args:
        features: Parsed feature directives

    Returns:
        Dictionary mapping deprecated feature names to modern replacements
    """
    deprecated = {}
    deprecated_map = CONFIG["validation"]["deprecated_features"]

    for feature_name in features.keys():
        if feature_name in deprecated_map:
            deprecated[feature_name] = deprecated_map[feature_name]

    return deprecated


def get_all_sensitive_features() -> list:
    """
    Get combined list of all sensitive features (high + medium risk).

    Returns:
        List of all sensitive feature names
    """
    high_risk = CONFIG["validation"]["high_risk_features"]
    medium_risk = CONFIG["validation"]["medium_risk_features"]
    return high_risk + medium_risk


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Permissions-Policy header.

    Validation rules:
    - Missing: High severity (modern feature, important for privacy)
    - Restricts high-risk features with () or self: Good
    - Has some restrictions: Acceptable
    - Allows high-risk features with *: Bad
    - Detects deprecated features and provides warnings
    - Warns about unrestricted high-risk features

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
        - warnings: list (optional - for deprecated features)
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

    # Check for deprecated features
    deprecated = detect_deprecated_features(features)
    warnings = []
    if deprecated:
        for old_name, new_name in deprecated.items():
            warnings.append(
                f"Deprecated feature '{old_name}' - use '{new_name}' instead"
            )

    # Get all sensitive features (high + medium risk)
    high_risk_features = CONFIG["validation"]["high_risk_features"]
    medium_risk_features = CONFIG["validation"]["medium_risk_features"]
    restrictive_values = CONFIG["validation"]["restrictive_values"]

    # Track restricted features by risk level
    high_risk_restricted = 0
    medium_risk_restricted = 0
    unrestricted_high_risk = []
    unrestricted_medium_risk = []
    missing_high_risk = []

    # Check high-risk features
    for feature in high_risk_features:
        if feature in features:
            allowlist = features[feature]
            # Check if it's restrictive (empty list or self only)
            if any(restrictive in allowlist for restrictive in restrictive_values):
                high_risk_restricted += 1
            elif "*" in allowlist:
                unrestricted_high_risk.append(feature)
        else:
            # High-risk feature not mentioned - warn about it
            missing_high_risk.append(feature)

    # Check medium-risk features
    for feature in medium_risk_features:
        if feature in features:
            allowlist = features[feature]
            if any(restrictive in allowlist for restrictive in restrictive_values):
                medium_risk_restricted += 1
            elif "*" in allowlist:
                unrestricted_medium_risk.append(feature)

    total_restricted = high_risk_restricted + medium_risk_restricted

    # Build recommendation based on analysis
    recommendation = None
    if missing_high_risk and high_risk_restricted < len(high_risk_features):
        # Suggest adding missing high-risk restrictions
        missing_list = ", ".join(missing_high_risk[:3])  # Show first 3
        if len(missing_high_risk) > 3:
            missing_list += f", and {len(missing_high_risk) - 3} more"
        recommendation = (
            f"Consider restricting high-risk features: {missing_list}. "
            f"Example: {missing_high_risk[0]}=()"
        )

    # Evaluate the policy
    if unrestricted_high_risk:
        # BAD: High-risk features explicitly allowed with wildcard
        message = (
            f"{CONFIG['messages'][STATUS_BAD]}: "
            f"High-risk features allowed with wildcard: {', '.join(unrestricted_high_risk)}"
        )
        result = {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": "high",
            "message": message,
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["too_permissive"],
        }
    elif unrestricted_medium_risk:
        # BAD: Medium-risk features unrestricted
        message = (
            f"{CONFIG['messages'][STATUS_BAD]}: "
            f"Medium-risk features allowed with wildcard: {', '.join(unrestricted_medium_risk)}"
        )
        result = {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": "medium",
            "message": message,
            "actual_value": value,
            "recommendation": "Restrict medium-risk features to specific origins or deny with ()",
        }
    elif high_risk_restricted >= 3:
        # GOOD: At least 3 high-risk features restricted
        message = f"{CONFIG['messages'][STATUS_GOOD]} ({high_risk_restricted} high-risk features restricted)"
        result = {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": message,
            "actual_value": value,
            "recommendation": recommendation,
        }
    elif total_restricted >= 3:
        # ACCEPTABLE: At least 3 sensitive features restricted
        result = {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": f"{CONFIG['messages'][STATUS_ACCEPTABLE]} ({total_restricted} features restricted)",
            "actual_value": value,
            "recommendation": recommendation or "Consider adding more restrictive policies for high-risk features",
        }
    else:
        # ACCEPTABLE: Has directives but few restrictions
        result = {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "medium",
            "message": "Permissions-Policy is present but doesn't adequately restrict sensitive features",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["too_permissive"],
        }

    # Add warnings if any deprecated features found
    if warnings:
        result["warnings"] = warnings

    return result
