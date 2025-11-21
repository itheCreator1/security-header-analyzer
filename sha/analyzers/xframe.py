"""
X-Frame-Options Header Analyzer.

This module contains configuration and analysis logic for the
X-Frame-Options header which prevents clickjacking attacks.
"""

from typing import Dict, Optional, Any

from ..config import STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING


HEADER_KEY = "x-frame-options"

CONFIG = {
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
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze X-Frame-Options header.

    Validation rules:
    - Missing: High severity
    - DENY: Good
    - SAMEORIGIN: Acceptable
    - ALLOW-FROM: Bad (deprecated)
    - Other values: Bad

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

    value_upper = value.strip().upper()

    # DENY - Best practice
    if value_upper == "DENY":
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # SAMEORIGIN - Acceptable
    if value_upper == "SAMEORIGIN":
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["use_deny"],
        }

    # ALLOW-FROM - Deprecated
    if value_upper.startswith("ALLOW-FROM"):
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": f"{CONFIG['messages'][STATUS_BAD]} - ALLOW-FROM is deprecated",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["allow_from"],
        }

    # Unknown value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - unknown value: {value}",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["missing"],
    }
