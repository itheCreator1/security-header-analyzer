"""
Referrer-Policy Header Analyzer.

This module contains configuration and analysis logic for the
Referrer-Policy header which controls referrer information leakage.
"""

from typing import Dict, Optional, Any

from ..config import STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING


HEADER_KEY = "referrer-policy"

CONFIG = {
    "display_name": "Referrer-Policy",
    "severity_missing": "high",
    "description": "Controls how much referrer information is sent with requests",
    "validation": {
        # Best practice values (strongest privacy protection)
        "best_values": ["strict-origin", "no-referrer"],
        # Acceptable values (good balance of privacy and functionality)
        "acceptable_values": ["strict-origin-when-cross-origin", "same-origin", "origin", "origin-when-cross-origin"],
        # Bad/unsafe values (leak too much information)
        "bad_values": ["unsafe-url", "no-referrer-when-downgrade"],
    },
    "messages": {
        STATUS_GOOD: "Referrer-Policy is properly configured with strong privacy protection",
        STATUS_ACCEPTABLE: "Referrer-Policy is present with acceptable configuration",
        STATUS_BAD: "Referrer-Policy has weak configuration that may leak sensitive information",
        STATUS_MISSING: "Referrer-Policy header is missing - referrer information may leak sensitive data in URLs",
    },
    "recommendations": {
        "missing": "Add: Referrer-Policy: strict-origin-when-cross-origin or strict-origin",
        "weak": "Use a more restrictive policy like strict-origin or no-referrer to prevent URL parameter leakage",
        "consider_strict": "Consider using strict-origin for maximum privacy (only sends origin, not full URL path)",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Referrer-Policy header.

    Validation rules:
    - Missing: High severity
    - "strict-origin" or "no-referrer": Good (strongest privacy)
    - Acceptable values (strict-origin-when-cross-origin, same-origin, etc.): Acceptable
    - Bad values (unsafe-url, no-referrer-when-downgrade): Bad

    Note: If multiple values are provided (comma-separated), the first valid value takes precedence.

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

    # Handle comma-separated values (RFC allows fallback values)
    # The first valid value takes precedence
    value_lower = value.strip().lower()
    if "," in value_lower:
        # Split by comma and take the first value
        value_lower = value_lower.split(",")[0].strip()

    # Check for best values (strongest privacy)
    if value_lower in CONFIG["validation"]["best_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Check for acceptable values
    if value_lower in CONFIG["validation"]["acceptable_values"]:
        recommendation = None
        # If it's one of the weaker acceptable values, suggest upgrading
        if value_lower in ["origin-when-cross-origin", "origin"]:
            recommendation = CONFIG["recommendations"]["consider_strict"]

        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": recommendation,
        }

    # Check for bad/weak values
    if value_lower in CONFIG["validation"]["bad_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"][STATUS_BAD],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["weak"],
        }

    # Unknown/invalid value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - unknown value: {value}",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["missing"],
    }
