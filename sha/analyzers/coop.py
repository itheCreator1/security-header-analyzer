"""
Cross-Origin-Opener-Policy (COOP) Header Analyzer.

This module contains configuration and analysis logic for the
Cross-Origin-Opener-Policy header which isolates browsing context
and protects against cross-origin attacks.
"""

from typing import Dict, Optional, Any

from ..config import STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING


HEADER_KEY = "cross-origin-opener-policy"

CONFIG = {
    "display_name": "Cross-Origin-Opener-Policy",
    "severity_missing": "medium",
    "description": "Isolates browsing context from cross-origin windows",
    "validation": {
        "best_values": ["same-origin"],
        "acceptable_values": ["same-origin-allow-popups"],
        "bad_values": ["unsafe-none"],
    },
    "messages": {
        STATUS_GOOD: "COOP is properly configured with same-origin isolation",
        STATUS_ACCEPTABLE: "COOP is set to same-origin-allow-popups (acceptable with reduced isolation)",
        STATUS_BAD: "COOP is set to unsafe-none or has invalid value",
        STATUS_MISSING: "COOP header is missing - browsing context is not isolated from cross-origin windows",
    },
    "recommendations": {
        "missing": "Add: Cross-Origin-Opener-Policy: same-origin",
        "weak": "Use same-origin for strongest isolation (unless your application requires popups)",
        "info": "COOP provides protection against Spectre-like attacks by isolating your browsing context.",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Cross-Origin-Opener-Policy header.

    Validation rules:
    - Missing: Medium severity (important for security isolation)
    - same-origin: Good (strongest isolation)
    - same-origin-allow-popups: Acceptable (allows popups, reduced isolation)
    - unsafe-none or other: Bad

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

    value_lower = value.strip().lower()

    # Check for best value (same-origin)
    if value_lower in CONFIG["validation"]["best_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Check for acceptable value (same-origin-allow-popups)
    if value_lower in CONFIG["validation"]["acceptable_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["weak"],
        }

    # Check for explicitly bad value (unsafe-none)
    if value_lower in CONFIG["validation"]["bad_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"][STATUS_BAD],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["missing"],
        }

    # Invalid/unknown value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - unknown value: {value}",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["missing"],
    }
