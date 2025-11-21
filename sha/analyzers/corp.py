"""
Cross-Origin-Resource-Policy (CORP) Header Analyzer.

This module contains configuration and analysis logic for the
Cross-Origin-Resource-Policy header which controls how resources
can be loaded by other origins.
"""

from typing import Dict, Optional, Any

from ..config import STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING


HEADER_KEY = "cross-origin-resource-policy"

CONFIG = {
    "display_name": "Cross-Origin-Resource-Policy",
    "severity_missing": "medium",
    "description": "Controls whether resources can be loaded cross-origin",
    "validation": {
        "best_values": ["same-origin"],
        "acceptable_values": ["same-site"],
        "bad_values": ["cross-origin"],
    },
    "messages": {
        STATUS_GOOD: "CORP is properly configured with same-origin restriction",
        STATUS_ACCEPTABLE: "CORP is set to same-site (acceptable for related sites)",
        STATUS_BAD: "CORP is set to cross-origin or has invalid value",
        STATUS_MISSING: "CORP header is missing - resources can be loaded by any origin",
    },
    "recommendations": {
        "missing": "Add: Cross-Origin-Resource-Policy: same-origin",
        "weak": "Use same-origin for strongest protection (unless resources need to be shared with same-site origins)",
        "info": "CORP protects against certain cross-origin attacks like Spectre by controlling resource loading.",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Cross-Origin-Resource-Policy header.

    Validation rules:
    - Missing: Medium severity (important for resource protection)
    - same-origin: Good (most restrictive)
    - same-site: Acceptable (allows same-site access)
    - cross-origin or other: Bad (allows cross-origin access)

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
            "recommendation": CONFIG["recommendations"]["info"],
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

    # Check for acceptable value (same-site)
    if value_lower in CONFIG["validation"]["acceptable_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["weak"],
        }

    # Check for explicitly bad value (cross-origin)
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
