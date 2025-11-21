"""
X-Content-Type-Options Header Analyzer.

This module contains configuration and analysis logic for the
X-Content-Type-Options header which prevents MIME-type sniffing attacks.
"""

from typing import Dict, Optional, Any

from ..config import STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING


HEADER_KEY = "x-content-type-options"

CONFIG = {
    "display_name": "X-Content-Type-Options",
    "severity_missing": "medium-high",
    "description": "Prevents MIME-type sniffing attacks",
    "validation": {
        "required_value": "nosniff",
    },
    "messages": {
        STATUS_GOOD: "X-Content-Type-Options is properly configured",
        STATUS_ACCEPTABLE: "X-Content-Type-Options is properly configured",
        STATUS_BAD: "X-Content-Type-Options has incorrect value",
        STATUS_MISSING: "X-Content-Type-Options header is missing - browser may perform MIME-type sniffing",
    },
    "recommendations": {
        "missing": "Add: X-Content-Type-Options: nosniff",
        "wrong_value": "Set value to: nosniff",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze X-Content-Type-Options header.

    Validation rules:
    - Missing: Medium-High severity
    - "nosniff": Good
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

    value_lower = value.strip().lower()

    # Check for correct value
    if value_lower == CONFIG["validation"]["required_value"]:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Incorrect value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - value should be 'nosniff', got '{value}'",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["wrong_value"],
    }
