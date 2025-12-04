"""
X-Download-Options Header Analyzer.

This module contains configuration and analysis logic for the
X-Download-Options header which prevents Internet Explorer from
executing downloaded HTML files in the site's security context.
"""

from typing import Any, Dict, Optional

from ..config import STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "x-download-options"

CONFIG = {
    "display_name": "X-Download-Options",
    "severity_missing": "low",
    "description": "Prevents IE from executing downloads in site context",
    "validation": {
        "required_value": "noopen",
    },
    "messages": {
        STATUS_GOOD: "X-Download-Options is properly configured",
        STATUS_BAD: "X-Download-Options has incorrect value",
        STATUS_MISSING: "X-Download-Options header is missing - IE may execute downloads in site context",
    },
    "recommendations": {
        "missing": "Add: X-Download-Options: noopen",
        "wrong_value": "Set value to: noopen",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze X-Download-Options header.

    Validation rules:
    - Missing: Low severity (IE-specific, legacy)
    - "noopen": Good
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

    # Empty value
    if not value_lower:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": f"{CONFIG['messages'][STATUS_BAD]} - empty value",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["wrong_value"],
        }

    # Incorrect value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - "
        f"unknown value '{value}', should be 'noopen'",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["wrong_value"],
    }
