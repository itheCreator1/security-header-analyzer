"""
X-XSS-Protection Header Analyzer.

This module contains configuration and analysis logic for the
X-XSS-Protection header which was used to control browser XSS filters.
This header is now deprecated and the modern recommendation is to
explicitly disable it or use Content-Security-Policy instead.
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING


HEADER_KEY = "x-xss-protection"

CONFIG = {
    "display_name": "X-XSS-Protection",
    "severity_missing": "low",
    "description": "Legacy XSS filter control (deprecated)",
    "validation": {
        "best_value": "0",
        "acceptable_value": "1; mode=block",
        "bad_value": "1",
    },
    "messages": {
        STATUS_GOOD: "X-XSS-Protection is properly configured (disabled)",
        STATUS_ACCEPTABLE: "X-XSS-Protection uses legacy filter mode",
        STATUS_BAD: "X-XSS-Protection has insecure configuration",
        STATUS_MISSING: "X-XSS-Protection header is missing - consider setting to 0",
    },
    "recommendations": {
        "missing": "Add: X-XSS-Protection: 0",
        "bad_value": "Set to: X-XSS-Protection: 0",
        "acceptable": "Consider setting to: X-XSS-Protection: 0 (modern recommendation)",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze X-XSS-Protection header.

    Validation rules:
    - Missing: Low severity (acceptable if using CSP)
    - "0": Good (modern recommendation to explicitly disable)
    - "1; mode=block": Acceptable (legacy approach)
    - "1": Bad (enables filter without blocking, can create vulnerabilities)
    - Unknown values: Bad

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

    # Normalize value for comparison
    value_normalized = value.strip().lower()

    # Best practice: explicitly disabled
    if value_normalized == CONFIG["validation"]["best_value"]:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Acceptable: legacy mode=block
    if value_normalized == CONFIG["validation"]["acceptable_value"]:
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": f"{CONFIG['messages'][STATUS_ACCEPTABLE]} - "
            f"modern recommendation is to disable with 0",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["acceptable"],
        }

    # Bad: plain "1" enables filter without blocking
    if value_normalized == CONFIG["validation"]["bad_value"]:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": "medium",
            "message": f"{CONFIG['messages'][STATUS_BAD]} - "
            f"value '1' can introduce XSS vulnerabilities",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["bad_value"],
        }

    # Empty value
    if not value_normalized:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": f"{CONFIG['messages'][STATUS_BAD]} - empty value",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["bad_value"],
        }

    # Unknown/invalid value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - "
        f"unknown value '{value}'",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["bad_value"],
    }
