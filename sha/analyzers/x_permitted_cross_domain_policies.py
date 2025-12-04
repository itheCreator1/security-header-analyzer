"""
X-Permitted-Cross-Domain-Policies Header Analyzer.

This module contains configuration and analysis logic for the
X-Permitted-Cross-Domain-Policies header which controls whether
Adobe Flash Player and PDF documents can load cross-domain policy files.
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "x-permitted-cross-domain-policies"

CONFIG = {
    "display_name": "X-Permitted-Cross-Domain-Policies",
    "severity_missing": "medium",
    "description": "Controls Flash/PDF cross-domain policy file access",
    "validation": {
        "best_value": "none",
        "acceptable_value": "master-only",
        "bad_values": {
            "all": "high",
            "by-content-type": "medium",
            "by-ftp-filename": "medium",
        },
    },
    "messages": {
        STATUS_GOOD: "X-Permitted-Cross-Domain-Policies is properly configured",
        STATUS_ACCEPTABLE: "X-Permitted-Cross-Domain-Policies allows master policy file only",
        STATUS_BAD: "X-Permitted-Cross-Domain-Policies has insecure configuration",
        STATUS_MISSING: "X-Permitted-Cross-Domain-Policies header is missing - Flash/PDF may load policy files",
    },
    "recommendations": {
        "missing": "Add: X-Permitted-Cross-Domain-Policies: none",
        "bad_value": "Set to: X-Permitted-Cross-Domain-Policies: none",
        "acceptable": "Consider setting to: none for maximum security",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze X-Permitted-Cross-Domain-Policies header.

    Validation rules:
    - Missing: Medium severity
    - "none": Good (completely prohibits policy files)
    - "master-only": Acceptable (allows /crossdomain.xml only)
    - "all": Bad, High severity (allows policy files anywhere)
    - "by-content-type": Bad, Medium severity (too permissive)
    - "by-ftp-filename": Bad, Medium severity (legacy, insecure)
    - Unknown values: Bad, Medium severity

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
    value_lower = value.strip().lower()

    # Best practice: none
    if value_lower == CONFIG["validation"]["best_value"]:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Acceptable: master-only
    if value_lower == CONFIG["validation"]["acceptable_value"]:
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": f"{CONFIG['messages'][STATUS_ACCEPTABLE]} - "
            f"consider using 'none' for maximum security",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["acceptable"],
        }

    # Empty value
    if not value_lower:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": f"{CONFIG['messages'][STATUS_BAD]} - empty value",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["bad_value"],
        }

    # Check for known bad values with specific severities
    if value_lower in CONFIG["validation"]["bad_values"]:
        severity = CONFIG["validation"]["bad_values"][value_lower]
        if value_lower == "all":
            message = (
                f"{CONFIG['messages'][STATUS_BAD]} - "
                f"'all' allows policy files from anywhere (very insecure)"
            )
        elif value_lower == "by-content-type":
            message = f"{CONFIG['messages'][STATUS_BAD]} - " f"'by-content-type' is too permissive"
        else:  # by-ftp-filename
            message = (
                f"{CONFIG['messages'][STATUS_BAD]} - " f"'by-ftp-filename' is legacy and insecure"
            )

        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": severity,
            "message": message,
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["bad_value"],
        }

    # Unknown value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - " f"unknown value '{value}'",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["bad_value"],
    }
