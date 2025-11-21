"""
HSTS (Strict-Transport-Security) Header Analyzer.

This module contains configuration and analysis logic for the
Strict-Transport-Security header which enforces HTTPS connections.
"""

import re
from typing import Dict, Optional, Any

from ..config import STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING


HEADER_KEY = "strict-transport-security"

CONFIG = {
    "display_name": "Strict-Transport-Security",
    "severity_missing": "critical",
    "description": "Enforces HTTPS connections to prevent man-in-the-middle attacks",
    "validation": {
        # Minimum max-age: 126 days (10886400 seconds)
        "min_max_age": 10886400,
        # Best practice max-age: 1 year (31536000 seconds)
        "best_max_age": 31536000,
        # Required directives for best practice
        "required_directives": ["includesubdomains"],
        # Optional but recommended directives
        "recommended_directives": ["preload"],
    },
    "messages": {
        STATUS_GOOD: "HSTS is properly configured with strong security settings",
        STATUS_ACCEPTABLE: "HSTS is present but could be improved",
        STATUS_BAD: "HSTS is present but improperly configured",
        STATUS_MISSING: "HSTS header is missing - connections vulnerable to downgrade attacks",
    },
    "recommendations": {
        "missing": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "low_max_age": "Increase max-age to at least 10886400 (126 days), preferably 31536000 (1 year)",
        "no_subdomains": "Add includeSubDomains directive to protect all subdomains",
        "no_preload": "Consider adding preload directive and submitting to HSTS preload list",
    },
}


def parse_hsts(value: str) -> Dict[str, Any]:
    """
    Parse HSTS header value into components.

    Args:
        value: HSTS header value

    Returns:
        Dictionary with:
        - max_age: int or None
        - include_subdomains: bool
        - preload: bool

    Example:
        >>> parse_hsts("max-age=31536000; includeSubDomains; preload")
        {"max_age": 31536000, "include_subdomains": True, "preload": True}
    """
    result = {
        "max_age": None,
        "include_subdomains": False,
        "preload": False,
    }

    # Parse max-age
    max_age_match = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
    if max_age_match:
        result["max_age"] = int(max_age_match.group(1))

    # Check for directives (case-insensitive)
    value_lower = value.lower()
    result["include_subdomains"] = "includesubdomains" in value_lower
    result["preload"] = "preload" in value_lower

    return result


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Strict-Transport-Security header.

    Validation rules:
    - Missing: Critical severity
    - max-age < 10886400 (126 days): Bad, Critical
    - max-age >= 10886400 with includeSubDomains + preload: Good
    - max-age >= 10886400 with includeSubDomains: Acceptable
    - max-age >= 10886400 without includeSubDomains: Acceptable (with warning)

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

    # Parse HSTS header
    parsed = parse_hsts(value)

    if parsed["max_age"] is None:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": "HSTS header is malformed - missing or invalid max-age directive",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["missing"],
        }

    max_age = parsed["max_age"]
    has_subdomains = parsed["include_subdomains"]
    has_preload = parsed["preload"]

    min_max_age = CONFIG["validation"]["min_max_age"]
    best_max_age = CONFIG["validation"]["best_max_age"]

    # Check if max-age is too low
    if max_age < min_max_age:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": f"HSTS max-age is too low ({max_age} seconds, minimum recommended: {min_max_age})",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["low_max_age"],
        }

    # Evaluate based on directives
    recommendations = []

    if not has_subdomains:
        recommendations.append(CONFIG["recommendations"]["no_subdomains"])

    if not has_preload:
        recommendations.append(CONFIG["recommendations"]["no_preload"])

    # Determine status
    if has_subdomains and has_preload and max_age >= best_max_age:
        status = STATUS_GOOD
        severity = "info"
        message = CONFIG["messages"][STATUS_GOOD]
        recommendation = None
    elif has_subdomains:
        status = STATUS_ACCEPTABLE
        severity = "low"
        message = CONFIG["messages"][STATUS_ACCEPTABLE]
        recommendation = "; ".join(recommendations) if recommendations else None
    else:
        status = STATUS_ACCEPTABLE
        severity = "medium"
        message = f"{CONFIG['messages'][STATUS_ACCEPTABLE]} - missing includeSubDomains directive"
        recommendation = "; ".join(recommendations)

    return {
        "header_name": header_name,
        "status": status,
        "severity": severity,
        "message": message,
        "actual_value": value,
        "recommendation": recommendation,
    }
