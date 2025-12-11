"""
Expect-CT Header Analyzer.

This module contains configuration and analysis logic for the
Expect-CT (Certificate Transparency) header which helps detect
misissued SSL/TLS certificates.

Note: Expect-CT is gradually being replaced by Certificate Transparency
enforcement in browsers, but is still useful for additional protection.
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "expect-ct"

# One day in seconds
MIN_MAX_AGE = 86400

CONFIG = {
    "display_name": "Expect-CT",
    "severity_missing": "low",
    "description": "Enforces Certificate Transparency to detect misissued certificates",
    "validation": {
        "min_max_age": MIN_MAX_AGE,
        "enforce_recommended": True,
    },
    "messages": {
        STATUS_GOOD: "Expect-CT is properly configured with enforcement enabled",
        STATUS_ACCEPTABLE: "Expect-CT is present but could be improved",
        STATUS_BAD: "Expect-CT has invalid or insufficient configuration",
        STATUS_MISSING: "Expect-CT header is missing (optional security enhancement)",
    },
    "recommendations": {
        "missing": "Consider adding Expect-CT header for Certificate Transparency enforcement",
        "add_enforce": "Add enforce directive to actively block violating certificates",
        "low_max_age": f"Increase max-age to at least {MIN_MAX_AGE} seconds (1 day)",
        "example": "Example: Expect-CT: max-age=86400, enforce",
    },
}


def parse_expect_ct(value: str) -> Dict[str, Any]:
    """
    Parse Expect-CT header value into components.

    Args:
        value: Expect-CT header value

    Returns:
        Dictionary with:
        - max_age: int or None (in seconds)
        - enforce: bool
        - report_uri: str or None

    Example:
        >>> parse_expect_ct("max-age=86400, enforce")
        {"max_age": 86400, "enforce": True, "report_uri": None}
    """
    result = {
        "max_age": None,
        "enforce": False,
        "report_uri": None,
    }

    directives = value.split(",")

    for directive in directives:
        directive = directive.strip()
        if not directive:
            continue

        if "=" in directive:
            dir_name, dir_value = directive.split("=", 1)
            dir_name = dir_name.strip().lower()
            dir_value = dir_value.strip()

            if dir_name == "max-age":
                try:
                    result["max_age"] = int(dir_value)
                except ValueError:
                    pass
            elif dir_name == "report-uri":
                result["report_uri"] = dir_value.replace('"', "").replace("'", "")
        else:
            if directive.lower() == "enforce":
                result["enforce"] = True

    return result


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Expect-CT header.

    Validation rules:
    - Missing: Low severity (optional header)
    - enforce + max-age >= 86400: Good
    - max-age >= 86400 without enforce: Acceptable (report-only mode)
    - max-age < 86400: Acceptable with warning
    - No max-age: Bad (required directive)
    - report-uri present: Info (provides additional monitoring)

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

    Note:
        Expect-CT is being phased out as Certificate Transparency
        becomes mandatory in browsers, but still provides value.
    """
    header_name = CONFIG["display_name"]

    if value is None:
        return {
            "header_name": header_name,
            "status": STATUS_MISSING,
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"][STATUS_MISSING],
            "actual_value": None,
            "recommendation": CONFIG["recommendations"]["missing"],
        }

    parsed = parse_expect_ct(value)

    max_age = parsed["max_age"]
    has_enforce = parsed["enforce"]
    report_uri = parsed["report_uri"]

    if max_age is None:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": "low",
            "message": "Expect-CT is missing required max-age directive",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["example"],
        }

    recommendations = []

    if max_age < CONFIG["validation"]["min_max_age"]:
        recommendations.append(CONFIG["recommendations"]["low_max_age"])

    if not has_enforce:
        recommendations.append(CONFIG["recommendations"]["add_enforce"])

    if has_enforce and max_age >= CONFIG["validation"]["min_max_age"]:
        status = STATUS_GOOD
        severity = "info"
        message = CONFIG["messages"][STATUS_GOOD]
        if report_uri:
            message += " with reporting enabled"
        recommendation = None
    elif max_age >= CONFIG["validation"]["min_max_age"]:
        status = STATUS_ACCEPTABLE
        severity = "low"
        message = CONFIG["messages"][STATUS_ACCEPTABLE] + " (report-only mode)"
        recommendation = "; ".join(recommendations) if recommendations else None
    elif has_enforce:
        status = STATUS_ACCEPTABLE
        severity = "low"
        message = f"{CONFIG['messages'][STATUS_ACCEPTABLE]} (max-age={max_age} seconds is low)"
        recommendation = "; ".join(recommendations) if recommendations else None
    else:
        status = STATUS_ACCEPTABLE
        severity = "low"
        message = CONFIG["messages"][STATUS_ACCEPTABLE]
        recommendation = "; ".join(recommendations)

    return {
        "header_name": header_name,
        "status": status,
        "severity": severity,
        "message": message,
        "actual_value": value,
        "recommendation": recommendation,
    }
