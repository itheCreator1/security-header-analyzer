"""
Set-Cookie Header Analyzer.

This module contains configuration and analysis logic for the
Set-Cookie header which controls cookie security attributes.

Note: Due to current fetcher implementation limitations, only one
Set-Cookie header is analyzed even if multiple cookies are set.
Future enhancement: Capture all Set-Cookie headers from response.
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "set-cookie"

# One year in seconds (365 days)
MAX_AGE_ONE_YEAR = 31536000

CONFIG = {
    "display_name": "Set-Cookie",
    "severity_missing": "info",  # Optional header - not all responses set cookies
    "description": "Controls security attributes of HTTP cookies",
    "validation": {
        # Security attributes that should be present
        "required_secure": True,  # Cookie should only be sent over HTTPS
        "required_httponly": True,  # Cookie should not be accessible via JavaScript
        # SameSite values (case-insensitive)
        "samesite_strict": "strict",  # Best - no cross-site requests
        "samesite_lax": "lax",  # Good - some cross-site requests allowed
        "samesite_none": "none",  # Requires Secure attribute
        # Max-Age validation
        "max_age_warning_threshold": MAX_AGE_ONE_YEAR,  # Warn if >1 year
    },
    "messages": {
        STATUS_GOOD: "Cookie has all recommended security attributes (Secure, HttpOnly, SameSite)",
        STATUS_ACCEPTABLE: "Cookie has basic security attributes but could be improved",
        STATUS_BAD: "Cookie is missing critical security attributes",
        STATUS_MISSING: "No Set-Cookie header present (cookies are not being set)",
    },
    "recommendations": {
        "missing": "If setting cookies, ensure Secure, HttpOnly, and SameSite attributes are used",
        "no_secure": "Add Secure attribute to prevent cookie transmission over HTTP",
        "no_httponly": "Add HttpOnly attribute to prevent JavaScript access to cookie",
        "no_samesite": "Add SameSite attribute (Strict or Lax) to prevent CSRF attacks",
        "samesite_none_without_secure": "SameSite=None requires Secure attribute",
        "long_max_age": "Consider shorter Max-Age for sensitive cookies (current >1 year)",
        "example": "Example: Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=86400; Path=/",
    },
}


def parse_set_cookie(value: str) -> Dict[str, Any]:
    """
    Parse Set-Cookie header value into components.

    Args:
        value: Set-Cookie header value

    Returns:
        Dictionary with:
        - cookie_name: str or None
        - cookie_value: str or None
        - secure: bool
        - httponly: bool
        - samesite: str or None ('Strict', 'Lax', 'None')
        - max_age: int or None (in seconds)
        - expires: str or None (HTTP date string)
        - domain: str or None
        - path: str or None

    Example:
        >>> parse_set_cookie("session=abc123; Secure; HttpOnly; SameSite=Strict")
        {
            "cookie_name": "session",
            "cookie_value": "abc123",
            "secure": True,
            "httponly": True,
            "samesite": "Strict",
            ...
        }
    """
    result = {
        "cookie_name": None,
        "cookie_value": None,
        "secure": False,
        "httponly": False,
        "samesite": None,
        "max_age": None,
        "expires": None,
        "domain": None,
        "path": None,
    }

    # Split by semicolon to get cookie definition and attributes
    parts = value.split(";")

    if not parts:
        return result

    # First part is cookie-name=cookie-value
    cookie_def = parts[0].strip()
    if "=" in cookie_def:
        name, val = cookie_def.split("=", 1)
        result["cookie_name"] = name.strip()
        result["cookie_value"] = val.strip()

    # Parse attributes (case-insensitive)
    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue

        # Check for attribute=value
        if "=" in part:
            attr_name, attr_value = part.split("=", 1)
            attr_name = attr_name.strip().lower()
            attr_value = attr_value.strip()

            if attr_name == "samesite":
                # Normalize to title case
                result["samesite"] = attr_value.capitalize()
            elif attr_name == "max-age":
                # Parse as integer
                try:
                    result["max_age"] = int(attr_value)
                except ValueError:
                    pass  # Invalid max-age, leave as None
            elif attr_name == "expires":
                result["expires"] = attr_value
            elif attr_name == "domain":
                result["domain"] = attr_value
            elif attr_name == "path":
                result["path"] = attr_value
        else:
            # Boolean attributes (just the name, no value)
            attr_name = part.lower()
            if attr_name == "secure":
                result["secure"] = True
            elif attr_name == "httponly":
                result["httponly"] = True

    return result


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Set-Cookie header.

    Validation rules:
    - Missing: Info severity (not all responses set cookies)
    - Missing Secure attribute: High severity (cookie sent over HTTP)
    - Missing HttpOnly attribute: High severity (XSS can steal cookie)
    - Missing SameSite or SameSite=None without Secure: Medium-High severity
    - SameSite=Strict + Secure + HttpOnly: Good
    - SameSite=Lax + Secure + HttpOnly: Acceptable
    - Max-Age >1 year: Low severity warning

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
        Currently only analyzes one cookie due to fetcher limitations.
        If multiple Set-Cookie headers exist, only one is analyzed.
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

    # Parse cookie
    parsed = parse_set_cookie(value)

    # Check for critical security attributes
    has_secure = parsed["secure"]
    has_httponly = parsed["httponly"]
    samesite = parsed["samesite"]
    max_age = parsed["max_age"]

    # Build list of issues
    issues = []
    recommendations = []

    if not has_secure:
        issues.append("missing Secure attribute")
        recommendations.append(CONFIG["recommendations"]["no_secure"])

    if not has_httponly:
        issues.append("missing HttpOnly attribute")
        recommendations.append(CONFIG["recommendations"]["no_httponly"])

    # SameSite validation
    if samesite is None:
        issues.append("missing SameSite attribute")
        recommendations.append(CONFIG["recommendations"]["no_samesite"])
    elif samesite == "None" and not has_secure:
        issues.append("SameSite=None without Secure attribute")
        recommendations.append(CONFIG["recommendations"]["samesite_none_without_secure"])

    # Max-Age validation (low priority warning)
    if max_age and max_age > CONFIG["validation"]["max_age_warning_threshold"]:
        issues.append(f"very long Max-Age ({max_age} seconds, >{MAX_AGE_ONE_YEAR})")
        recommendations.append(CONFIG["recommendations"]["long_max_age"])

    # Determine status based on issues
    if not has_secure or not has_httponly:
        # Critical security attributes missing
        status = STATUS_BAD
        severity = "high"
        message = f"Cookie {', '.join(issues)}"
        recommendation = "; ".join(recommendations)
    elif samesite is None or (samesite == "None" and not has_secure):
        # SameSite issues
        status = STATUS_BAD
        severity = "medium"
        message = f"Cookie {', '.join(issues)}"
        recommendation = "; ".join(recommendations)
    elif samesite == "Strict":
        # Best configuration
        if max_age and max_age > CONFIG["validation"]["max_age_warning_threshold"]:
            status = STATUS_ACCEPTABLE
            severity = "low"
            message = f"{CONFIG['messages'][STATUS_GOOD]}, but {issues[0]}"
            recommendation = recommendations[0] if recommendations else None
        else:
            status = STATUS_GOOD
            severity = "info"
            message = CONFIG["messages"][STATUS_GOOD]
            recommendation = None
    elif samesite == "Lax" or (samesite == "None" and has_secure):
        # Acceptable configuration
        if max_age and max_age > CONFIG["validation"]["max_age_warning_threshold"]:
            status = STATUS_ACCEPTABLE
            severity = "low"
            message = f"{CONFIG['messages'][STATUS_ACCEPTABLE]} ({issues[0]})"
            recommendation = recommendations[0] if recommendations else None
        else:
            status = STATUS_ACCEPTABLE
            severity = "low"
            message = CONFIG["messages"][STATUS_ACCEPTABLE]
            recommendation = "Consider using SameSite=Strict for maximum protection"
    else:
        # Shouldn't reach here, but handle gracefully
        status = STATUS_ACCEPTABLE
        severity = "low"
        message = CONFIG["messages"][STATUS_ACCEPTABLE]
        recommendation = None

    return {
        "header_name": header_name,
        "status": status,
        "severity": severity,
        "message": message,
        "actual_value": value,
        "recommendation": recommendation,
    }
