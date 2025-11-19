"""
Analyzer module for Security Header Analyzer.

This module analyzes HTTP security headers against industry best practices
and generates detailed findings with severity levels and recommendations.
"""

import re
from typing import Dict, List, Optional, Any

from .config import (
    SECURITY_HEADERS,
    STATUS_GOOD,
    STATUS_ACCEPTABLE,
    STATUS_BAD,
    STATUS_MISSING,
    get_all_header_names,
)


# Type alias for finding result
Finding = Dict[str, Any]


def analyze_headers(headers: Dict[str, str]) -> List[Finding]:
    """
    Analyze all security headers and generate findings.

    Args:
        headers: Dictionary of HTTP headers (lowercase keys)

    Returns:
        List of findings, each containing:
        {
            "header_name": str,        # Display name
            "status": str,              # good/acceptable/bad/missing
            "severity": str,            # critical/high/medium/low/info
            "message": str,             # Detailed explanation
            "actual_value": str|None,  # Actual header value (if present)
            "recommendation": str|None # How to fix (if not good)
        }

    Example:
        >>> headers = {"strict-transport-security": "max-age=31536000"}
        >>> findings = analyze_headers(headers)
        >>> findings[0]["status"]
        "acceptable"
    """
    findings = []

    # Analyze each configured security header
    for header_key in get_all_header_names():
        header_value = headers.get(header_key)

        # Route to specific analyzer based on header type
        if header_key == "strict-transport-security":
            finding = analyze_hsts(header_value)
        elif header_key == "x-frame-options":
            finding = analyze_xframe(header_value)
        elif header_key == "x-content-type-options":
            finding = analyze_content_type_options(header_value)
        elif header_key == "content-security-policy":
            finding = analyze_csp(header_value)
        else:
            # Shouldn't happen, but handle gracefully
            continue

        findings.append(finding)

    return findings


def analyze_hsts(value: Optional[str]) -> Finding:
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
        Finding dictionary
    """
    config = SECURITY_HEADERS["strict-transport-security"]
    header_name = config["display_name"]

    # Missing header
    if value is None:
        return {
            "header_name": header_name,
            "status": STATUS_MISSING,
            "severity": config["severity_missing"],
            "message": config["messages"][STATUS_MISSING],
            "actual_value": None,
            "recommendation": config["recommendations"]["missing"],
        }

    # Parse HSTS header
    parsed = parse_hsts(value)

    if parsed["max_age"] is None:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": config["severity_missing"],
            "message": "HSTS header is malformed - missing or invalid max-age directive",
            "actual_value": value,
            "recommendation": config["recommendations"]["missing"],
        }

    max_age = parsed["max_age"]
    has_subdomains = parsed["include_subdomains"]
    has_preload = parsed["preload"]

    min_max_age = config["validation"]["min_max_age"]
    best_max_age = config["validation"]["best_max_age"]

    # Check if max-age is too low
    if max_age < min_max_age:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": config["severity_missing"],
            "message": f"HSTS max-age is too low ({max_age} seconds, minimum recommended: {min_max_age})",
            "actual_value": value,
            "recommendation": config["recommendations"]["low_max_age"],
        }

    # Evaluate based on directives
    recommendations = []

    if not has_subdomains:
        recommendations.append(config["recommendations"]["no_subdomains"])

    if not has_preload:
        recommendations.append(config["recommendations"]["no_preload"])

    # Determine status
    if has_subdomains and has_preload and max_age >= best_max_age:
        status = STATUS_GOOD
        severity = "info"
        message = config["messages"][STATUS_GOOD]
        recommendation = None
    elif has_subdomains:
        status = STATUS_ACCEPTABLE
        severity = "low"
        message = config["messages"][STATUS_ACCEPTABLE]
        recommendation = "; ".join(recommendations) if recommendations else None
    else:
        status = STATUS_ACCEPTABLE
        severity = "medium"
        message = f"{config['messages'][STATUS_ACCEPTABLE]} - missing includeSubDomains directive"
        recommendation = "; ".join(recommendations)

    return {
        "header_name": header_name,
        "status": status,
        "severity": severity,
        "message": message,
        "actual_value": value,
        "recommendation": recommendation,
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


def analyze_xframe(value: Optional[str]) -> Finding:
    """
    Analyze X-Frame-Options header.

    Validation rules:
    - Missing: High severity
    - DENY: Good
    - SAMEORIGIN: Acceptable
    - ALLOW-FROM: Bad (deprecated)
    - Other values: Bad

    Args:
        value: Header value or None if missing

    Returns:
        Finding dictionary
    """
    config = SECURITY_HEADERS["x-frame-options"]
    header_name = config["display_name"]

    # Missing header
    if value is None:
        return {
            "header_name": header_name,
            "status": STATUS_MISSING,
            "severity": config["severity_missing"],
            "message": config["messages"][STATUS_MISSING],
            "actual_value": None,
            "recommendation": config["recommendations"]["missing"],
        }

    value_upper = value.strip().upper()

    # DENY - Best practice
    if value_upper == "DENY":
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": config["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # SAMEORIGIN - Acceptable
    if value_upper == "SAMEORIGIN":
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": config["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": config["recommendations"]["use_deny"],
        }

    # ALLOW-FROM - Deprecated
    if value_upper.startswith("ALLOW-FROM"):
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": config["severity_missing"],
            "message": f"{config['messages'][STATUS_BAD]} - ALLOW-FROM is deprecated",
            "actual_value": value,
            "recommendation": config["recommendations"]["allow_from"],
        }

    # Unknown value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": config["severity_missing"],
        "message": f"{config['messages'][STATUS_BAD]} - unknown value: {value}",
        "actual_value": value,
        "recommendation": config["recommendations"]["missing"],
    }


def analyze_content_type_options(value: Optional[str]) -> Finding:
    """
    Analyze X-Content-Type-Options header.

    Validation rules:
    - Missing: Medium-High severity
    - "nosniff": Good
    - Other values: Bad

    Args:
        value: Header value or None if missing

    Returns:
        Finding dictionary
    """
    config = SECURITY_HEADERS["x-content-type-options"]
    header_name = config["display_name"]

    # Missing header
    if value is None:
        return {
            "header_name": header_name,
            "status": STATUS_MISSING,
            "severity": config["severity_missing"],
            "message": config["messages"][STATUS_MISSING],
            "actual_value": None,
            "recommendation": config["recommendations"]["missing"],
        }

    value_lower = value.strip().lower()

    # Check for correct value
    if value_lower == config["validation"]["required_value"]:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": config["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Incorrect value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": config["severity_missing"],
        "message": f"{config['messages'][STATUS_BAD]} - value should be 'nosniff', got '{value}'",
        "actual_value": value,
        "recommendation": config["recommendations"]["wrong_value"],
    }


def analyze_csp(value: Optional[str]) -> Finding:
    """
    Analyze Content-Security-Policy header.

    This is the most complex header due to its directive-based structure.

    Validation rules:
    - Missing: Critical severity
    - Contains dangerous patterns (unsafe-inline in script-src, wildcards): Bad
    - Contains unsafe-eval: Acceptable with warning
    - Restrictive policy with security directives: Good

    Args:
        value: Header value or None if missing

    Returns:
        Finding dictionary
    """
    config = SECURITY_HEADERS["content-security-policy"]
    header_name = config["display_name"]

    # Missing header
    if value is None:
        return {
            "header_name": header_name,
            "status": STATUS_MISSING,
            "severity": config["severity_missing"],
            "message": config["messages"][STATUS_MISSING],
            "actual_value": None,
            "recommendation": config["recommendations"]["missing"],
        }

    # Parse CSP into directives
    directives = parse_csp(value)

    # Check for dangerous patterns
    dangerous_findings = check_csp_dangerous_patterns(directives, config)

    if dangerous_findings:
        # Found dangerous patterns
        severity = dangerous_findings[0]["severity"]  # Use highest severity
        messages = [f["message"] for f in dangerous_findings]
        recommendations = [f["recommendation"] for f in dangerous_findings]

        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": severity,
            "message": f"{config['messages'][STATUS_BAD]}: {'; '.join(messages)}",
            "actual_value": value,
            "recommendation": "; ".join(recommendations),
        }

    # Check for good patterns
    has_restrictive_default = check_csp_restrictive_default(directives, config)
    has_security_directives = check_csp_security_directives(directives, config)

    # Evaluate overall CSP quality
    if has_restrictive_default and has_security_directives:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": config["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }
    elif has_restrictive_default or len(directives) >= 3:
        # Has some good directives but could be improved
        recommendations = []
        if not has_security_directives:
            recommendations.append(config["recommendations"]["add_directives"])

        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": config["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": "; ".join(recommendations) if recommendations else None,
        }
    else:
        # CSP is present but too permissive
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "medium",
            "message": f"{config['messages'][STATUS_ACCEPTABLE]} - policy could be more restrictive",
            "actual_value": value,
            "recommendation": config["recommendations"]["example"],
        }


def parse_csp(value: str) -> Dict[str, List[str]]:
    """
    Parse CSP header value into directives.

    Args:
        value: CSP header value

    Returns:
        Dictionary mapping directive names to lists of values

    Example:
        >>> parse_csp("default-src 'self'; script-src 'self' https://cdn.example.com")
        {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.example.com"]
        }
    """
    directives = {}

    # Split by semicolon to get individual directives
    for directive_str in value.split(';'):
        directive_str = directive_str.strip()
        if not directive_str:
            continue

        # Split directive into name and values
        parts = directive_str.split()
        if not parts:
            continue

        directive_name = parts[0].lower()
        directive_values = parts[1:] if len(parts) > 1 else []

        directives[directive_name] = directive_values

    return directives


def check_csp_dangerous_patterns(
    directives: Dict[str, List[str]], config: Dict[str, Any]
) -> List[Dict[str, str]]:
    """
    Check CSP for dangerous patterns.

    Args:
        directives: Parsed CSP directives
        config: CSP configuration

    Returns:
        List of dangerous pattern findings (empty if none found)
    """
    findings = []
    dangerous_patterns = config["validation"]["dangerous_patterns"]

    # Check each dangerous pattern
    for pattern_name, pattern_config in dangerous_patterns.items():
        for directive_name in pattern_config["directives"]:
            if directive_name in directives:
                directive_values = directives[directive_name]

                # Check if any dangerous value is present
                for dangerous_value in pattern_config["values"]:
                    # Check for exact match or wildcard match
                    if dangerous_value in directive_values:
                        findings.append({
                            "severity": pattern_config["severity"],
                            "message": pattern_config["message"],
                            "recommendation": config["recommendations"].get(
                                pattern_name.replace("_", "-"),
                                config["recommendations"]["too_permissive"]
                            ),
                        })
                        break

    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

    return findings


def check_csp_restrictive_default(
    directives: Dict[str, List[str]], config: Dict[str, Any]
) -> bool:
    """
    Check if CSP has a restrictive default-src directive.

    Args:
        directives: Parsed CSP directives
        config: CSP configuration

    Returns:
        True if default-src is restrictive
    """
    if "default-src" not in directives:
        return False

    default_values = directives["default-src"]
    restrictive_values = config["validation"]["good_patterns"]["restrictive_default"]

    # Check if default-src contains any restrictive value
    for value in default_values:
        if value in restrictive_values:
            return True

    return False


def check_csp_security_directives(
    directives: Dict[str, List[str]], config: Dict[str, Any]
) -> bool:
    """
    Check if CSP has important security directives.

    Args:
        directives: Parsed CSP directives
        config: CSP configuration

    Returns:
        True if at least one security directive is present
    """
    security_directives = config["validation"]["good_patterns"]["security_directives"]

    for directive in security_directives:
        if directive in directives:
            return True

    return False
