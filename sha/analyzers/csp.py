"""
Content-Security-Policy Header Analyzer.

This module contains configuration and analysis logic for the
Content-Security-Policy header which prevents XSS and injection attacks.
"""

from typing import Dict, List, Optional, Any

from ..config import STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING


HEADER_KEY = "content-security-policy"

CONFIG = {
    "display_name": "Content-Security-Policy",
    "severity_missing": "critical",
    "description": "Prevents XSS and other injection attacks by controlling resource loading",
    "validation": {
        # Dangerous patterns that indicate insecure CSP
        "dangerous_patterns": {
            "unsafe_inline_script": {
                "directives": ["script-src", "default-src"],
                "values": ["'unsafe-inline'"],
                "severity": "high",
                "message": "CSP allows unsafe-inline for scripts, defeating XSS protection",
            },
            "unsafe_eval": {
                "directives": ["script-src", "default-src"],
                "values": ["'unsafe-eval'"],
                "severity": "medium",
                "message": "CSP allows unsafe-eval, which can enable some XSS attacks",
            },
            "wildcard_script": {
                "directives": ["script-src"],
                "values": ["*", "data:", "http:", "https:"],
                "severity": "high",
                "message": "CSP allows scripts from any source (wildcard)",
            },
            "wildcard_default": {
                "directives": ["default-src"],
                "values": ["*"],
                "severity": "high",
                "message": "CSP default-src is wildcard, allowing resources from any source",
            },
        },
        # Good patterns that indicate secure CSP
        "good_patterns": {
            "restrictive_default": ["'self'", "'none'"],
            "security_directives": ["frame-ancestors", "base-uri", "form-action"],
        },
    },
    "messages": {
        STATUS_GOOD: "CSP is properly configured with restrictive policy",
        STATUS_ACCEPTABLE: "CSP is present but could be more restrictive",
        STATUS_BAD: "CSP is present but contains dangerous directives",
        STATUS_MISSING: "CSP header is missing - site vulnerable to XSS and injection attacks",
    },
    "recommendations": {
        "missing": "Add a Content-Security-Policy header with restrictive directives",
        "unsafe_inline": "Remove 'unsafe-inline' from script-src and use nonces or hashes instead",
        "unsafe_eval": "Remove 'unsafe-eval' from script-src if possible",
        "too_permissive": "Restrict source lists to specific trusted domains instead of wildcards",
        "add_directives": "Consider adding security directives: frame-ancestors, base-uri, form-action",
        "example": "Example: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    },
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


def has_nonces_or_hashes(directive_values: List[str]) -> bool:
    """
    Check if a directive uses nonces or hashes (better than unsafe-inline).

    Args:
        directive_values: List of values for a directive

    Returns:
        True if nonces or hashes are present
    """
    for value in directive_values:
        # Check for nonce: 'nonce-<value>'
        if value.startswith("'nonce-"):
            return True
        # Check for hash: 'sha256-<hash>', 'sha384-<hash>', 'sha512-<hash>'
        if value.startswith(("'sha256-", "'sha384-", "'sha512-")):
            return True
    return False


def has_strict_dynamic(directive_values: List[str]) -> bool:
    """
    Check if a directive uses 'strict-dynamic' (modern best practice).

    Args:
        directive_values: List of values for a directive

    Returns:
        True if 'strict-dynamic' is present
    """
    return "'strict-dynamic'" in directive_values


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

    Note:
        'unsafe-inline' is not considered dangerous if nonces, hashes,
        or 'strict-dynamic' are also present, as they override it.
    """
    findings = []
    dangerous_patterns = config["validation"]["dangerous_patterns"]

    # Check each dangerous pattern
    for pattern_name, pattern_config in dangerous_patterns.items():
        for directive_name in pattern_config["directives"]:
            if directive_name in directives:
                directive_values = directives[directive_name]

                # Special handling for unsafe-inline: it's OK if nonces/hashes/strict-dynamic present
                if pattern_name == "unsafe_inline_script":
                    if "'unsafe-inline'" in directive_values:
                        # Check if mitigated by nonces, hashes, or strict-dynamic
                        if has_nonces_or_hashes(directive_values) or has_strict_dynamic(directive_values):
                            # unsafe-inline is ignored when these are present
                            continue
                        else:
                            findings.append({
                                "severity": pattern_config["severity"],
                                "message": pattern_config["message"],
                                "recommendation": config["recommendations"].get(
                                    pattern_name.replace("_", "-"),
                                    config["recommendations"]["too_permissive"]
                                ),
                            })
                    continue

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


def analyze(value: Optional[str]) -> Dict[str, Any]:
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

    # Parse CSP into directives
    directives = parse_csp(value)

    # Check for dangerous patterns
    dangerous_findings = check_csp_dangerous_patterns(directives, CONFIG)

    if dangerous_findings:
        # Found dangerous patterns
        severity = dangerous_findings[0]["severity"]  # Use highest severity
        messages = [f["message"] for f in dangerous_findings]
        recommendations = [f["recommendation"] for f in dangerous_findings]

        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": severity,
            "message": f"{CONFIG['messages'][STATUS_BAD]}: {'; '.join(messages)}",
            "actual_value": value,
            "recommendation": "; ".join(recommendations),
        }

    # Check for good patterns
    has_restrictive_default = check_csp_restrictive_default(directives, CONFIG)
    has_security_directives = check_csp_security_directives(directives, CONFIG)

    # Evaluate overall CSP quality
    if has_restrictive_default and has_security_directives:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }
    elif has_restrictive_default or len(directives) >= 3:
        # Has some good directives but could be improved
        recommendations = []
        if not has_security_directives:
            recommendations.append(CONFIG["recommendations"]["add_directives"])

        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": "; ".join(recommendations) if recommendations else None,
        }
    else:
        # CSP is present but too permissive
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "medium",
            "message": f"{CONFIG['messages'][STATUS_ACCEPTABLE]} - policy could be more restrictive",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["example"],
        }
