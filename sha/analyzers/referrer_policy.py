"""
Referrer-Policy Analyzer - Referrer information leakage control

Module: sha.analyzers.referrer_policy

Purpose:
    Analyzes the Referrer-Policy header to control how much referrer information
    (originating page URL) is sent with outgoing requests. Validates policy values
    for privacy protection and prevents leakage of sensitive URL parameters.

Overview:
    The Referrer-Policy analyzer evaluates privacy protection levels of different
    referrer policies. It categorizes policies into best (strict-origin, no-referrer),
    acceptable (strict-origin-when-cross-origin, same-origin), and bad (unsafe-url,
    no-referrer-when-downgrade). The analyzer handles comma-separated fallback values
    and provides recommendations for upgrading to more restrictive policies.

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that validates referrer policy value and categorizes
      it by privacy protection strength

Validation Rules:
    - Missing header: HIGH severity
    - Best values (strict-origin, no-referrer): GOOD, info severity (strongest privacy)
    - Acceptable values (strict-origin-when-cross-origin, same-origin, origin,
      origin-when-cross-origin): ACCEPTABLE, low severity
    - Bad values (unsafe-url, no-referrer-when-downgrade): BAD, high severity
    - Unknown value: BAD, high severity

Attack Scenarios Prevented:
    - **Sensitive URL Parameter Leakage**: Prevents leaking tokens, session IDs,
      or other sensitive data in URL query parameters to third-party sites
      (e.g., ?reset_token=abc123, ?api_key=secret)
    - **Privacy Violations**: Protects user privacy by not revealing full browsing
      history to external sites through referrer headers
    - **Analytics Tracking**: Limits cross-site tracking capabilities by restricting
      what origin information is shared
    - **HTTPS→HTTP Downgrade Leakage**: With strict-origin, prevents sending
      referrer when downgrading from HTTPS to HTTP

Policy Privacy Levels:
    - **no-referrer**: Never send referrer (maximum privacy)
    - **strict-origin**: Only send origin on same security level (HTTPS→HTTPS)
    - **strict-origin-when-cross-origin**: Full URL for same-origin, origin for cross-origin
    - **same-origin**: Full URL for same-origin only, nothing for cross-origin
    - **origin**: Always send origin only (no path/query)
    - **unsafe-url**: Always send full URL (including to HTTP) - **BAD**
    - **no-referrer-when-downgrade**: Send full URL except on HTTPS→HTTP - **BAD**

Configuration:
    - best_values: strict-origin, no-referrer (strongest privacy)
    - acceptable_values: strict-origin-when-cross-origin, same-origin, origin,
      origin-when-cross-origin
    - bad_values: unsafe-url, no-referrer-when-downgrade

Related Modules:
    - sha.analyzers.__init__ - Registers referrer_policy.analyze in ANALYZER_REGISTRY
    - sha.config - Imports STATUS_* constants
    - docs/headers/Referrer-Policy.md - Detailed header documentation

Example Usage:
    >>> from sha.analyzers.referrer_policy import analyze
    >>> # Best practice - strict-origin
    >>> finding = analyze("strict-origin")
    >>> finding["status"]
    "good"
    >>> finding["severity"]
    "info"

    >>> # Acceptable - good balance
    >>> finding = analyze("strict-origin-when-cross-origin")
    >>> finding["status"]
    "acceptable"
    >>> finding["severity"]
    "low"

    >>> # Bad - unsafe policy
    >>> finding = analyze("unsafe-url")
    >>> finding["status"]
    "bad"
    >>> finding["severity"]
    "high"

See Also:
    - docs/headers/Referrer-Policy.md - Technical explanation and attack scenarios
    - docs/architecture/EXTENSIBILITY.md - Adding new analyzers
    - https://w3c.github.io/webappsec-referrer-policy/ - Referrer Policy specification
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "referrer-policy"

CONFIG = {
    "display_name": "Referrer-Policy",
    "severity_missing": "high",
    "description": "Controls how much referrer information is sent with requests",
    "validation": {
        # Best practice values (strongest privacy protection)
        "best_values": ["strict-origin", "no-referrer"],
        # Acceptable values (good balance of privacy and functionality)
        "acceptable_values": [
            "strict-origin-when-cross-origin",
            "same-origin",
            "origin",
            "origin-when-cross-origin",
        ],
        # Bad/unsafe values (leak too much information)
        "bad_values": ["unsafe-url", "no-referrer-when-downgrade"],
    },
    "messages": {
        STATUS_GOOD: "Referrer-Policy is properly configured with strong privacy protection",
        STATUS_ACCEPTABLE: "Referrer-Policy is present with acceptable configuration",
        STATUS_BAD: "Referrer-Policy has weak configuration that may leak sensitive information",
        STATUS_MISSING: "Referrer-Policy header is missing - referrer information may leak sensitive data in URLs",
    },
    "recommendations": {
        "missing": "Add: Referrer-Policy: strict-origin-when-cross-origin or strict-origin",
        "weak": "Use a more restrictive policy like strict-origin or no-referrer to prevent URL parameter leakage",
        "consider_strict": "Consider using strict-origin for maximum privacy (only sends origin, not full URL path)",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Referrer-Policy header.

    Validation rules:
    - Missing: High severity
    - "strict-origin" or "no-referrer": Good (strongest privacy)
    - Acceptable values (strict-origin-when-cross-origin, same-origin, etc.): Acceptable
    - Bad values (unsafe-url, no-referrer-when-downgrade): Bad

    Note: If multiple values are provided (comma-separated), the first valid value takes precedence.

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

    # Handle comma-separated values (RFC allows fallback values)
    # The first valid value takes precedence
    value_lower = value.strip().lower()
    if "," in value_lower:
        # Split by comma and take the first value
        value_lower = value_lower.split(",")[0].strip()

    # Check for best values (strongest privacy)
    if value_lower in CONFIG["validation"]["best_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Check for acceptable values
    if value_lower in CONFIG["validation"]["acceptable_values"]:
        recommendation = None
        # If it's one of the weaker acceptable values, suggest upgrading
        if value_lower in ["origin-when-cross-origin", "origin"]:
            recommendation = CONFIG["recommendations"]["consider_strict"]

        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": recommendation,
        }

    # Check for bad/weak values
    if value_lower in CONFIG["validation"]["bad_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"][STATUS_BAD],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["weak"],
        }

    # Unknown/invalid value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - unknown value: {value}",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["missing"],
    }
