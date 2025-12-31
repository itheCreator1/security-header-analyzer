"""
X-Frame-Options Analyzer - Clickjacking protection validation

Module: sha.analyzers.xframe

Purpose:
    Analyzes the X-Frame-Options header to prevent clickjacking attacks by controlling
    whether the page can be embedded in frames/iframes. Validates the three allowed
    values (DENY, SAMEORIGIN, ALLOW-FROM) and detects deprecated configurations.

Overview:
    The X-Frame-Options analyzer enforces clickjacking protection by validating frame
    embedding policies. It performs case-insensitive value checking, detects the
    deprecated ALLOW-FROM directive, and recommends modern CSP frame-ancestors as
    a replacement. The analyzer is straightforward due to the header's simple
    three-value syntax but critical for preventing UI redressing attacks.

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that validates X-Frame-Options value against allowed
      options (DENY, SAMEORIGIN) and deprecated options (ALLOW-FROM)

Validation Rules:
    - Missing header: HIGH severity
    - DENY: GOOD (maximum protection - no embedding allowed)
    - SAMEORIGIN: ACCEPTABLE, low severity (allows same-origin embedding)
    - ALLOW-FROM: BAD, high severity (deprecated, use CSP frame-ancestors instead)
    - Unknown value: BAD, high severity

Attack Scenarios Prevented:
    - **Clickjacking (UI Redressing)**: Prevents attackers from embedding the page
      in a malicious iframe and overlaying transparent elements to trick users into
      clicking on hidden buttons/links (e.g., "Like" button, fund transfer)
    - **Frame-Based Session Hijacking**: Prevents embedding in iframes that could
      intercept user interactions or steal session tokens
    - **Phishing via Iframe Embedding**: Stops attackers from embedding legitimate
      pages in phishing sites to increase credibility

Configuration:
    - best_values: DENY (no framing allowed)
    - acceptable_values: SAMEORIGIN (same-origin framing allowed)
    - deprecated_values: ALLOW-FROM (replaced by CSP frame-ancestors)

Related Modules:
    - sha.analyzers.__init__ - Registers xframe.analyze in ANALYZER_REGISTRY
    - sha.config - Imports STATUS_* constants
    - docs/headers/X-Frame-Options.md - Detailed header documentation

Example Usage:
    >>> from sha.analyzers.xframe import analyze
    >>> # Best practice - no framing
    >>> finding = analyze("DENY")
    >>> finding["status"]
    "good"
    >>> finding["severity"]
    "info"

    >>> # Acceptable - same-origin framing
    >>> finding = analyze("SAMEORIGIN")
    >>> finding["status"]
    "acceptable"
    >>> finding["severity"]
    "low"

    >>> # Deprecated ALLOW-FROM
    >>> finding = analyze("ALLOW-FROM https://example.com")
    >>> finding["status"]
    "bad"
    >>> finding["severity"]
    "high"

See Also:
    - docs/headers/X-Frame-Options.md - Technical explanation and attack scenarios
    - docs/headers/csp.md - Modern frame-ancestors directive as replacement
    - https://tools.ietf.org/html/rfc7034 - X-Frame-Options specification
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "x-frame-options"

CONFIG = {
    "display_name": "X-Frame-Options",
    "severity_missing": "high",
    "description": "Prevents clickjacking attacks by controlling iframe embedding",
    "validation": {
        "best_values": ["deny"],
        "acceptable_values": ["sameorigin"],
        "deprecated_values": ["allow-from"],
    },
    "messages": {
        STATUS_GOOD: "X-Frame-Options is properly configured to prevent clickjacking",
        STATUS_ACCEPTABLE: "X-Frame-Options allows same-origin framing (acceptable for most use cases)",
        STATUS_BAD: "X-Frame-Options is using deprecated or insecure configuration",
        STATUS_MISSING: "X-Frame-Options header is missing - site vulnerable to clickjacking attacks",
    },
    "recommendations": {
        "missing": "Add: X-Frame-Options: DENY (or SAMEORIGIN if iframe embedding is needed)",
        "allow_from": "Replace deprecated ALLOW-FROM with Content-Security-Policy frame-ancestors directive",
        "use_deny": "Consider using DENY instead of SAMEORIGIN for maximum protection",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
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

    value_upper = value.strip().upper()

    # DENY - Best practice
    if value_upper == "DENY":
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # SAMEORIGIN - Acceptable
    if value_upper == "SAMEORIGIN":
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["use_deny"],
        }

    # ALLOW-FROM - Deprecated
    if value_upper.startswith("ALLOW-FROM"):
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": f"{CONFIG['messages'][STATUS_BAD]} - ALLOW-FROM is deprecated",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["allow_from"],
        }

    # Unknown value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - unknown value: {value}",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["missing"],
    }
