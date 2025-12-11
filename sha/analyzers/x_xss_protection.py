"""
X-XSS-Protection Analyzer - Deprecated XSS filter control (recommend disabling)

Module: sha.analyzers.x_xss_protection

Purpose:
    Analyzes the X-XSS-Protection header which controlled legacy browser XSS filters.
    IMPORTANT: This header is DEPRECATED. Modern recommendation is X-XSS-Protection: 0
    to explicitly disable XSS auditors which can introduce vulnerabilities.

Overview:
    The X-XSS-Protection analyzer validates the deprecated XSS filter header. While
    originally designed to enable browser XSS protection, research showed these filters
    could be weaponized to CREATE vulnerabilities (XSS auditor bypass attacks). Modern
    best practice is X-XSS-Protection: 0 to disable filters and rely on Content-Security-
    Policy instead. The analyzer rates value '0' as GOOD (explicit disable), '1; mode=block'
    as ACCEPTABLE (legacy), and plain '1' as BAD (dangerous).

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that validates XSS filter configuration and recommends
      disabling (value=0) per modern security best practices

Validation Rules:
    - Missing header: LOW severity (acceptable if using CSP)
    - 0: GOOD (modern recommendation - explicitly disable XSS auditor)
    - 1; mode=block: ACCEPTABLE, low severity (legacy approach, outdated)
    - 1: BAD, MEDIUM severity (dangerous - enables filter without blocking)
    - Unknown values: BAD, low severity

Attack Scenarios (Why Filters Were Deprecated):
    - **XSS Filter Bypass Attacks**: Attackers crafted URLs that trigger XSS filters
      to block legitimate scripts, breaking page functionality or creating new XSS vectors
    - **Selective Script Blocking**: Attackers use filters to block specific scripts
      (like CSP nonces) while allowing their malicious payload
    - **Information Leakage**: Filters can leak information about page content through
      timing attacks or side-channel observations

Historical Context:
    - 2010-2018: Browsers implemented XSS auditors (X-XSS-Protection: 1)
    - 2018-2019: Research revealed filters could be weaponized (XSLeaks)
    - 2019: Chrome removed XSS Auditor entirely
    - 2020: Edge removed XSS filter
    - Modern: All major browsers removed/never had XSS auditors
    - Recommendation: Explicitly set to 0, use CSP for XSS protection

Configuration:
    - best_value: '0' (disable XSS auditor - modern recommendation)
    - acceptable_value: '1; mode=block' (legacy mode, outdated)
    - bad_value: '1' (enables filter without blocking - dangerous)

Related Modules:
    - sha.analyzers.__init__ - Registers analyzer in ANALYZER_REGISTRY
    - sha.analyzers.csp - Modern XSS protection via Content-Security-Policy
    - sha.config - Imports STATUS_* constants
    - docs/headers/X-XSS-Protection.md - Detailed deprecation history

Example Usage:
    >>> from sha.analyzers.x_xss_protection import analyze
    >>> # Modern recommendation - explicitly disable
    >>> finding = analyze("0")
    >>> finding["status"]
    "good"

    >>> # Dangerous - enables filter without blocking
    >>> finding = analyze("1")
    >>> finding["status"]
    "bad"
    >>> finding["severity"]
    "medium"

See Also:
    - docs/headers/X-XSS-Protection.md - Why filters were deprecated
    - docs/headers/CSP.md - Modern XSS protection replacement
    - https://owasp.org/www-community/attacks/xss/
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
        "message": f"{CONFIG['messages'][STATUS_BAD]} - " f"unknown value '{value}'",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["bad_value"],
    }
