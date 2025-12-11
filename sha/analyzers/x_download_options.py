"""
X-Download-Options Analyzer - IE download security (legacy)

Module: sha.analyzers.x_download_options

Purpose:
    Analyzes the X-Download-Options header which prevents Internet Explorer (IE) from
    executing downloaded HTML files in the site's security context. Legacy header
    specific to IE/Edge (pre-Chromium) to prevent "Open" button security issues.

Overview:
    The X-Download-Options analyzer validates the IE-specific 'noopen' directive that
    prevents downloads from being opened directly in the browser security context. This
    simple analyzer checks for a single valid value ('noopen', case-insensitive) and
    flags missing or incorrect values. While IE is deprecated (June 2022), the header
    remains useful for defense-in-depth and legacy browser support.

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that validates X-Download-Options is set to 'noopen'

Validation Rules:
    - Missing header: LOW severity (IE-specific, browser deprecated)
    - noopen (case-insensitive): GOOD, info severity
    - Any other value: BAD, low severity
    - Empty value: BAD, low severity

Attack Scenario Prevented:
    - **IE Download Context Execution**: In IE, when users download HTML files, they
      can click "Open" button which executes the HTML in the SITE'S security context
      (not local file context), granting access to site cookies/localStorage
    - **Download-and-Execute XSS**: Attacker uploads malicious HTML to file upload
      feature, victim downloads and clicks "Open", HTML executes with site privileges

IE Deprecation Status:
    - Internet Explorer 11 reached end-of-life June 15, 2022
    - IE mode in Edge continues for enterprise compatibility
    - However, header still valuable for:
      * Defense-in-depth strategy
      * Legacy enterprise environments
      * Security scanning compliance

Configuration:
    - required_value: 'noopen' (only valid value, case-insensitive)

Related Modules:
    - sha.analyzers.__init__ - Registers analyzer in ANALYZER_REGISTRY
    - sha.config - Imports STATUS_* constants
    - docs/headers/X-Download-Options.md - Detailed IE security documentation

Example Usage:
    >>> from sha.analyzers.x_download_options import analyze
    >>> # Correct configuration
    >>> finding = analyze("noopen")
    >>> finding["status"]
    "good"

    >>> # Wrong value
    >>> finding = analyze("open")
    >>> finding["status"]
    "bad"

See Also:
    - docs/headers/X-Download-Options.md - IE-specific attack scenarios
    - docs/architecture/EXTENSIBILITY.md - Adding new analyzers
"""

from typing import Any, Dict, Optional

from ..config import STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "x-download-options"

CONFIG = {
    "display_name": "X-Download-Options",
    "severity_missing": "low",
    "description": "Prevents IE from executing downloads in site context",
    "validation": {
        "required_value": "noopen",
    },
    "messages": {
        STATUS_GOOD: "X-Download-Options is properly configured",
        STATUS_BAD: "X-Download-Options has incorrect value",
        STATUS_MISSING: "X-Download-Options header is missing - IE may execute downloads in site context",
    },
    "recommendations": {
        "missing": "Add: X-Download-Options: noopen",
        "wrong_value": "Set value to: noopen",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze X-Download-Options header.

    Validation rules:
    - Missing: Low severity (IE-specific, legacy)
    - "noopen": Good
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

    value_lower = value.strip().lower()

    # Check for correct value
    if value_lower == CONFIG["validation"]["required_value"]:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Empty value
    if not value_lower:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": f"{CONFIG['messages'][STATUS_BAD]} - empty value",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["wrong_value"],
        }

    # Incorrect value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - "
        f"unknown value '{value}', should be 'noopen'",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["wrong_value"],
    }
