"""
X-Content-Type-Options Analyzer - MIME sniffing protection

Module: sha.analyzers.content_type

Purpose:
    Analyzes the X-Content-Type-Options header to prevent MIME-type sniffing
    attacks where browsers ignore declared Content-Type and guess content type
    from file contents, potentially executing malicious scripts.

Overview:
    The X-Content-Type-Options analyzer enforces the simple 'nosniff' directive
    that prevents browsers from MIME-sniffing responses. This is a straightforward
    analyzer with a single valid value but critical importance for preventing
    content-type confusion attacks. Validates presence and correctness of the
    header value using case-insensitive comparison.

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that validates X-Content-Type-Options value is 'nosniff'

Validation Rules:
    - Missing header: MEDIUM-HIGH severity
    - Value == 'nosniff' (case-insensitive): GOOD, info severity
    - Any other value: BAD, medium-high severity

Attack Scenarios Prevented:
    - **MIME Sniffing Attacks**: Prevents browsers from ignoring declared Content-Type
      and guessing content type from file contents, which can turn uploaded images
      into executed HTML/JavaScript
    - **Content-Type Confusion**: Stops attackers from uploading malicious files
      (e.g., polyglot files that are both valid images and HTML) that execute
      as scripts despite being served with image/* Content-Type
    - **XSS via File Upload**: In file upload scenarios, prevents uploaded SVG or
      HTML files from being interpreted as scripts even if served with wrong MIME type

Example Attack Without This Header:
    1. Attacker uploads malicious.jpg containing <script>alert('XSS')</script>
    2. Server serves file with Content-Type: image/jpeg
    3. Without nosniff, browser detects HTML content and executes script
    4. With nosniff, browser respects Content-Type and displays as image

Configuration:
    - required_value: 'nosniff' (only valid value, case-insensitive)

Related Modules:
    - sha.analyzers.__init__ - Registers content_type.analyze in ANALYZER_REGISTRY
    - sha.config - Imports STATUS_* constants
    - docs/headers/X-Content-Type-Options.md - Detailed header documentation

Example Usage:
    >>> from sha.analyzers.content_type import analyze
    >>> # Correct configuration
    >>> finding = analyze("nosniff")
    >>> finding["status"]
    "good"
    >>> finding["severity"]
    "info"

    >>> # Case-insensitive check
    >>> finding = analyze("NOSNIFF")
    >>> finding["status"]
    "good"

    >>> # Wrong value
    >>> finding = analyze("sniff")
    >>> finding["status"]
    "bad"
    >>> finding["severity"]
    "medium-high"

See Also:
    - docs/headers/X-Content-Type-Options.md - Technical explanation and attack scenarios
    - docs/architecture/EXTENSIBILITY.md - Adding new analyzers
    - https://fetch.spec.whatwg.org/#x-content-type-options-header - Specification
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "x-content-type-options"

CONFIG = {
    "display_name": "X-Content-Type-Options",
    "severity_missing": "medium-high",
    "description": "Prevents MIME-type sniffing attacks",
    "validation": {
        "required_value": "nosniff",
    },
    "messages": {
        STATUS_GOOD: "X-Content-Type-Options is properly configured",
        STATUS_ACCEPTABLE: "X-Content-Type-Options is properly configured",
        STATUS_BAD: "X-Content-Type-Options has incorrect value",
        STATUS_MISSING: "X-Content-Type-Options header is missing - browser may perform MIME-type sniffing",
    },
    "recommendations": {
        "missing": "Add: X-Content-Type-Options: nosniff",
        "wrong_value": "Set value to: nosniff",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze X-Content-Type-Options header.

    Validation rules:
    - Missing: Medium-High severity
    - "nosniff": Good
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

    # Incorrect value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - value should be 'nosniff', got '{value}'",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["wrong_value"],
    }
