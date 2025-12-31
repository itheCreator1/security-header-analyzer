"""
COOP Analyzer - Cross-Origin-Opener-Policy for browsing context isolation

Module: sha.analyzers.coop

Purpose:
    Analyzes the Cross-Origin-Opener-Policy (COOP) header which isolates browsing
    contexts from cross-origin windows, protecting against Spectre-like attacks and
    enabling cross-origin isolation when combined with COEP.

Overview:
    The COOP analyzer validates browsing context isolation policies that break
    window.opener references between cross-origin windows. It checks for three values:
    'same-origin' (strict isolation), 'same-origin-allow-popups' (allows popups),
    and 'unsafe-none' (no isolation - bad). COOP prevents cross-origin windows from
    accessing each other's memory and provides Spectre attack mitigation.

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that validates COOP value and determines isolation strength

Validation Rules:
    - Missing header: MEDIUM severity (important for Spectre protection)
    - same-origin: GOOD, info severity (strongest isolation - breaks all cross-origin window access)
    - same-origin-allow-popups: ACCEPTABLE, low severity (allows opening popups, reduced isolation)
    - unsafe-none or invalid: BAD, medium severity (no isolation)

Attack Scenarios Prevented:
    - **Spectre via Cross-Origin Window**: Without COOP, cross-origin windows share
      same browsing context group, allowing Spectre timing attacks to leak data
      across origins through shared process memory
    - **window.opener Exploitation**: Prevents malicious sites opened in new tabs
      from accessing opener window (e.g., changing opener's location for phishing)

Policy Values:
    - **same-origin**: Isolate from ALL cross-origin windows (breaks window.opener
      for cross-origin, enables cross-origin isolation with COEP)
    - **same-origin-allow-popups**: Like same-origin but windows opened by this page
      can retain opener reference (useful if your site opens popups)
    - **unsafe-none**: No isolation (default, unsafe - allows cross-origin window access)

Use Cases:
    - **Enable SharedArrayBuffer**: Requires COOP: same-origin + COEP (cross-origin isolation)
    - **Spectre Protection**: Isolates process memory from cross-origin windows
    - **window.opener Security**: Prevents cross-origin opener manipulation

Deployment Considerations:
    - COOP: same-origin breaks window.opener for cross-origin windows (may affect OAuth flows)
    - same-origin-allow-popups preserves popups but reduces isolation strength
    - Required for full cross-origin isolation (with COEP)

Configuration:
    - best_values: 'same-origin' (full isolation)
    - acceptable_values: 'same-origin-allow-popups' (allows popups)
    - bad_values: 'unsafe-none' (no isolation)

Related Modules:
    - sha.analyzers.__init__ - Registers analyzer in ANALYZER_REGISTRY
    - sha.analyzers.coep - Cross-Origin-Embedder-Policy (companion for SharedArrayBuffer)
    - sha.config - Imports STATUS_* constants
    - docs/headers/coop.md - Detailed COOP documentation

Example Usage:
    >>> from sha.analyzers.coop import analyze
    >>> # Full isolation
    >>> finding = analyze("same-origin")
    >>> finding["status"]
    "good"

    >>> # Allow popups
    >>> finding = analyze("same-origin-allow-popups")
    >>> finding["status"]
    "acceptable"

See Also:
    - docs/headers/coop.md - Technical explanation and attack scenarios
    - docs/headers/coep.md - Companion header for SharedArrayBuffer
    - https://web.dev/why-coop-coep/ - Why COOP+COEP matter
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "cross-origin-opener-policy"

CONFIG = {
    "display_name": "Cross-Origin-Opener-Policy",
    "severity_missing": "medium",
    "description": "Isolates browsing context from cross-origin windows",
    "validation": {
        "best_values": ["same-origin"],
        "acceptable_values": ["same-origin-allow-popups"],
        "bad_values": ["unsafe-none"],
    },
    "messages": {
        STATUS_GOOD: "COOP is properly configured with same-origin isolation",
        STATUS_ACCEPTABLE: "COOP is set to same-origin-allow-popups (acceptable with reduced isolation)",
        STATUS_BAD: "COOP is set to unsafe-none or has invalid value",
        STATUS_MISSING: "COOP header is missing - browsing context is not isolated from cross-origin windows",
    },
    "recommendations": {
        "missing": "Add: Cross-Origin-Opener-Policy: same-origin",
        "weak": "Use same-origin for strongest isolation (unless your application requires popups)",
        "info": "COOP provides protection against Spectre-like attacks by isolating your browsing context.",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Cross-Origin-Opener-Policy header.

    Validation rules:
    - Missing: Medium severity (important for security isolation)
    - same-origin: Good (strongest isolation)
    - same-origin-allow-popups: Acceptable (allows popups, reduced isolation)
    - unsafe-none or other: Bad

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

    # Check for best value (same-origin)
    if value_lower in CONFIG["validation"]["best_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Check for acceptable value (same-origin-allow-popups)
    if value_lower in CONFIG["validation"]["acceptable_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["weak"],
        }

    # Check for explicitly bad value (unsafe-none)
    if value_lower in CONFIG["validation"]["bad_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"][STATUS_BAD],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["missing"],
        }

    # Invalid/unknown value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - unknown value: {value}",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["missing"],
    }
