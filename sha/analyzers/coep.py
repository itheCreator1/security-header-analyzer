"""
Cross-Origin-Embedder-Policy (COEP) Header Analyzer.

This module contains configuration and analysis logic for the
Cross-Origin-Embedder-Policy header which enables cross-origin isolation
and allows use of powerful features like SharedArrayBuffer.
"""

from typing import Dict, Optional, Any

from ..config import STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING


HEADER_KEY = "cross-origin-embedder-policy"

CONFIG = {
    "display_name": "Cross-Origin-Embedder-Policy",
    "severity_missing": "medium",
    "description": "Enables cross-origin isolation for powerful features like SharedArrayBuffer",
    "validation": {
        "best_values": ["require-corp"],
        "acceptable_values": ["credentialless"],
    },
    "messages": {
        STATUS_GOOD: "COEP is properly configured with require-corp",
        STATUS_ACCEPTABLE: "COEP is set to credentialless (acceptable but less strict)",
        STATUS_BAD: "COEP has invalid or unsafe value",
        STATUS_MISSING: "COEP header is missing - cannot use SharedArrayBuffer and high-resolution timers",
    },
    "recommendations": {
        "missing": "Add: Cross-Origin-Embedder-Policy: require-corp",
        "weak": "Use require-corp for stronger cross-origin isolation",
        "info": "COEP is required for using SharedArrayBuffer and precise timers. Only add if your application needs these features.",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Cross-Origin-Embedder-Policy header.

    Validation rules:
    - Missing: Medium severity (only needed for specific features)
    - require-corp: Good (strongest isolation)
    - credentialless: Acceptable (newer alternative)
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
            "recommendation": CONFIG["recommendations"]["info"],
        }

    value_lower = value.strip().lower()

    # Check for best value (require-corp)
    if value_lower in CONFIG["validation"]["best_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Check for acceptable value (credentialless)
    if value_lower in CONFIG["validation"]["acceptable_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["weak"],
        }

    # Invalid value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": "medium",
        "message": f"{CONFIG['messages'][STATUS_BAD]}: {value}",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["missing"],
    }
