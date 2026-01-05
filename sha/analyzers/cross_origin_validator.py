"""
Cross-Origin Isolation Validator

Module: sha.analyzers.cross_origin_validator

Purpose:
    Validates cross-origin header interactions (COEP + COOP + CORP) to determine
    SharedArrayBuffer eligibility and cross-origin isolation status. This module
    provides cross-header analysis that individual analyzers cannot perform alone.

Overview:
    Cross-origin isolation requires specific combinations of COEP and COOP headers.
    This validator checks for:
    - Full isolation: COEP: require-corp + COOP: same-origin
    - Credentialless isolation: COEP: credentialless + COOP: same-origin
    - SharedArrayBuffer eligibility
    - Partial isolation warnings

Key Functions:
    - validate_cross_origin_isolation(headers) -> Finding or None
      Main validation function that checks cross-header interactions

SharedArrayBuffer Requirements:
    To enable SharedArrayBuffer and high-resolution timers, browsers require:
    1. COEP: require-corp OR credentialless
    2. COOP: same-origin (must be same-origin, not same-origin-allow-popups)

    These headers together create "cross-origin isolated" state.

Isolation Levels Detected:
    - **Full Isolation**: COEP: require-corp + COOP: same-origin
      → SharedArrayBuffer enabled, all cross-origin resources need CORP header

    - **Credentialless Isolation**: COEP: credentialless + COOP: same-origin
      → SharedArrayBuffer enabled, cross-origin resources load without credentials

    - **Partial Isolation**: Only COEP or only COOP set
      → SharedArrayBuffer NOT enabled, warns about incomplete setup

    - **No Isolation**: Neither header set
      → No cross-origin isolation, SharedArrayBuffer disabled

CORP Interaction:
    - With COEP: require-corp, all cross-origin subresources MUST have CORP header
    - With COEP: credentialless, CORP not required (resources load without credentials)
    - CORP analyzer validates resource-level policy separately

Related Modules:
    - sha.analyzers.coep - Cross-Origin-Embedder-Policy analyzer
    - sha.analyzers.coop - Cross-Origin-Opener-Policy analyzer
    - sha.analyzers.corp - Cross-Origin-Resource-Policy analyzer
    - sha.analyzer - Calls this validator after individual analyzers

References:
    - https://web.dev/coop-coep/ - Cross-origin isolation guide
    - https://developer.mozilla.org/en-US/docs/Web/API/crossOriginIsolated
"""

from typing import Any, Dict, Optional

from ..config import STATUS_BAD, STATUS_GOOD


def validate_cross_origin_isolation(headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """
    Validate cross-origin header interactions for SharedArrayBuffer eligibility.

    Checks COEP + COOP combination to determine if the site achieves cross-origin
    isolation state required for SharedArrayBuffer, high-resolution timers, and
    memory measurement APIs.

    Args:
        headers: Dictionary of normalized headers (lowercase keys)

    Returns:
        Finding dictionary if cross-origin headers are present, None otherwise
        Finding keys:
        - header_name: "Cross-Origin Isolation"
        - status: good/acceptable/bad/missing
        - severity: info/low/medium
        - message: Description of isolation status
        - actual_value: Summary of COEP+COOP values
        - recommendation: How to achieve cross-origin isolation

    Isolation States:
        - Full isolation (GOOD): COEP: require-corp + COOP: same-origin
        - Credentialless isolation (GOOD): COEP: credentialless + COOP: same-origin
        - Partial isolation (BAD): Only one header set or incompatible combination
        - No isolation (MISSING): Neither header set

    Example:
        >>> headers = {
        ...     "cross-origin-embedder-policy": "require-corp",
        ...     "cross-origin-opener-policy": "same-origin"
        ... }
        >>> finding = validate_cross_origin_isolation(headers)
        >>> finding["status"]
        "good"
        >>> "SharedArrayBuffer enabled" in finding["message"]
        True
    """
    coep_value = headers.get("cross-origin-embedder-policy")
    coop_value = headers.get("cross-origin-opener-policy")

    # If neither header is present, don't return a finding
    # (individual analyzers already report missing headers)
    if not coep_value and not coop_value:
        return None

    # Normalize values
    coep_normalized = coep_value.strip().lower() if coep_value else None
    coop_normalized = coop_value.strip().lower() if coop_value else None

    # Check for full cross-origin isolation
    # COEP: require-corp + COOP: same-origin
    if coep_normalized == "require-corp" and coop_normalized == "same-origin":
        return {
            "header_name": "Cross-Origin Isolation",
            "status": STATUS_GOOD,
            "severity": "info",
            "message": (
                "Cross-origin isolation ENABLED (full isolation mode): "
                "SharedArrayBuffer, high-resolution timers, and memory measurement APIs are available. "
                "All cross-origin subresources must have Cross-Origin-Resource-Policy header."
            ),
            "actual_value": f"COEP: {coep_value}, COOP: {coop_value}",
            "recommendation": None,
        }

    # Check for credentialless isolation
    # COEP: credentialless + COOP: same-origin
    if coep_normalized == "credentialless" and coop_normalized == "same-origin":
        return {
            "header_name": "Cross-Origin Isolation",
            "status": STATUS_GOOD,
            "severity": "info",
            "message": (
                "Cross-origin isolation ENABLED (credentialless mode): "
                "SharedArrayBuffer, high-resolution timers, and memory measurement APIs are available. "
                "Cross-origin resources load without credentials (no cookies/auth)."
            ),
            "actual_value": f"COEP: {coep_value}, COOP: {coop_value}",
            "recommendation": (
                "Consider using 'require-corp' instead of 'credentialless' for stricter isolation "
                "if your application controls all cross-origin resources."
            ),
        }

    # Partial isolation: COEP set but COOP wrong or missing
    if coep_normalized in ["require-corp", "credentialless"]:
        if not coop_normalized:
            return {
                "header_name": "Cross-Origin Isolation",
                "status": STATUS_BAD,
                "severity": "medium",
                "message": (
                    "Partial cross-origin isolation: COEP is set but COOP is missing. "
                    "SharedArrayBuffer is NOT available. To enable cross-origin isolation, "
                    "add Cross-Origin-Opener-Policy: same-origin."
                ),
                "actual_value": f"COEP: {coep_value}, COOP: (missing)",
                "recommendation": "Add 'Cross-Origin-Opener-Policy: same-origin' to enable cross-origin isolation",
            }
        elif coop_normalized == "same-origin-allow-popups":
            return {
                "header_name": "Cross-Origin Isolation",
                "status": STATUS_BAD,
                "severity": "medium",
                "message": (
                    "Partial cross-origin isolation: COEP is set but COOP is 'same-origin-allow-popups'. "
                    "SharedArrayBuffer is NOT available. COOP must be 'same-origin' (not 'same-origin-allow-popups') "
                    "for cross-origin isolation."
                ),
                "actual_value": f"COEP: {coep_value}, COOP: {coop_value}",
                "recommendation": (
                    "Change Cross-Origin-Opener-Policy to 'same-origin' to enable cross-origin isolation. "
                    "Note: This will break window.opener for popups opened by your site."
                ),
            }
        elif coop_normalized == "unsafe-none":
            return {
                "header_name": "Cross-Origin Isolation",
                "status": STATUS_BAD,
                "severity": "medium",
                "message": (
                    "Incompatible cross-origin isolation: COEP is set but COOP is 'unsafe-none'. "
                    "SharedArrayBuffer is NOT available. COOP must be 'same-origin' for cross-origin isolation."
                ),
                "actual_value": f"COEP: {coep_value}, COOP: {coop_value}",
                "recommendation": "Change Cross-Origin-Opener-Policy to 'same-origin' to enable cross-origin isolation",
            }

    # Partial isolation: COOP set but COEP wrong or missing
    if coop_normalized == "same-origin":
        if not coep_normalized:
            return {
                "header_name": "Cross-Origin Isolation",
                "status": STATUS_BAD,
                "severity": "medium",
                "message": (
                    "Partial cross-origin isolation: COOP is 'same-origin' but COEP is missing. "
                    "SharedArrayBuffer is NOT available. To enable cross-origin isolation, "
                    "add Cross-Origin-Embedder-Policy: require-corp or credentialless."
                ),
                "actual_value": f"COEP: (missing), COOP: {coop_value}",
                "recommendation": (
                    "Add 'Cross-Origin-Embedder-Policy: require-corp' for strict isolation or "
                    "'Cross-Origin-Embedder-Policy: credentialless' for easier deployment"
                ),
            }

    # Both headers present but with incompatible values
    if coep_normalized and coop_normalized:
        return {
            "header_name": "Cross-Origin Isolation",
            "status": STATUS_BAD,
            "severity": "medium",
            "message": (
                "Incompatible cross-origin isolation: COEP and COOP are set but with incompatible values. "
                "SharedArrayBuffer is NOT available. Valid combinations are: "
                "(COEP: require-corp + COOP: same-origin) or (COEP: credentialless + COOP: same-origin)."
            ),
            "actual_value": f"COEP: {coep_value}, COOP: {coop_value}",
            "recommendation": (
                "Use compatible header values: "
                "COEP: require-corp + COOP: same-origin (full isolation) OR "
                "COEP: credentialless + COOP: same-origin (credentialless isolation)"
            ),
        }

    # If we get here, headers are present but don't match expected patterns
    # (e.g., invalid values already flagged by individual analyzers)
    # Return None to avoid duplicate findings
    return None
