"""
COEP Analyzer - Cross-Origin-Embedder-Policy for SharedArrayBuffer access

Module: sha.analyzers.coep

Purpose:
    Analyzes the Cross-Origin-Embedder-Policy (COEP) header which enables cross-origin
    isolation, allowing use of powerful features like SharedArrayBuffer and high-resolution
    timers. Validates require-corp (strict) and credentialless (lenient) policies.

Overview:
    The COEP analyzer validates cross-origin isolation policies required for accessing
    SharedArrayBuffer (multi-threaded memory) and precise performance timers. It checks
    for two valid values: 'require-corp' (strict - requires CORP on all subresources)
    and 'credentialless' (lenient - loads resources without credentials). COEP is
    optional unless your application needs SharedArrayBuffer for performance-critical
    features (WebAssembly, video processing, cryptography).

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that validates COEP value and categorizes policy strength

Validation Rules:
    - Missing header: MEDIUM severity (only needed for SharedArrayBuffer/precise timers)
    - require-corp: GOOD, info severity (strongest cross-origin isolation)
    - credentialless: ACCEPTABLE, low severity (newer, less strict alternative)
    - Invalid/unknown value: BAD, medium severity

Purpose and Use Cases:
    COEP enables "cross-origin isolated" state which unlocks:
    - **SharedArrayBuffer**: Multi-threaded shared memory (required for performance-
      critical WebAssembly, video encoding, scientific computing)
    - **High-Resolution Timers**: performance.now() with microsecond precision
      (normally degraded to 100μs for Spectre mitigation)
    - **Memory Measurement API**: Precise memory usage tracking

Attack Prevention (Spectre Mitigation):
    COEP prevents Spectre-like timing attacks by ensuring embedded resources either:
    1. Explicitly opt-in with CORP header (require-corp mode)
    2. Load without credentials (credentialless mode)

    This prevents attackers from using timing side-channels to read cross-origin data.

Policy Values:
    - **require-corp**: All cross-origin resources must have Cross-Origin-Resource-Policy
      header (strict but may break third-party resources)
    - **credentialless**: Cross-origin resources load without cookies/auth (easier
      deployment, less strict)

Deployment Considerations:
    - Most sites DON'T need COEP (only if using SharedArrayBuffer)
    - require-corp can break third-party embeds (ads, analytics) if they lack CORP header
    - credentialless is easier to deploy but requires newer browser support
    - COEP requires COOP: same-origin for full cross-origin isolation

Configuration:
    - best_values: 'require-corp' (strongest isolation)
    - acceptable_values: 'credentialless' (newer, easier deployment)

Related Modules:
    - sha.analyzers.__init__ - Registers analyzer in ANALYZER_REGISTRY
    - sha.analyzers.coop - Cross-Origin-Opener-Policy (required companion)
    - sha.analyzers.corp - Cross-Origin-Resource-Policy (required for require-corp)
    - sha.config - Imports STATUS_* constants
    - docs/headers/COEP.md - Detailed COEP documentation

Example Usage:
    >>> from sha.analyzers.coep import analyze
    >>> # Strict cross-origin isolation
    >>> finding = analyze("require-corp")
    >>> finding["status"]
    "good"

    >>> # Lenient isolation
    >>> finding = analyze("credentialless")
    >>> finding["status"]
    "acceptable"

See Also:
    - docs/headers/COEP.md - Technical explanation and use cases
    - docs/headers/COOP.md - Companion header for full isolation
    - https://web.dev/coop-coep/ - Cross-origin isolation guide
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

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
