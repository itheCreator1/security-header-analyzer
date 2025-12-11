"""
CORP Analyzer - Cross-Origin-Resource-Policy for resource protection

Module: sha.analyzers.corp

Purpose:
    Analyzes the Cross-Origin-Resource-Policy (CORP) header which controls whether
    resources can be loaded by other origins, protecting against Spectre-like attacks
    and unauthorized resource inclusion.

Overview:
    The CORP analyzer validates resource loading policies that prevent cross-origin
    inclusion. It checks for three values: 'same-origin' (strictest), 'same-site'
    (allows related domains), and 'cross-origin' (permissive - bad). CORP provides
    opt-in protection for images, scripts, stylesheets, and other resources against
    Spectre timing attacks and unauthorized embedding.

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that validates CORP value and categorizes protection level

Validation Rules:
    - Missing header: MEDIUM severity (resources loadable by any origin)
    - same-origin: GOOD, info severity (only same origin can load resource)
    - same-site: ACCEPTABLE, low severity (allows same-site access, e.g., subdomain.example.com)
    - cross-origin or invalid: BAD, medium severity (allows cross-origin loading - defeats protection)

Attack Scenarios Prevented:
    - **Spectre via Cross-Origin Resource**: Without CORP, attackers can <img> include
      your resources and use Spectre timing attacks to infer content (pixel data, script
      code) across process boundaries
    - **Unauthorized Resource Embedding**: Prevents hotlinking and resource theft where
      other sites embed your images/scripts without permission
    - **Cross-Site Data Leakage**: With CORP, browsers block cross-origin loads that
      could leak data via timing side-channels

Policy Values:
    - **same-origin**: Only same origin (https://example.com) can load resource
    - **same-site**: Same site including subdomains (*.example.com) can load
    - **cross-origin**: Any origin can load (defeats CORP protection - BAD)

Use Cases:
    - **API Responses**: Set same-origin on JSON/API responses to prevent cross-origin reads
    - **Sensitive Images**: Protect user profile pictures from unauthorized embedding
    - **Internal Scripts**: Prevent third parties from loading your application code
    - **COEP Compliance**: Required when using COEP: require-corp for cross-origin resources

Deployment Considerations:
    - CORP same-origin breaks CDN/third-party loading (use same-site for CDNs on subdomain)
    - Public assets (fonts, libraries) may need cross-origin for legitimate sharing
    - Required for cross-origin isolation with COEP: require-corp

Configuration:
    - best_values: 'same-origin' (strictest resource protection)
    - acceptable_values: 'same-site' (allows same-site subdomains)
    - bad_values: 'cross-origin' (allows all origins - defeats protection)

Related Modules:
    - sha.analyzers.__init__ - Registers analyzer in ANALYZER_REGISTRY
    - sha.analyzers.coep - Cross-Origin-Embedder-Policy (requires CORP on subresources)
    - sha.config - Imports STATUS_* constants
    - docs/headers/CORP.md - Detailed CORP documentation

Example Usage:
    >>> from sha.analyzers.corp import analyze
    >>> # Strict resource protection
    >>> finding = analyze("same-origin")
    >>> finding["status"]
    "good"

    >>> # Allow same-site
    >>> finding = analyze("same-site")
    >>> finding["status"]
    "acceptable"

See Also:
    - docs/headers/CORP.md - Technical explanation and attack scenarios
    - docs/headers/COEP.md - COEP requires CORP on cross-origin resources
    - https://resourcepolicy.fyi/ - CORP explainer
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "cross-origin-resource-policy"

CONFIG = {
    "display_name": "Cross-Origin-Resource-Policy",
    "severity_missing": "medium",
    "description": "Controls whether resources can be loaded cross-origin",
    "validation": {
        "best_values": ["same-origin"],
        "acceptable_values": ["same-site"],
        "bad_values": ["cross-origin"],
    },
    "messages": {
        STATUS_GOOD: "CORP is properly configured with same-origin restriction",
        STATUS_ACCEPTABLE: "CORP is set to same-site (acceptable for related sites)",
        STATUS_BAD: "CORP is set to cross-origin or has invalid value",
        STATUS_MISSING: "CORP header is missing - resources can be loaded by any origin",
    },
    "recommendations": {
        "missing": "Add: Cross-Origin-Resource-Policy: same-origin",
        "weak": "Use same-origin for strongest protection (unless resources need to be shared with same-site origins)",
        "info": "CORP protects against certain cross-origin attacks like Spectre by controlling resource loading.",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Cross-Origin-Resource-Policy header.

    Validation rules:
    - Missing: Medium severity (important for resource protection)
    - same-origin: Good (most restrictive)
    - same-site: Acceptable (allows same-site access)
    - cross-origin or other: Bad (allows cross-origin access)

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

    # Check for acceptable value (same-site)
    if value_lower in CONFIG["validation"]["acceptable_values"]:
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["weak"],
        }

    # Check for explicitly bad value (cross-origin)
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
