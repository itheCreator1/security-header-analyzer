"""
X-Permitted-Cross-Domain-Policies Analyzer - Flash/PDF policy control

Module: sha.analyzers.x_permitted_cross_domain_policies

Purpose:
    Analyzes the X-Permitted-Cross-Domain-Policies header to control whether Adobe
    Flash Player and PDF viewers can load cross-domain policy files (crossdomain.xml).
    Validates policy values to prevent unauthorized cross-origin data access by Flash/PDF.

Overview:
    The X-Permitted-Cross-Domain-Policies analyzer enforces restrictions on Flash and
    PDF cross-domain policy file loading. It validates five possible values (none,
    master-only, all, by-content-type, by-ftp-filename) and categorizes them by
    security risk. While Flash is deprecated (EOL 2020), this header still applies
    to PDF viewers in some browsers and should be set to 'none' for defense-in-depth.

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that validates policy value and assigns severity based
      on permissiveness (none=good, master-only=acceptable, all=bad/high)

Validation Rules:
    - Missing header: MEDIUM severity (Flash/PDF may load policy files)
    - none: GOOD (completely prohibits policy file loading)
    - master-only: ACCEPTABLE, low severity (allows /crossdomain.xml only)
    - all: BAD, HIGH severity (allows policy files anywhere - very insecure)
    - by-content-type: BAD, MEDIUM severity (too permissive)
    - by-ftp-filename: BAD, MEDIUM severity (legacy, insecure)
    - Unknown value: BAD, MEDIUM severity

Attack Scenarios Prevented:
    - **Flash Cross-Domain Data Theft** (legacy): Flash could load policy files
      from arbitrary paths, allowing cross-origin data access if attacker uploads
      malicious crossdomain.xml to user-writable directories
    - **PDF Cross-Origin Requests**: Some PDF viewers respect crossdomain.xml,
      allowing embedded PDFs to make cross-origin requests if policy permits
    - **Policy File Injection**: With 'all' value, attackers upload policy files
      to any writable path (/uploads/crossdomain.xml) to bypass same-origin policy

Policy Value Meanings:
    - **none**: No policy files allowed (maximum security)
    - **master-only**: Only /crossdomain.xml at domain root (Adobe default)
    - **all**: Policy files anywhere on domain (VERY DANGEROUS)
    - **by-content-type**: Policy files with specific MIME type (deprecated)
    - **by-ftp-filename**: FTP-specific policy files (legacy, insecure)

Legacy Context:
    - Flash Player reached end-of-life December 31, 2020
    - However, header still relevant for:
      * PDF viewers (Adobe Reader, browser PDF viewers)
      * Defense-in-depth (prevent future plugin vulnerabilities)
      * Compliance/security scanning (expected by tools)
    - Best practice: Set to 'none' even post-Flash

Configuration:
    - best_value: 'none' (prohibit all policy files)
    - acceptable_value: 'master-only' (allow /crossdomain.xml only)
    - bad_values: 'all' (high severity), 'by-content-type' (medium),
      'by-ftp-filename' (medium)

Related Modules:
    - sha.analyzers.__init__ - Registers analyzer in ANALYZER_REGISTRY
    - sha.config - Imports STATUS_* constants
    - docs/headers/X-Permitted-Cross-Domain-Policies.md - Detailed documentation

Example Usage:
    >>> from sha.analyzers.x_permitted_cross_domain_policies import analyze
    >>> # Best practice - prohibit all
    >>> finding = analyze("none")
    >>> finding["status"]
    "good"

    >>> # Dangerous - allows anywhere
    >>> finding = analyze("all")
    >>> finding["status"]
    "bad"
    >>> finding["severity"]
    "high"

See Also:
    - docs/headers/X-Permitted-Cross-Domain-Policies.md - Attack scenarios and history
    - docs/architecture/extensibility-guide.md - Adding new analyzers
    - https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain.html
"""

from typing import Any, Dict, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "x-permitted-cross-domain-policies"

CONFIG = {
    "display_name": "X-Permitted-Cross-Domain-Policies",
    "severity_missing": "medium",
    "description": "Controls Flash/PDF cross-domain policy file access",
    "validation": {
        "best_value": "none",
        "acceptable_value": "master-only",
        "bad_values": {
            "all": "high",
            "by-content-type": "medium",
            "by-ftp-filename": "medium",
        },
    },
    "messages": {
        STATUS_GOOD: "X-Permitted-Cross-Domain-Policies is properly configured",
        STATUS_ACCEPTABLE: "X-Permitted-Cross-Domain-Policies allows master policy file only",
        STATUS_BAD: "X-Permitted-Cross-Domain-Policies has insecure configuration",
        STATUS_MISSING: "X-Permitted-Cross-Domain-Policies header is missing - Flash/PDF may load policy files",
    },
    "recommendations": {
        "missing": "Add: X-Permitted-Cross-Domain-Policies: none",
        "bad_value": "Set to: X-Permitted-Cross-Domain-Policies: none",
        "acceptable": "Consider setting to: none for maximum security",
    },
}


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze X-Permitted-Cross-Domain-Policies header.

    Validation rules:
    - Missing: Medium severity
    - "none": Good (completely prohibits policy files)
    - "master-only": Acceptable (allows /crossdomain.xml only)
    - "all": Bad, High severity (allows policy files anywhere)
    - "by-content-type": Bad, Medium severity (too permissive)
    - "by-ftp-filename": Bad, Medium severity (legacy, insecure)
    - Unknown values: Bad, Medium severity

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
    value_lower = value.strip().lower()

    # Best practice: none
    if value_lower == CONFIG["validation"]["best_value"]:
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": None,
        }

    # Acceptable: master-only
    if value_lower == CONFIG["validation"]["acceptable_value"]:
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": f"{CONFIG['messages'][STATUS_ACCEPTABLE]} - "
            f"consider using 'none' for maximum security",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["acceptable"],
        }

    # Empty value
    if not value_lower:
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": CONFIG["severity_missing"],
            "message": f"{CONFIG['messages'][STATUS_BAD]} - empty value",
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["bad_value"],
        }

    # Check for known bad values with specific severities
    if value_lower in CONFIG["validation"]["bad_values"]:
        severity = CONFIG["validation"]["bad_values"][value_lower]
        if value_lower == "all":
            message = (
                f"{CONFIG['messages'][STATUS_BAD]} - "
                f"'all' allows policy files from anywhere (very insecure)"
            )
        elif value_lower == "by-content-type":
            message = f"{CONFIG['messages'][STATUS_BAD]} - " f"'by-content-type' is too permissive"
        else:  # by-ftp-filename
            message = (
                f"{CONFIG['messages'][STATUS_BAD]} - " f"'by-ftp-filename' is legacy and insecure"
            )

        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": severity,
            "message": message,
            "actual_value": value,
            "recommendation": CONFIG["recommendations"]["bad_value"],
        }

    # Unknown value
    return {
        "header_name": header_name,
        "status": STATUS_BAD,
        "severity": CONFIG["severity_missing"],
        "message": f"{CONFIG['messages'][STATUS_BAD]} - " f"unknown value '{value}'",
        "actual_value": value,
        "recommendation": CONFIG["recommendations"]["bad_value"],
    }
