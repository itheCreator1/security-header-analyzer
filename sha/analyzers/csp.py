"""
CSP Analyzer - Content-Security-Policy header validation

Module: sha.analyzers.csp

Purpose:
    Analyzes the Content-Security-Policy (CSP) header to prevent Cross-Site
    Scripting (XSS) and code injection attacks. Validates directive structure,
    detects dangerous patterns (unsafe-inline, wildcards), and evaluates overall
    policy restrictiveness according to W3C CSP3 specification and OWASP best practices.

Overview:
    The CSP analyzer is the most complex header analyzer due to CSP's directive-based
    structure and numerous security implications. It parses the semicolon-delimited
    policy into directives, checks for dangerous patterns (unsafe-inline, unsafe-eval,
    wildcards), validates source lists, detects nonces/hashes/strict-dynamic, and
    evaluates restrictiveness. The analyzer provides granular feedback on specific
    directives that weaken security and suggests concrete improvements.

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that orchestrates all validation checks and returns
      comprehensive finding with aggregated security warnings

    - parse_csp(value) -> Dict[str, List[str]]
      Parses CSP into directive-value mapping (e.g., {"script-src": ["'self'", "cdn.example.com"]})

    - check_csp_dangerous_patterns(directives, config) -> List[Dict]
      Detects dangerous patterns like unsafe-inline, unsafe-eval, wildcards in script-src.
      Returns list of pattern findings sorted by severity (critical → high → medium)

    - has_nonces_or_hashes(directive_values) -> bool
      Checks for nonces ('nonce-XXX') or hashes ('sha256-XXX') which make unsafe-inline safe

    - has_strict_dynamic(directive_values) -> bool
      Checks for 'strict-dynamic' (modern CSP3 pattern for script whitelisting)

    - check_csp_restrictive_default(directives, config) -> bool
      Validates if default-src is restrictive ('self' or 'none')

    - check_csp_security_directives(directives, config) -> bool
      Checks for important security directives (frame-ancestors, base-uri, form-action)

Validation Rules:
    - Missing header: CRITICAL severity
    - Dangerous patterns found (unsafe-inline without nonces, wildcards): BAD with HIGH severity
    - Unsafe-eval in script-src: BAD with MEDIUM severity
    - Restrictive default + security directives: GOOD, info severity
    - Restrictive default OR 3+ directives: ACCEPTABLE, low severity
    - Weak policy (<3 directives, no restrictive default): ACCEPTABLE, medium severity

Attack Scenarios Prevented:
    - **Cross-Site Scripting (XSS)**: Blocks execution of injected malicious scripts
      by whitelisting allowed script sources
    - **Data Injection**: Prevents attackers from loading malicious resources (images,
      stylesheets, iframes) from untrusted sources
    - **Clickjacking**: frame-ancestors directive controls which sites can embed pages
      in iframes
    - **Form Hijacking**: form-action directive restricts form submission destinations
    - **Base Tag Injection**: base-uri directive prevents attackers from changing base
      URL to redirect relative URLs to malicious sites

Dangerous Patterns:
    - unsafe-inline in script-src: Allows inline scripts, defeating XSS protection
      (OK if nonces/hashes/strict-dynamic present, as they override it)
    - unsafe-eval: Allows eval(), setTimeout(string), Function() constructor
    - Wildcards in script-src (*,data:, http:, https:): Allow scripts from any source
    - Wildcard default-src (*): Allows any resource type from any source

Configuration:
    - dangerous_patterns: Patterns that indicate insecure CSP (unsafe-inline, wildcards)
    - good_patterns: Restrictive defaults ('self', 'none'), security directives
    - security_directives: frame-ancestors, base-uri, form-action

Related Modules:
    - sha.analyzers.__init__ - Registers csp.analyze in ANALYZER_REGISTRY
    - sha.config - Imports STATUS_* constants
    - docs/headers/csp.md - Detailed CSP documentation with examples

Example Usage:
    >>> from sha.analyzers.csp import analyze, parse_csp
    >>> # Strong CSP with restrictive policy
    >>> finding = analyze("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
    >>> finding["status"]
    "good"

    >>> # Parse CSP into directives
    >>> parsed = parse_csp("default-src 'self'; script-src 'self' cdn.example.com")
    >>> parsed["script-src"]
    ["'self'", "cdn.example.com"]

    >>> # Dangerous CSP with unsafe-inline
    >>> finding = analyze("script-src 'unsafe-inline'")
    >>> finding["status"]
    "bad"
    >>> finding["severity"]
    "high"

See Also:
    - docs/headers/csp.md - Technical explanation and attack scenarios
    - docs/architecture/components.md#analyzer-layer - Analyzer architecture
    - https://www.w3.org/TR/CSP3/ - CSP Level 3 specification
"""

from typing import Any, Dict, List, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "content-security-policy"

CONFIG = {
    "display_name": "Content-Security-Policy",
    "severity_missing": "critical",
    "description": "Prevents XSS and other injection attacks by controlling resource loading",
    "validation": {
        # Dangerous patterns that indicate insecure CSP
        "dangerous_patterns": {
            "unsafe_inline_script": {
                "directives": ["script-src", "default-src"],
                "values": ["'unsafe-inline'"],
                "severity": "high",
                "message": "CSP allows unsafe-inline for scripts, defeating XSS protection",
            },
            "unsafe_eval": {
                "directives": ["script-src", "default-src"],
                "values": ["'unsafe-eval'"],
                "severity": "medium",
                "message": "CSP allows unsafe-eval, which can enable some XSS attacks",
            },
            "wildcard_script": {
                "directives": ["script-src"],
                "values": ["*", "data:", "http:", "https:"],
                "severity": "high",
                "message": "CSP allows scripts from any source (wildcard)",
            },
            "wildcard_default": {
                "directives": ["default-src"],
                "values": ["*"],
                "severity": "high",
                "message": "CSP default-src is wildcard, allowing resources from any source",
            },
        },
        # Good patterns that indicate secure CSP
        "good_patterns": {
            "restrictive_default": ["'self'", "'none'"],
            "security_directives": ["frame-ancestors", "base-uri", "form-action"],
        },
    },
    "messages": {
        STATUS_GOOD: "CSP is properly configured with restrictive policy",
        STATUS_ACCEPTABLE: "CSP is present but could be more restrictive",
        STATUS_BAD: "CSP is present but contains dangerous directives",
        STATUS_MISSING: "CSP header is missing - site vulnerable to XSS and injection attacks",
    },
    "recommendations": {
        "missing": "Add a Content-Security-Policy header with restrictive directives",
        "unsafe_inline": "Remove 'unsafe-inline' from script-src and use nonces or hashes instead",
        "unsafe_eval": "Remove 'unsafe-eval' from script-src if possible",
        "too_permissive": "Restrict source lists to specific trusted domains instead of wildcards",
        "add_directives": "Consider adding security directives: frame-ancestors, base-uri, form-action",
        "example": "Example: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    },
}


def parse_csp(value: str) -> Dict[str, List[str]]:
    """
    Parse CSP header value into directives.

    Handles:
    - Empty directives
    - Malformed directives
    - Duplicate directives (last one wins, per CSP spec)
    - Extremely long CSPs (memory limit protection)

    Args:
        value: CSP header value

    Returns:
        Dictionary mapping directive names to lists of values

    Raises:
        ValueError: If CSP is too large (potential DoS)

    Example:
        >>> parse_csp("default-src 'self'; script-src 'self' https://cdn.example.com")
        {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.example.com"]
        }
    """
    # Protect against DoS via extremely long CSP
    MAX_CSP_LENGTH = 10000  # 10KB
    if len(value) > MAX_CSP_LENGTH:
        raise ValueError(f"CSP too long: {len(value)} bytes (max {MAX_CSP_LENGTH})")

    directives = {}

    # Split by semicolon to get individual directives
    for directive_str in value.split(";"):
        directive_str = directive_str.strip()

        # Skip empty directives (e.g., ";;;" or trailing semicolon)
        if not directive_str:
            continue

        # Split directive into name and values
        parts = directive_str.split()

        # Skip if no parts after splitting (e.g., all whitespace)
        if not parts:
            continue

        # Skip if directive has no name (e.g., " 'self'" with no directive name)
        if not parts[0]:
            continue

        directive_name = parts[0].lower()
        directive_values = parts[1:] if len(parts) > 1 else []

        # Handle duplicate directives: last one wins (standard CSP behavior per spec)
        # If directive already exists, it will be overwritten
        directives[directive_name] = directive_values

    return directives


def has_nonces_or_hashes(directive_values: List[str]) -> bool:
    """
    Check if a directive uses nonces or hashes (better than unsafe-inline).

    Args:
        directive_values: List of values for a directive

    Returns:
        True if nonces or hashes are present
    """
    for value in directive_values:
        # Check for nonce: 'nonce-<value>'
        if value.startswith("'nonce-"):
            return True
        # Check for hash: 'sha256-<hash>', 'sha384-<hash>', 'sha512-<hash>'
        if value.startswith(("'sha256-", "'sha384-", "'sha512-")):
            return True
    return False


def has_strict_dynamic(directive_values: List[str]) -> bool:
    """
    Check if a directive uses 'strict-dynamic' (modern best practice).

    Args:
        directive_values: List of values for a directive

    Returns:
        True if 'strict-dynamic' is present
    """
    return "'strict-dynamic'" in directive_values


def check_csp_dangerous_patterns(
    directives: Dict[str, List[str]], config: Dict[str, Any]
) -> List[Dict[str, str]]:
    """
    Check CSP for dangerous patterns.

    Args:
        directives: Parsed CSP directives
        config: CSP configuration

    Returns:
        List of dangerous pattern findings (empty if none found)

    Note:
        'unsafe-inline' is not considered dangerous if nonces, hashes,
        or 'strict-dynamic' are also present, as they override it.
    """
    findings = []
    dangerous_patterns = config["validation"]["dangerous_patterns"]

    # Check each dangerous pattern
    for pattern_name, pattern_config in dangerous_patterns.items():
        for directive_name in pattern_config["directives"]:
            if directive_name in directives:
                directive_values = directives[directive_name]

                # Special handling for unsafe-inline: it's OK if nonces/hashes/strict-dynamic present
                if pattern_name == "unsafe_inline_script":
                    if "'unsafe-inline'" in directive_values:
                        # Check if mitigated by nonces, hashes, or strict-dynamic
                        if has_nonces_or_hashes(directive_values) or has_strict_dynamic(
                            directive_values
                        ):
                            # unsafe-inline is ignored when these are present
                            continue
                        else:
                            findings.append(
                                {
                                    "severity": pattern_config["severity"],
                                    "message": pattern_config["message"],
                                    "recommendation": config["recommendations"].get(
                                        pattern_name.replace("_", "-"),
                                        config["recommendations"]["too_permissive"],
                                    ),
                                }
                            )
                    continue

                # Check if any dangerous value is present
                for dangerous_value in pattern_config["values"]:
                    # Check for exact match or wildcard match
                    if dangerous_value in directive_values:
                        findings.append(
                            {
                                "severity": pattern_config["severity"],
                                "message": pattern_config["message"],
                                "recommendation": config["recommendations"].get(
                                    pattern_name.replace("_", "-"),
                                    config["recommendations"]["too_permissive"],
                                ),
                            }
                        )
                        break

    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

    return findings


def check_csp_restrictive_default(directives: Dict[str, List[str]], config: Dict[str, Any]) -> bool:
    """
    Check if CSP has a restrictive default-src directive.

    Args:
        directives: Parsed CSP directives
        config: CSP configuration

    Returns:
        True if default-src is restrictive
    """
    if "default-src" not in directives:
        return False

    default_values = directives["default-src"]
    restrictive_values = config["validation"]["good_patterns"]["restrictive_default"]

    # Check if default-src contains any restrictive value
    for value in default_values:
        if value in restrictive_values:
            return True

    return False


def check_csp_security_directives(directives: Dict[str, List[str]], config: Dict[str, Any]) -> bool:
    """
    Check if CSP has important security directives.

    Args:
        directives: Parsed CSP directives
        config: CSP configuration

    Returns:
        True if at least one security directive is present
    """
    security_directives = config["validation"]["good_patterns"]["security_directives"]

    for directive in security_directives:
        if directive in directives:
            return True

    return False


def check_missing_directives(directives: Dict[str, List[str]]) -> List[str]:
    """
    Check for common directives that should be explicitly defined.

    Args:
        directives: Parsed CSP directives

    Returns:
        List of missing directive names
    """
    missing = []
    common_directives = ["img-src", "font-src", "connect-src", "style-src"]

    # Only flag as missing if there's no default-src
    has_default = "default-src" in directives

    if not has_default:
        for directive in common_directives:
            if directive not in directives:
                missing.append(directive)

    return missing


def check_overly_broad_domains(directives: Dict[str, List[str]]) -> List[str]:
    """
    Check for overly broad domain allowlists in CSP directives.

    Args:
        directives: Parsed CSP directives

    Returns:
        List of warning messages for overly broad domains
    """
    warnings = []

    for directive_name, directive_values in directives.items():
        for value in directive_values:
            # Skip special keywords
            if value.startswith("'"):
                continue

            # Check for IP addresses (usually bad practice)
            if any(char.isdigit() for char in value) and ("." in value or ":" in value):
                # Simple check for IPv4/IPv6 patterns
                parts = (
                    value.replace("http://", "").replace("https://", "").split("/")[0].split(":")
                )
                if any(
                    part.replace(".", "").replace("[", "").replace("]", "").isdigit()
                    for part in parts
                ):
                    warnings.append(f"{directive_name} contains IP address ({value})")
                    continue

            # Check for wildcard subdomains
            if value.startswith("*."):
                warnings.append(f"{directive_name} contains wildcard subdomain ({value})")

    return warnings


def check_csp_bypasses(directives: Dict[str, List[str]]) -> List[Dict[str, str]]:
    """
    Detect common CSP bypass patterns that attackers exploit.

    This function identifies specific misconfigurations that allow attackers to
    bypass CSP protections, even when a CSP is present. These bypasses are well-
    documented attack techniques used in real-world exploits.

    Args:
        directives: Parsed CSP directives

    Returns:
        List of bypass findings with severity, message, and recommendation

    Bypass Patterns Detected:
        1. JSONP endpoints (Google APIs, AngularJS CDN, etc.)
        2. Angular/AngularJS template injection
        3. User-uploaded content domains
        4. CDNs with JSONP endpoints
        5. Base-uri missing (allows base tag injection)
        6. Object-src missing/permissive (Flash/plugin bypass)
        7. Script-src with 'self' + file upload (stored XSS)
        8. Unsafe-hashes without proper context
        9. Script-src with data: URIs
        10. Dangling markup injection via img-src

    References:
        - CSP Evaluator: https://csp-evaluator.withgoogle.com/
        - CSP Bypass Techniques: https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass
        - Research: "CSP Is Dead, Long Live CSP!" (Weichselbaum et al., 2016)
    """
    bypasses = []

    # Get relevant directives
    script_src = directives.get("script-src", [])
    default_src = directives.get("default-src", [])
    object_src = directives.get("object-src", [])
    base_uri = directives.get("base-uri", [])
    img_src = directives.get("img-src", [])

    # Effective script-src (script-src overrides default-src)
    effective_script_src = script_src if script_src else default_src

    # Known JSONP endpoints that allow CSP bypass
    jsonp_bypass_domains = [
        "accounts.google.com",
        "www.google.com",
        "ajax.googleapis.com",
        "www.googletagmanager.com",
        "www.google-analytics.com",
        "maps.googleapis.com",
        "maps.google.com",
        "www.youtube.com",
        "s.ytimg.com",
        "accounts.youtube.com",
        "oss.maxcdn.com",
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "code.jquery.com",
        "ajax.aspnetcdn.com",
        "angularjs.org",
        "ajax.googleapis.com",  # AngularJS CDN
        "*.cloudflare.com",
        "*.amazonaws.com",
        "*.s3.amazonaws.com",
    ]

    # BYPASS 1-4: Check for known JSONP bypass domains in script-src
    for value in effective_script_src:
        # Normalize value (remove protocols for comparison)
        normalized = value.replace("https://", "").replace("http://", "")
        # Also handle wildcard in value
        normalized_no_wildcard = normalized.replace("*.", "")

        for bypass_domain in jsonp_bypass_domains:
            # Handle wildcards in bypass domain list
            if bypass_domain.startswith("*."):
                # Wildcard pattern - check if domain ends with the pattern
                pattern = bypass_domain[2:]  # Remove *.
                if normalized.endswith(pattern) or normalized.endswith(f".{pattern}") or normalized_no_wildcard.endswith(f".{pattern}"):
                    bypasses.append({
                        "severity": "high",
                        "message": f"CSP allows {value} which has known JSONP endpoints that can bypass CSP",
                        "recommendation": f"Remove {value} from script-src or use 'strict-dynamic' with nonces/hashes instead",
                    })
                    break  # Only report once per domain
            else:
                # Exact or subdomain match
                if normalized_no_wildcard == bypass_domain or normalized_no_wildcard.endswith(f".{bypass_domain}"):
                    bypasses.append({
                        "severity": "high",
                        "message": f"CSP allows {value} which has known JSONP endpoints that can bypass CSP",
                        "recommendation": f"Remove {value} from script-src or use 'strict-dynamic' with nonces/hashes instead",
                    })
                    break  # Only report once per domain

    # BYPASS 5: Check for AngularJS template injection via whitelisted Angular CDN
    angular_domains = ["angularjs.org", "ajax.googleapis.com"]
    for value in effective_script_src:
        normalized = value.replace("https://", "").replace("http://", "").replace("*.", "")
        for angular_domain in angular_domains:
            if normalized == angular_domain or normalized.endswith(f".{angular_domain}"):
                # Check if there's no strict-dynamic (which would prevent this)
                if "'strict-dynamic'" not in effective_script_src:
                    bypasses.append({
                        "severity": "high",
                        "message": f"CSP allows {value} which enables AngularJS template injection attacks",
                        "recommendation": "Use 'strict-dynamic' with nonces, or remove AngularJS CDN from script-src",
                    })
                break

    # BYPASS 6: Missing base-uri allows base tag injection
    if not base_uri:
        # base-uri defaults to * if not specified, allowing base tag injection
        bypasses.append({
            "severity": "medium",
            "message": "CSP missing base-uri directive allows base tag injection attacks",
            "recommendation": "Add base-uri 'self' or base-uri 'none' to prevent base tag injection",
        })

    # BYPASS 7: Missing or permissive object-src (Flash/plugin bypass)
    if not object_src:
        # object-src defaults to default-src, check if that's restrictive
        if "'none'" not in default_src:
            bypasses.append({
                "severity": "medium",
                "message": "CSP missing object-src directive allows Flash/plugin-based bypasses",
                "recommendation": "Add object-src 'none' to block plugins",
            })
    elif "'none'" not in object_src:
        bypasses.append({
            "severity": "medium",
            "message": "CSP object-src is not set to 'none', allowing Flash/plugin-based bypasses",
            "recommendation": "Set object-src to 'none' to block all plugins",
        })

    # BYPASS 8: 'self' with user-uploaded content (stored XSS)
    if "'self'" in effective_script_src:
        # This is a warning, not a definitive bypass (depends on application)
        bypasses.append({
            "severity": "low",
            "message": "CSP allows 'self' in script-src - vulnerable if application allows file uploads or JSONP endpoints on same domain",
            "recommendation": "If application allows user-uploaded content, use 'strict-dynamic' with nonces instead of 'self'",
        })

    # BYPASS 9: data: URIs in script-src (allows inline script bypass)
    if "data:" in effective_script_src:
        bypasses.append({
            "severity": "high",
            "message": "CSP allows data: URIs in script-src, which can bypass CSP protections",
            "recommendation": "Remove data: from script-src - use nonces or hashes for inline scripts instead",
        })

    # BYPASS 10: Dangling markup injection via permissive img-src
    effective_img_src = img_src if img_src else default_src
    if effective_img_src:
        if "*" in effective_img_src:
            # Wildcard allows all external domains - highest risk for dangling markup
            bypasses.append({
                "severity": "medium",
                "message": "CSP img-src allows all external domains (*) - high risk for dangling markup injection to exfiltrate data",
                "recommendation": "Restrict img-src to 'self' or specific trusted domains; never use wildcard *",
            })
        else:
            # Check if img-src allows external domains (potential for dangling markup)
            external_domains = [v for v in effective_img_src if not v.startswith("'") and v not in ("data:", "*")]
            if external_domains:
                bypasses.append({
                    "severity": "low",
                    "message": "CSP img-src allows external domains - potential for dangling markup injection to exfiltrate data",
                    "recommendation": "Restrict img-src to 'self' if possible, or use nonces for dynamic images",
                })

    # BYPASS 11: unsafe-hashes without proper configuration
    if "'unsafe-hashes'" in effective_script_src:
        # unsafe-hashes should only be used with specific hash values
        has_hashes = any(v.startswith(("'sha256-", "'sha384-", "'sha512-")) for v in effective_script_src)
        if not has_hashes:
            bypasses.append({
                "severity": "medium",
                "message": "CSP uses 'unsafe-hashes' without corresponding hash values, which may not work as intended",
                "recommendation": "Remove 'unsafe-hashes' or add specific hash values for inline event handlers",
            })

    # BYPASS 12: script-src-elem and script-src-attr confusion
    script_src_elem = directives.get("script-src-elem", [])
    script_src_attr = directives.get("script-src-attr", [])

    if script_src_elem and "'unsafe-inline'" in script_src_elem:
        if not (has_nonces_or_hashes(script_src_elem) or has_strict_dynamic(script_src_elem)):
            bypasses.append({
                "severity": "high",
                "message": "CSP script-src-elem allows 'unsafe-inline' without nonces/hashes - allows inline script tags",
                "recommendation": "Remove 'unsafe-inline' from script-src-elem or add nonces",
            })

    if script_src_attr and "'unsafe-inline'" not in script_src_attr and not script_src_attr:
        # This is actually good, but worth noting
        pass

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    bypasses.sort(key=lambda x: severity_order.get(x["severity"], 99))

    return bypasses


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Content-Security-Policy header.

    This is the most complex header due to its directive-based structure.

    Validation rules:
    - Missing: Critical severity
    - Contains dangerous patterns (unsafe-inline in script-src, wildcards): Bad
    - Contains unsafe-eval: Acceptable with warning
    - Restrictive policy with security directives: Good

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

    # Parse CSP into directives
    try:
        directives = parse_csp(value)
    except ValueError as e:
        # CSP is malformed or too large
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": "medium",
            "message": f"CSP header is malformed: {e}",
            "actual_value": value,
            "recommendation": "Fix CSP syntax errors and ensure policy is under 10KB",
        }

    # Check for dangerous patterns
    dangerous_findings = check_csp_dangerous_patterns(directives, CONFIG)

    # Check for CSP bypass patterns
    bypass_findings = check_csp_bypasses(directives)

    # Combine dangerous patterns and bypasses, but only HIGH/CRITICAL severity ones for BAD status
    critical_findings = dangerous_findings + [b for b in bypass_findings if b["severity"] in ["critical", "high"]]

    # Keep low/medium severity bypasses for recommendations even if status is GOOD/ACCEPTABLE
    low_severity_bypasses = [b for b in bypass_findings if b["severity"] in ["low", "medium"]]

    if critical_findings:
        # Found dangerous patterns or high-severity bypasses
        severity = critical_findings[0]["severity"]  # Use highest severity
        messages = [f["message"] for f in critical_findings]
        recommendations = [f["recommendation"] for f in critical_findings]

        # Limit to first 3 issues to avoid overwhelming output
        if len(messages) > 3:
            remaining = len(messages) - 3
            messages = messages[:3] + [f"({remaining} more issues detected)"]
            recommendations = recommendations[:3]

        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": severity,
            "message": f"{CONFIG['messages'][STATUS_BAD]}: {'; '.join(messages)}",
            "actual_value": value,
            "recommendation": "; ".join(recommendations),
        }

    # Check for good patterns
    has_restrictive_default = check_csp_restrictive_default(directives, CONFIG)
    has_security_directives = check_csp_security_directives(directives, CONFIG)

    # Check for additional warnings
    missing_directives = check_missing_directives(directives)
    broad_domain_warnings = check_overly_broad_domains(directives)

    # Evaluate overall CSP quality
    if has_restrictive_default and has_security_directives:
        # Build recommendations for warnings even in GOOD status
        recommendations = []

        # Add low-severity bypass recommendations
        for bypass in low_severity_bypasses[:2]:  # Limit to 2
            recommendations.append(bypass["recommendation"])

        if missing_directives:
            recommendations.append(
                f"Consider adding specific directives: {', '.join(missing_directives)}"
            )
        if broad_domain_warnings:
            recommendations.extend(broad_domain_warnings[:2])  # Limit to first 2 warnings

        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD],
            "actual_value": value,
            "recommendation": "; ".join(recommendations) if recommendations else None,
        }
    elif has_restrictive_default or len(directives) >= 3:
        # Has some good directives but could be improved
        recommendations = []

        # Add low-severity bypass recommendations
        for bypass in low_severity_bypasses[:2]:  # Limit to 2
            recommendations.append(bypass["recommendation"])

        if not has_security_directives:
            recommendations.append(CONFIG["recommendations"]["add_directives"])
        if missing_directives:
            recommendations.append(
                f"Consider adding specific directives: {', '.join(missing_directives)}"
            )
        if broad_domain_warnings:
            recommendations.extend(broad_domain_warnings[:2])  # Limit to first 2 warnings

        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE],
            "actual_value": value,
            "recommendation": "; ".join(recommendations) if recommendations else None,
        }
    else:
        # CSP is present but too permissive
        recommendations = [CONFIG["recommendations"]["example"]]
        if missing_directives:
            recommendations.append(
                f"Consider adding specific directives: {', '.join(missing_directives)}"
            )
        if broad_domain_warnings:
            recommendations.extend(broad_domain_warnings[:2])  # Limit to first 2 warnings

        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "medium",
            "message": f"{CONFIG['messages'][STATUS_ACCEPTABLE]} - policy could be more restrictive",
            "actual_value": value,
            "recommendation": "; ".join(recommendations),
        }
