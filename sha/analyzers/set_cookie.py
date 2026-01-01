"""
Set-Cookie Analyzer - Cookie security attributes validation

Module: sha.analyzers.set_cookie

Purpose:
    Analyzes Set-Cookie headers to validate security attributes (Secure, HttpOnly,
    SameSite) that protect cookies from theft and misuse. Handles multiple cookies,
    parses attributes, and reports worst-case security status across all cookies.

Overview:
    The Set-Cookie analyzer is unique in handling multiple header instances (HTTP
    allows multiple Set-Cookie headers in one response). It parses each cookie's
    attributes (Secure, HttpOnly, SameSite, Max-Age, Domain, Path), validates
    security properties, and aggregates findings across all cookies. The analyzer
    detects missing security attributes, validates SameSite=None requires Secure,
    and warns about excessive Max-Age durations. Special handling for list-valued
    headers from fetcher.py.

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that handles single cookie string, list of cookies,
      or None. Returns aggregated finding with worst security status.

    - parse_set_cookie(value) -> Dict[str, Any]
      Parses single Set-Cookie header into attributes (cookie_name, cookie_value,
      secure, httponly, samesite, max_age, expires, domain, path)

    - _analyze_single_cookie(value) -> Dict[str, Any]
      Internal function analyzing one cookie and returning per-cookie results
      (status, severity, issues, recommendations)

Validation Rules:
    - Missing header: INFO severity (not all responses set cookies - optional)
    - Missing Secure: BAD, HIGH severity (cookie sent over HTTP - session hijack)
    - Missing HttpOnly: BAD, HIGH severity (XSS can steal cookie)
    - Missing SameSite: BAD, MEDIUM severity (CSRF attacks possible)
    - SameSite=None without Secure: BAD, MEDIUM severity (invalid configuration)
    - Max-Age >1 year: ACCEPTABLE, LOW severity (warn about excessive duration)
    - Secure + HttpOnly + SameSite=Strict: GOOD, info severity
    - Secure + HttpOnly + SameSite=Lax: ACCEPTABLE, low severity

Attack Scenarios Prevented:
    - **Session Hijacking (Secure)**: Without Secure attribute, cookies sent over
      HTTP can be intercepted by network attackers (MITM, public Wi-Fi)
    - **Cookie Theft via XSS (HttpOnly)**: Without HttpOnly, JavaScript can access
      cookies (document.cookie), allowing XSS attacks to steal session tokens
    - **Cross-Site Request Forgery (SameSite)**: Without SameSite, browsers send
      cookies on cross-site requests, allowing CSRF attacks where attacker sites
      make authenticated requests to victim site
    - **SameSite=None Misconfiguration**: SameSite=None without Secure is rejected
      by browsers, breaking third-party cookie functionality

Cookie Attribute Details:
    - **Secure**: Cookie only sent over HTTPS connections (required for security)
    - **HttpOnly**: Cookie not accessible via JavaScript document.cookie (XSS protection)
    - **SameSite**:
      * Strict: Never sent on cross-site requests (maximum CSRF protection)
      * Lax: Sent on top-level navigations only (good balance)
      * None: Sent on all cross-site requests (requires Secure attribute)
    - **Max-Age**: Cookie lifetime in seconds (warn if >1 year for sensitive data)
    - **Domain**: Cookie scope (security implications, not validated here)
    - **Path**: URL path scope (security implications, not validated here)

Configuration:
    - required_secure: True (Secure attribute required)
    - required_httponly: True (HttpOnly attribute required)
    - max_age_warning_threshold: 31536000 (1 year - warn if exceeded)
    - samesite_strict: Strictest policy (recommended for authentication cookies)
    - samesite_lax: Good balance (acceptable for most use cases)
    - samesite_none: Requires Secure (for third-party cookies)

Related Modules:
    - sha.analyzers.__init__ - Registers set_cookie.analyze in ANALYZER_REGISTRY
    - sha.fetcher - Provides cookies as list (multiple Set-Cookie headers captured)
    - sha.config - Imports STATUS_* constants
    - docs/headers/Set-Cookie.md - Detailed cookie security documentation

Example Usage:
    >>> from sha.analyzers.set_cookie import analyze, parse_set_cookie
    >>> # Perfect cookie configuration
    >>> finding = analyze("session=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=86400")
    >>> finding["status"]
    "good"
    >>> finding["cookie_count"]
    1

    >>> # Multiple cookies (worst status reported)
    >>> finding = analyze([
    ...     "session=abc123; Secure; HttpOnly; SameSite=Strict",
    ...     "csrf=xyz; Secure"  # Missing HttpOnly
    ... ])
    >>> finding["status"]
    "bad"
    >>> finding["cookie_count"]
    2

    >>> # Parse cookie attributes
    >>> parsed = parse_set_cookie("session=abc123; Secure; HttpOnly; SameSite=Strict")
    >>> parsed["secure"]
    True
    >>> parsed["samesite"]
    "Strict"

See Also:
    - docs/headers/Set-Cookie.md - Technical explanation and attack scenarios
    - docs/architecture/components.md#analyzer-layer - Multi-header handling
    - https://tools.ietf.org/html/rfc6265 - HTTP State Management (cookies)
"""

from typing import Any, Dict, List, Optional, Union

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "set-cookie"

# One year in seconds (365 days)
MAX_AGE_ONE_YEAR = 31536000

CONFIG = {
    "display_name": "Set-Cookie",
    "severity_missing": "info",  # Optional header - not all responses set cookies
    "description": "Controls security attributes of HTTP cookies",
    "validation": {
        # Security attributes that should be present
        "required_secure": True,  # Cookie should only be sent over HTTPS
        "required_httponly": True,  # Cookie should not be accessible via JavaScript
        # SameSite values (case-insensitive)
        "samesite_strict": "strict",  # Best - no cross-site requests
        "samesite_lax": "lax",  # Good - some cross-site requests allowed
        "samesite_none": "none",  # Requires Secure attribute
        # Max-Age validation
        "max_age_warning_threshold": MAX_AGE_ONE_YEAR,  # Warn if >1 year
    },
    "messages": {
        STATUS_GOOD: "Cookie has all recommended security attributes (Secure, HttpOnly, SameSite)",
        STATUS_ACCEPTABLE: "Cookie has basic security attributes but could be improved",
        STATUS_BAD: "Cookie is missing critical security attributes",
        STATUS_MISSING: "No Set-Cookie header present (cookies are not being set)",
    },
    "recommendations": {
        "missing": "If setting cookies, ensure Secure, HttpOnly, and SameSite attributes are used",
        "no_secure": "Add Secure attribute to prevent cookie transmission over HTTP",
        "no_httponly": "Add HttpOnly attribute to prevent JavaScript access to cookie",
        "no_samesite": "Add SameSite attribute (Strict or Lax) to prevent CSRF attacks",
        "samesite_none_without_secure": "SameSite=None requires Secure attribute",
        "long_max_age": "Consider shorter Max-Age for sensitive cookies (current >1 year)",
        "example": "Example: Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=86400; Path=/",
    },
}


def parse_set_cookie(value: str) -> Dict[str, Any]:
    """
    Parse Set-Cookie header value into components.

    Args:
        value: Set-Cookie header value

    Returns:
        Dictionary with:
        - cookie_name: str or None
        - cookie_value: str or None
        - secure: bool
        - httponly: bool
        - samesite: str or None ('Strict', 'Lax', 'None')
        - max_age: int or None (in seconds)
        - expires: str or None (HTTP date string)
        - domain: str or None
        - path: str or None

    Example:
        >>> parse_set_cookie("session=abc123; Secure; HttpOnly; SameSite=Strict")
        {
            "cookie_name": "session",
            "cookie_value": "abc123",
            "secure": True,
            "httponly": True,
            "samesite": "Strict",
            ...
        }
    """
    result = {
        "cookie_name": None,
        "cookie_value": None,
        "secure": False,
        "httponly": False,
        "samesite": None,
        "max_age": None,
        "expires": None,
        "domain": None,
        "path": None,
    }

    # Split by semicolon to get cookie definition and attributes
    parts = value.split(";")

    if not parts:
        return result

    # First part is cookie-name=cookie-value
    cookie_def = parts[0].strip()
    if "=" in cookie_def:
        name, val = cookie_def.split("=", 1)
        result["cookie_name"] = name.strip()
        result["cookie_value"] = val.strip()

    # Parse attributes (case-insensitive)
    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue

        # Check for attribute=value
        if "=" in part:
            attr_name, attr_value = part.split("=", 1)
            attr_name = attr_name.strip().lower()
            attr_value = attr_value.strip()

            if attr_name == "samesite":
                # Normalize to title case
                result["samesite"] = attr_value.capitalize()
            elif attr_name == "max-age":
                # Parse as integer
                try:
                    result["max_age"] = int(attr_value)
                except ValueError:
                    pass  # Invalid max-age, leave as None
            elif attr_name == "expires":
                result["expires"] = attr_value
            elif attr_name == "domain":
                result["domain"] = attr_value
            elif attr_name == "path":
                result["path"] = attr_value
        else:
            # Boolean attributes (just the name, no value)
            attr_name = part.lower()
            if attr_name == "secure":
                result["secure"] = True
            elif attr_name == "httponly":
                result["httponly"] = True

    return result


def _validate_cookie_prefix(parsed: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Validate cookie name prefixes (__Secure- and __Host-).

    Cookie prefixes are a security mechanism that enforces specific security
    requirements when a cookie name starts with special prefixes.

    Args:
        parsed: Parsed cookie dictionary from parse_set_cookie()

    Returns:
        List of validation issues (empty if valid)

    Prefix Rules:
        __Secure- prefix requirements:
            - Must have Secure attribute

        __Host- prefix requirements:
            - Must have Secure attribute
            - Must NOT have Domain attribute
            - Must have Path=/ (or no Path specified defaults to /)

    References:
        - RFC 6265bis Cookie Prefixes: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis
        - MDN: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes
    """
    issues = []
    cookie_name = parsed.get("cookie_name", "")

    if not cookie_name:
        return issues

    # Check __Secure- prefix
    if cookie_name.startswith("__Secure-"):
        if not parsed["secure"]:
            issues.append({
                "severity": "high",
                "message": f"Cookie '{cookie_name}' uses __Secure- prefix but missing Secure attribute",
                "recommendation": "Add Secure attribute - __Secure- prefix requires Secure",
            })

    # Check __Host- prefix (more restrictive than __Secure-)
    if cookie_name.startswith("__Host-"):
        prefix_issues = []

        if not parsed["secure"]:
            prefix_issues.append("missing Secure attribute")

        if parsed["domain"] is not None:
            prefix_issues.append("has Domain attribute (not allowed)")

        # Path must be / (or omitted, which defaults to request path but __Host- requires /)
        path = parsed.get("path")
        if path is not None and path != "/":
            prefix_issues.append(f"has Path={path} (must be / or omitted)")

        if prefix_issues:
            issues.append({
                "severity": "high",
                "message": f"Cookie '{cookie_name}' uses __Host- prefix but {', '.join(prefix_issues)}",
                "recommendation": "__Host- prefix requires: Secure attribute, no Domain attribute, Path=/ (or omitted)",
            })

    return issues


def _analyze_cookie_scope(parsed: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Analyze Domain and Path scope for overly broad configurations.

    Overly broad cookie scopes can expose cookies to more subdomains/paths
    than necessary, increasing attack surface if any subdomain is compromised.

    Args:
        parsed: Parsed cookie dictionary

    Returns:
        List of scope warnings (empty if scope is appropriate)

    Scope Issues Detected:
        - Domain set to parent domain (exposes cookie to all subdomains)
        - Path set to / (exposes cookie to entire site)
        - Missing Domain (defaults to current domain, usually good)
        - Domain starting with . (legacy syntax, applies to subdomains)
    """
    warnings = []
    domain = parsed.get("domain")
    path = parsed.get("path")
    cookie_name = parsed.get("cookie_name", "unknown")

    # Check Domain scope
    if domain:
        # Domain starting with "." applies to all subdomains (legacy syntax)
        if domain.startswith("."):
            warnings.append({
                "severity": "low",
                "message": f"Cookie '{cookie_name}' has Domain={domain} (applies to all subdomains)",
                "recommendation": "Consider restricting to specific subdomain or omit Domain attribute",
            })
        # Very short domains (e.g., "com", "co.uk") are suspicious - this is VERY rare and likely a mistake
        elif domain.count(".") == 0 or (domain.count(".") == 1 and len(domain) <= 6):
            # Only flag truly problematic cases like "com" or "co.uk"
            warnings.append({
                "severity": "medium",
                "message": f"Cookie '{cookie_name}' has overly broad Domain={domain}",
                "recommendation": "Specify full domain or omit Domain attribute to restrict to current origin",
            })

    # Check Path scope
    # Path=/ exposes cookie to entire site - warn for auth/session cookies
    if path == "/" and _looks_like_sensitive_cookie(cookie_name):
        warnings.append({
            "severity": "low",
            "message": f"Cookie '{cookie_name}' has Path=/ (exposed to entire site)",
            "recommendation": "Consider restricting Path to specific application path (e.g., /app, /api)",
        })

    return warnings


def _looks_like_sensitive_cookie(cookie_name: str) -> bool:
    """
    Detect if cookie name suggests it contains sensitive data.

    Args:
        cookie_name: Name of the cookie

    Returns:
        True if cookie name indicates sensitive data (session, auth, token, etc.)

    Patterns Detected:
        - Session identifiers: session, sess, sid, jsessionid, phpsessid
        - Authentication: auth, token, jwt, bearer, access, refresh
        - User identifiers: user, uid, userid
        - CSRF tokens: csrf, xsrf
    """
    if not cookie_name:
        return False

    name_lower = cookie_name.lower()

    sensitive_patterns = [
        "session", "sess", "sid",
        "auth", "token", "jwt", "bearer",
        "access", "refresh",
        "user", "uid", "userid",
        "csrf", "xsrf",
        "jsessionid", "phpsessid", "aspsessionid",
        "remember", "login",
    ]

    return any(pattern in name_lower for pattern in sensitive_patterns)


def _analyze_cookie_security(parsed: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Analyze cookie name patterns and flag potentially sensitive cookies without proper security.

    This function ONLY reports issues for sensitive cookies that are missing
    CRITICAL security attributes (Secure/HttpOnly). It does NOT duplicate
    warnings for attributes that are already checked by the main validation logic.

    Args:
        parsed: Parsed cookie dictionary

    Returns:
        List of security warnings based on cookie name patterns
    """
    warnings = []
    cookie_name = parsed.get("cookie_name", "")

    if not cookie_name:
        return warnings

    # Check if cookie looks sensitive
    if _looks_like_sensitive_cookie(cookie_name):
        # Only report if BOTH Secure AND HttpOnly are missing
        # (individual missing attributes are already reported by main logic)
        has_secure = parsed["secure"]
        has_httponly = parsed["httponly"]

        # If sensitive cookie is completely unprotected (no Secure, no HttpOnly), flag it
        if not has_secure and not has_httponly:
            warnings.append({
                "severity": "high",
                "message": f"Cookie '{cookie_name}' appears to be sensitive (session/auth) but has no security attributes",
                "recommendation": "Sensitive cookies should have Secure, HttpOnly, and SameSite=Strict attributes",
            })

    return warnings


def _analyze_single_cookie(cookie_value: str) -> Dict[str, Any]:
    """
    Analyze a single Set-Cookie header value.

    Args:
        cookie_value: Single cookie string

    Returns:
        Dictionary with analysis results for one cookie
    """
    parsed = parse_set_cookie(cookie_value)

    # Check for critical security attributes
    has_secure = parsed["secure"]
    has_httponly = parsed["httponly"]
    samesite = parsed["samesite"]
    max_age = parsed["max_age"]

    # Build list of issues
    issues = []
    recommendations = []

    # NEW: Check cookie prefix validation
    prefix_issues = _validate_cookie_prefix(parsed)
    for issue in prefix_issues:
        issues.append(issue["message"])
        recommendations.append(issue["recommendation"])

    # NEW: Check cookie scope (domain/path)
    scope_warnings = _analyze_cookie_scope(parsed)
    has_medium_severity_scope_issue = False
    for warning in scope_warnings:
        if warning["severity"] == "medium":
            has_medium_severity_scope_issue = True
            issues.append(warning["message"])
            recommendations.append(warning["recommendation"])
        elif warning["severity"] == "low":
            # LOW severity warnings go to recommendations only
            recommendations.append(warning["recommendation"])

    # NEW: Check cookie name patterns for sensitive cookies
    security_warnings = _analyze_cookie_security(parsed)
    has_high_severity_security_issue = False
    for warning in security_warnings:
        if warning["severity"] == "high":
            has_high_severity_security_issue = True
            issues.append(warning["message"])
            recommendations.append(warning["recommendation"])
        elif warning["severity"] in ["medium", "low"]:
            # MEDIUM/LOW severity warnings go to recommendations only
            recommendations.append(warning["recommendation"])

    # Existing validation
    if not has_secure:
        issues.append("missing Secure attribute")
        recommendations.append(CONFIG["recommendations"]["no_secure"])

    if not has_httponly:
        issues.append("missing HttpOnly attribute")
        recommendations.append(CONFIG["recommendations"]["no_httponly"])

    # SameSite validation
    if samesite is None:
        issues.append("missing SameSite attribute")
        recommendations.append(CONFIG["recommendations"]["no_samesite"])
    elif samesite == "None" and not has_secure:
        issues.append("SameSite=None without Secure attribute")
        recommendations.append(CONFIG["recommendations"]["samesite_none_without_secure"])

    # Max-Age validation (low priority warning)
    if max_age and max_age > CONFIG["validation"]["max_age_warning_threshold"]:
        issues.append(f"very long Max-Age ({max_age} seconds, >{MAX_AGE_ONE_YEAR})")
        recommendations.append(CONFIG["recommendations"]["long_max_age"])

    # Check if we have HIGH severity prefix violations
    has_high_severity_prefix_issue = any(issue.get("severity") == "high" for issue in prefix_issues)

    # Determine status based on issues
    if has_high_severity_prefix_issue or has_high_severity_security_issue:
        # Prefix violations or sensitive cookie issues are HIGH severity
        status = STATUS_BAD
        severity = "high"
        message = f"Cookie {', '.join(issues)}"
        recommendation = "; ".join(recommendations)
    elif not has_secure or not has_httponly:
        # Critical security attributes missing
        status = STATUS_BAD
        severity = "high"
        message = f"Cookie {', '.join(issues)}"
        recommendation = "; ".join(recommendations)
    elif samesite is None or (samesite == "None" and not has_secure) or has_medium_severity_scope_issue:
        # SameSite issues or scope issues
        status = STATUS_BAD
        severity = "medium"
        message = f"Cookie {', '.join(issues)}"
        recommendation = "; ".join(recommendations)
    elif samesite == "Strict":
        # Best configuration
        if max_age and max_age > CONFIG["validation"]["max_age_warning_threshold"]:
            status = STATUS_ACCEPTABLE
            severity = "low"
            message = f"{CONFIG['messages'][STATUS_GOOD]}, but {issues[0]}"
            recommendation = recommendations[0] if recommendations else None
        else:
            status = STATUS_GOOD
            severity = "info"
            message = CONFIG["messages"][STATUS_GOOD]
            # Include LOW severity recommendations even for GOOD status
            recommendation = "; ".join(recommendations) if recommendations else None
    elif samesite == "Lax" or (samesite == "None" and has_secure):
        # Acceptable configuration
        if max_age and max_age > CONFIG["validation"]["max_age_warning_threshold"]:
            status = STATUS_ACCEPTABLE
            severity = "low"
            message = f"{CONFIG['messages'][STATUS_ACCEPTABLE]} ({issues[0]})"
            recommendation = recommendations[0] if recommendations else None
        else:
            status = STATUS_ACCEPTABLE
            severity = "low"
            message = CONFIG["messages"][STATUS_ACCEPTABLE]
            recommendation = "Consider using SameSite=Strict for maximum protection"
    else:
        # Shouldn't reach here, but handle gracefully
        status = STATUS_ACCEPTABLE
        severity = "low"
        message = CONFIG["messages"][STATUS_ACCEPTABLE]
        recommendation = None

    return {
        "cookie_name": parsed.get("cookie_name", "unknown"),
        "status": status,
        "severity": severity,
        "issues": issues,
        "recommendations": recommendations,
        "has_secure": has_secure,
        "has_httponly": has_httponly,
        "samesite": samesite,
    }


def analyze(value: Optional[Union[str, List[str]]]) -> Dict[str, Any]:
    """
    Analyze Set-Cookie header(s).

    Supports analyzing multiple Set-Cookie headers. When multiple cookies
    are present, all are analyzed and the worst security status is reported.

    Validation rules:
    - Missing: Info severity (not all responses set cookies)
    - Missing Secure attribute: High severity (cookie sent over HTTP)
    - Missing HttpOnly attribute: High severity (XSS can steal cookie)
    - Missing SameSite or SameSite=None without Secure: Medium-High severity
    - SameSite=Strict + Secure + HttpOnly: Good
    - SameSite=Lax + Secure + HttpOnly: Acceptable
    - Max-Age >1 year: Low severity warning

    Args:
        value: Single cookie string, list of cookie strings, or None if missing

    Returns:
        Finding dictionary with keys:
        - header_name: str
        - status: str (good/acceptable/bad/missing)
        - severity: str (critical/high/medium/low/info)
        - message: str
        - actual_value: str or None (summary when multiple cookies)
        - recommendation: str or None
        - cookie_count: int (number of cookies analyzed)
        - cookies: List[Dict] (per-cookie analysis details)
    """
    header_name = CONFIG["display_name"]

    # Handle missing cookies
    if value is None or (isinstance(value, list) and len(value) == 0):
        return {
            "header_name": header_name,
            "status": STATUS_MISSING,
            "severity": CONFIG["severity_missing"],
            "message": CONFIG["messages"][STATUS_MISSING],
            "actual_value": None,
            "recommendation": CONFIG["recommendations"]["missing"],
            "cookie_count": 0,
            "cookies": [],
        }

    # Normalize to list
    cookies = [value] if isinstance(value, str) else value
    cookie_count = len(cookies)

    # Analyze each cookie
    cookie_results = []
    for cookie_value in cookies:
        result = _analyze_single_cookie(cookie_value)
        cookie_results.append(result)

    # Aggregate results - find worst status
    worst_status = STATUS_GOOD
    worst_severity = "info"
    all_issues = []
    all_recommendations = []

    # Severity ordering (worst to best)
    severity_order = {"high": 4, "medium": 3, "low": 2, "info": 1}

    for result in cookie_results:
        cookie_name = result["cookie_name"]

        # Collect issues with cookie name prefix
        if result["issues"]:
            for issue in result["issues"]:
                all_issues.append(f"{cookie_name}: {issue}")

        # Always collect recommendations (even if no issues - for LOW severity warnings)
        if result["recommendations"]:
            all_recommendations.extend(result["recommendations"])

        # Update worst status
        if result["status"] == STATUS_BAD:
            worst_status = STATUS_BAD
            if severity_order.get(result["severity"], 0) > severity_order.get(worst_severity, 0):
                worst_severity = result["severity"]
        elif result["status"] == STATUS_ACCEPTABLE and worst_status != STATUS_BAD:
            worst_status = STATUS_ACCEPTABLE
            if severity_order.get(result["severity"], 0) > severity_order.get(worst_severity, 0):
                worst_severity = result["severity"]

    # NEW: Check for excessive SameSite=None usage (third-party cookie risk)
    samesite_none_count = sum(1 for r in cookie_results if r.get("samesite") == "None")
    if samesite_none_count > 0 and cookie_count > 1:
        # If more than 50% of cookies use SameSite=None, warn about third-party cookie risks
        none_percentage = (samesite_none_count / cookie_count) * 100
        if none_percentage >= 50:
            all_recommendations.append(
                f"{samesite_none_count}/{cookie_count} cookies use SameSite=None (third-party cookies) - "
                "Consider if cross-site cookie access is necessary for all cookies"
            )

    # Build final message
    if all_issues:
        if cookie_count == 1:
            message = f"Cookie {', '.join(all_issues)}"
        else:
            message = f"Analyzed {cookie_count} cookies - Issues: {'; '.join(all_issues)}"
        recommendation = "; ".join(set(all_recommendations))  # Remove duplicates
    else:
        if cookie_count == 1:
            message = CONFIG["messages"][worst_status]
        else:
            message = f"All {cookie_count} cookies have secure attributes"
        # Include recommendations even if no issues (LOW severity warnings)
        recommendation = "; ".join(set(all_recommendations)) if all_recommendations else None

    # Create actual_value summary
    if cookie_count == 1:
        actual_value = cookies[0]
    else:
        # Show summary for multiple cookies
        cookie_names = [r["cookie_name"] for r in cookie_results]
        actual_value = f"{cookie_count} cookies: {', '.join(cookie_names)}"

    return {
        "header_name": header_name,
        "status": worst_status,
        "severity": worst_severity,
        "message": message,
        "actual_value": actual_value,
        "recommendation": recommendation if recommendation else None,
        "cookie_count": cookie_count,
        "cookies": cookie_results,
    }
