"""
Cache-Control Analyzer - HTTP caching security validation

Module: sha.analyzers.cache_control

Purpose:
    Analyzes the Cache-Control header to prevent sensitive data caching in shared
    caches (proxies, CDNs). Validates directives for security implications while
    recognizing that optimal caching strategy is context-dependent (API responses
    vs static assets).

Overview:
    The Cache-Control analyzer provides security-focused validation of caching
    directives. It parses comma-separated directives, evaluates security posture
    based on no-store/no-cache/private flags, warns about 'public' caching for
    potentially sensitive content, and flags excessively long max-age without
    immutable. The analyzer balances security (prevent sensitive data caching)
    with performance (allow static asset caching), providing context-aware
    recommendations.

Key Functions:
    - analyze(value) -> Finding
      Main analysis function that evaluates caching directives for security
      implications and provides context-aware recommendations

    - parse_cache_control(value) -> Dict[str, Any]
      Parses Cache-Control into directive components: no_store, no_cache, private,
      public, max_age, s_maxage, immutable, must_revalidate, proxy_revalidate,
      no_transform

Validation Rules:
    - Missing header: LOW severity (context-dependent - may use browser defaults)
    - no-store: GOOD (prevents all caching - ideal for sensitive data)
    - max-age=0: GOOD (effectively no caching)
    - private + no-cache: GOOD (browser cache only with revalidation)
    - public: BAD, MEDIUM severity (may cache sensitive data in shared caches)
    - private: ACCEPTABLE (prevents shared caching)
    - no-cache: ACCEPTABLE (requires revalidation)
    - max-age >1 year without immutable: LOW severity warning

Attack Scenarios Prevented:
    - **Sensitive Data Leakage via Shared Caches**: Without no-store/private,
      responses may be cached in shared proxies/CDNs where other users can
      retrieve sensitive data (API responses with personal info, authenticated pages)
    - **Stale Sensitive Data**: Without no-cache, cached responses may contain
      outdated sensitive information (user profiles, account balances)
    - **Proxy Cache Poisoning**: public caching increases attack surface for
      cache poisoning where attacker injects malicious cached responses

Context-Dependent Security:
    - **Sensitive Data** (API responses, authenticated pages, user content):
      * Best: Cache-Control: no-store, private
      * Acceptable: Cache-Control: private, no-cache
      * Bad: Cache-Control: public (or missing with long max-age)

    - **Static Assets** (images, CSS, JS with versioned URLs):
      * Best: Cache-Control: public, max-age=31536000, immutable
      * Acceptable: Cache-Control: public, max-age=86400
      * Note: Analyzer may flag 'public' - this is expected for static assets

Cache-Control Directives:
    - **no-store**: Don't cache response at all (sensitive data)
    - **no-cache**: Cache but revalidate before use (requires 304 check)
    - **private**: Only browser cache, not shared caches/proxies
    - **public**: Allow caching in shared caches (CDNs, proxies)
    - **max-age**: Cache lifetime in seconds
    - **s-maxage**: Shared cache max-age (overrides max-age for proxies)
    - **immutable**: Content never changes (allows long max-age safely)
    - **must-revalidate**: Revalidate stale responses (no serving stale)
    - **proxy-revalidate**: Like must-revalidate but only for shared caches

Configuration:
    - secure_directives: no-store, no-cache, private (prevent sensitive caching)
    - max_age_long_threshold: 31536000 (1 year - warn without immutable)

Related Modules:
    - sha.analyzers.__init__ - Registers cache_control.analyze in ANALYZER_REGISTRY
    - sha.config - Imports STATUS_* constants
    - docs/headers/Cache-Control.md - Detailed caching security documentation

Example Usage:
    >>> from sha.analyzers.cache_control import analyze, parse_cache_control
    >>> # Secure for sensitive data
    >>> finding = analyze("no-store, private")
    >>> finding["status"]
    "good"

    >>> # Parse directives
    >>> parsed = parse_cache_control("public, max-age=31536000, immutable")
    >>> parsed["public"]
    True
    >>> parsed["max_age"]
    31536000

    >>> # Warning for public caching
    >>> finding = analyze("public")
    >>> finding["status"]
    "bad"
    >>> finding["severity"]
    "medium"

See Also:
    - docs/headers/Cache-Control.md - Technical explanation and attack scenarios
    - docs/architecture/extensibility-guide.md - Adding new analyzers
    - https://tools.ietf.org/html/rfc7234 - HTTP Caching specification
"""

from typing import Any, Dict, List, Optional

from ..config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

HEADER_KEY = "cache-control"

# One year in seconds (365 days)
MAX_AGE_ONE_YEAR = 31536000

CONFIG = {
    "display_name": "Cache-Control",
    "severity_missing": "low",  # Missing is context-dependent
    "description": "Controls HTTP caching behavior for responses",
    "validation": {
        # Good directives for sensitive content
        "secure_directives": ["no-store", "no-cache", "private"],
        # Warning thresholds
        "max_age_long_threshold": MAX_AGE_ONE_YEAR,  # Warn if >1 year without immutable
    },
    "messages": {
        STATUS_GOOD: "Cache-Control is properly configured to prevent sensitive data caching",
        STATUS_ACCEPTABLE: "Cache-Control is present with reasonable caching policy",
        STATUS_BAD: "Cache-Control may allow caching of sensitive data",
        STATUS_MISSING: "Cache-Control header is missing - caching behavior depends on browser defaults",
    },
    "recommendations": {
        "missing": "Add Cache-Control header with appropriate directives for your content type",
        "public_warning": "Using 'public' may cache sensitive data - verify this is appropriate for your content",
        "add_no_store": "Consider using 'no-store' for sensitive data to prevent all caching",
        "add_private": "Consider using 'private' to prevent shared/proxy caching",
        "long_max_age": "Very long max-age without 'immutable' - consider if this is appropriate",
        "example_sensitive": "For sensitive data: Cache-Control: no-store, private",
        "example_static": "For static assets: Cache-Control: public, max-age=31536000, immutable",
    },
}


def parse_cache_control(value: str) -> Dict[str, Any]:
    """
    Parse Cache-Control header value into directives.

    Args:
        value: Cache-Control header value

    Returns:
        Dictionary with:
        - no_store: bool
        - no_cache: bool
        - private: bool
        - public: bool
        - max_age: int or None (in seconds)
        - s_maxage: int or None (in seconds, for shared caches)
        - immutable: bool
        - must_revalidate: bool
        - proxy_revalidate: bool
        - no_transform: bool
        - stale_while_revalidate: int or None (in seconds)
        - stale_if_error: int or None (in seconds)

    Example:
        >>> parse_cache_control("no-store, private")
        {"no_store": True, "private": True, "public": False, ...}
    """
    result = {
        "no_store": False,
        "no_cache": False,
        "private": False,
        "public": False,
        "max_age": None,
        "s_maxage": None,
        "immutable": False,
        "must_revalidate": False,
        "proxy_revalidate": False,
        "no_transform": False,
        "stale_while_revalidate": None,
        "stale_if_error": None,
    }

    # Split by comma and parse each directive
    directives = value.split(",")

    for directive in directives:
        directive = directive.strip().lower()
        if not directive:
            continue

        # Check for directive=value
        if "=" in directive:
            dir_name, dir_value = directive.split("=", 1)
            dir_name = dir_name.strip()
            dir_value = dir_value.strip()

            if dir_name == "max-age":
                try:
                    result["max_age"] = int(dir_value)
                except ValueError:
                    pass  # Invalid max-age, leave as None
            elif dir_name == "s-maxage":
                try:
                    result["s_maxage"] = int(dir_value)
                except ValueError:
                    pass
            elif dir_name == "stale-while-revalidate":
                try:
                    result["stale_while_revalidate"] = int(dir_value)
                except ValueError:
                    pass
            elif dir_name == "stale-if-error":
                try:
                    result["stale_if_error"] = int(dir_value)
                except ValueError:
                    pass
        else:
            # Boolean directives
            if directive == "no-store":
                result["no_store"] = True
            elif directive == "no-cache":
                result["no_cache"] = True
            elif directive == "private":
                result["private"] = True
            elif directive == "public":
                result["public"] = True
            elif directive == "immutable":
                result["immutable"] = True
            elif directive == "must-revalidate":
                result["must_revalidate"] = True
            elif directive == "proxy-revalidate":
                result["proxy_revalidate"] = True
            elif directive == "no-transform":
                result["no_transform"] = True

    return result


def detect_directive_conflicts(parsed: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Detect conflicting Cache-Control directives.

    Directive conflicts occur when mutually exclusive or contradictory
    directives are specified together, creating ambiguous caching behavior.

    Args:
        parsed: Parsed cache control dictionary

    Returns:
        List of conflict findings with severity, message, and recommendation

    Conflicts Detected:
        - public + private (mutually exclusive)
        - no-store + max-age (no-store overrides max-age, max-age is redundant)
        - no-cache + only-if-cached (contradictory intent)
        - private + s-maxage (s-maxage only applies to shared caches)
    """
    conflicts = []

    # CONFLICT 1: public + private (mutually exclusive)
    if parsed["public"] and parsed["private"]:
        conflicts.append({
            "severity": "medium",
            "message": "Cache-Control contains both 'public' and 'private' (mutually exclusive)",
            "recommendation": "Remove either 'public' or 'private' - use 'private' for sensitive data",
        })

    # CONFLICT 2: no-store + max-age (no-store overrides, max-age is redundant)
    if parsed["no_store"] and parsed["max_age"] is not None:
        conflicts.append({
            "severity": "low",
            "message": "Cache-Control contains both 'no-store' and 'max-age' (max-age is redundant with no-store)",
            "recommendation": "Remove 'max-age' directive - 'no-store' already prevents caching",
        })

    # CONFLICT 3: private + s-maxage (s-maxage only applies to shared caches)
    if parsed["private"] and parsed["s_maxage"] is not None:
        conflicts.append({
            "severity": "low",
            "message": "Cache-Control contains both 'private' and 's-maxage' (s-maxage only applies to shared caches)",
            "recommendation": "Remove 's-maxage' directive - 'private' already prevents shared caching",
        })

    # CONFLICT 4: no-store + no-cache (no-store is stronger, no-cache is redundant)
    if parsed["no_store"] and parsed["no_cache"]:
        conflicts.append({
            "severity": "low",
            "message": "Cache-Control contains both 'no-store' and 'no-cache' (no-cache is redundant with no-store)",
            "recommendation": "Remove 'no-cache' directive - 'no-store' already prevents caching",
        })

    return conflicts


def detect_must_revalidate_issues(parsed: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Detect issues with must-revalidate usage.

    must-revalidate forces caches to revalidate stale responses rather than
    serving them. Missing must-revalidate with long max-age can lead to serving
    very stale content if origin server is unreachable.

    Args:
        parsed: Parsed cache control dictionary

    Returns:
        List of must-revalidate related findings

    Issues Detected:
        - Long max-age without must-revalidate (stale content risk)
        - must-revalidate without max-age (unclear benefit)
    """
    issues = []

    max_age = parsed["max_age"]
    has_must_revalidate = parsed["must_revalidate"]
    has_immutable = parsed["immutable"]
    has_no_store = parsed["no_store"]
    has_no_cache = parsed["no_cache"]

    # Only check if we have actual caching directives
    if has_no_store or has_no_cache:
        return issues

    # ISSUE 1: Long max-age without must-revalidate (risk of serving very stale content)
    if max_age and max_age > 86400 and not has_must_revalidate and not has_immutable:  # > 1 day
        issues.append({
            "severity": "low",
            "message": f"Cache-Control has max-age={max_age} ({max_age // 86400} days) without 'must-revalidate' or 'immutable'",
            "recommendation": "Consider adding 'must-revalidate' to prevent serving stale content if origin is unreachable",
        })

    return issues


def analyze(value: Optional[str]) -> Dict[str, Any]:
    """
    Analyze Cache-Control header.

    Validation rules:
    - Missing: Low severity (context-dependent)
    - no-store: Good (prevents all caching)
    - max-age=0: Good (no caching)
    - private + no-cache: Good (only browser cache, requires revalidation)
    - private: Acceptable (prevents shared cache)
    - no-cache: Acceptable (requires revalidation)
    - public: Bad/Warning (may cache sensitive data)
    - Very long max-age without immutable: Low severity warning

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

    Note:
        Cache-Control interpretation is context-dependent.
        This analyzer provides general security guidance.
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

    # Parse directives
    parsed = parse_cache_control(value)

    # Analyze security posture
    has_no_store = parsed["no_store"]
    has_no_cache = parsed["no_cache"]
    has_private = parsed["private"]
    has_public = parsed["public"]
    max_age = parsed["max_age"]
    has_immutable = parsed["immutable"]

    # NEW: Check for directive conflicts
    conflicts = detect_directive_conflicts(parsed)
    has_medium_severity_conflict = any(c["severity"] == "medium" for c in conflicts)

    # NEW: Check for must-revalidate issues
    revalidate_issues = detect_must_revalidate_issues(parsed)

    # Collect LOW severity warnings (conflicts and revalidate issues)
    low_severity_warnings = []
    low_severity_warnings.extend([c["recommendation"] for c in conflicts if c["severity"] == "low"])
    low_severity_warnings.extend([i["recommendation"] for i in revalidate_issues if i["severity"] == "low"])

    # Check for good configurations
    if has_no_store:
        # Best: no caching at all
        # Include LOW severity warnings even for GOOD status
        recommendation = "; ".join(low_severity_warnings) if low_severity_warnings else None
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD] + " (no-store prevents all caching)",
            "actual_value": value,
            "recommendation": recommendation,
        }

    if max_age == 0:
        # Good: effectively no caching
        recommendation = "; ".join(low_severity_warnings) if low_severity_warnings else None
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD] + " (max-age=0 prevents caching)",
            "actual_value": value,
            "recommendation": recommendation,
        }

    if has_private and has_no_cache:
        # Good: browser cache only, requires revalidation
        recommendation = "; ".join(low_severity_warnings) if low_severity_warnings else None
        return {
            "header_name": header_name,
            "status": STATUS_GOOD,
            "severity": "info",
            "message": CONFIG["messages"][STATUS_GOOD] + " (private + no-cache)",
            "actual_value": value,
            "recommendation": recommendation,
        }

    # Check for problematic configurations (including MEDIUM severity conflicts)
    if has_medium_severity_conflict:
        # MEDIUM severity conflict (e.g., public + private)
        medium_conflicts = [c for c in conflicts if c["severity"] == "medium"]
        messages = [c["message"] for c in medium_conflicts]
        recommendations = [c["recommendation"] for c in medium_conflicts]
        recommendations.extend(low_severity_warnings)  # Include LOW severity warnings too

        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": "medium",
            "message": f"{CONFIG['messages'][STATUS_BAD]} - {'; '.join(messages)}",
            "actual_value": value,
            "recommendation": "; ".join(recommendations),
        }

    if has_public:
        # Warning: public caching may be inappropriate for sensitive data
        recommendations = [CONFIG["recommendations"]["public_warning"]]
        recommendations.extend(low_severity_warnings)  # Include LOW severity warnings
        return {
            "header_name": header_name,
            "status": STATUS_BAD,
            "severity": "medium",
            "message": f"{CONFIG['messages'][STATUS_BAD]} - 'public' allows caching by all caches",
            "actual_value": value,
            "recommendation": "; ".join(recommendations),
        }

    # Check for acceptable configurations
    if has_private:
        # Acceptable: only browser caching
        recommendations = []

        # Check for long max-age
        if (
            max_age
            and max_age > CONFIG["validation"]["max_age_long_threshold"]
            and not has_immutable
        ):
            recommendations.append(CONFIG["recommendations"]["long_max_age"])

        # Add LOW severity warnings
        recommendations.extend(low_severity_warnings)

        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low" if recommendations else "info",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE] + " (private prevents shared caching)",
            "actual_value": value,
            "recommendation": "; ".join(recommendations) if recommendations else None,
        }

    if has_no_cache:
        # Acceptable: requires revalidation
        recommendation = "; ".join(low_severity_warnings) if low_severity_warnings else None
        return {
            "header_name": header_name,
            "status": STATUS_ACCEPTABLE,
            "severity": "low" if low_severity_warnings else "info",
            "message": CONFIG["messages"][STATUS_ACCEPTABLE] + " (no-cache requires revalidation)",
            "actual_value": value,
            "recommendation": recommendation,
        }

    # Default: has cache control but not obviously secure or insecure
    recommendations = []

    if max_age and max_age > CONFIG["validation"]["max_age_long_threshold"] and not has_immutable:
        recommendations.append(CONFIG["recommendations"]["long_max_age"])

    # Add LOW severity warnings
    recommendations.extend(low_severity_warnings)

    # If caching is allowed, suggest being more restrictive
    if max_age and max_age > 0:
        recommendations.append(CONFIG["recommendations"]["add_private"])

    return {
        "header_name": header_name,
        "status": STATUS_ACCEPTABLE,
        "severity": "low",
        "message": CONFIG["messages"][STATUS_ACCEPTABLE],
        "actual_value": value,
        "recommendation": (
            "; ".join(recommendations)
            if recommendations
            else "Consider adding 'private' or 'no-cache' for sensitive content"
        ),
    }
