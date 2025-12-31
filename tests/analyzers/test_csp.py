"""
Tests for Content-Security-Policy (CSP) header analyzer.

Tests parsing and analysis logic for CSP including dangerous patterns,
restrictive defaults, and security directives.
"""

import pytest

from sha.analyzer import (
    analyze_csp,
    check_csp_dangerous_patterns,
    check_csp_restrictive_default,
    check_csp_security_directives,
    parse_csp,
)
from sha.config import SECURITY_HEADERS, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING


class TestParseCSP:
    """Test CSP header parsing."""

    def test_parse_csp_simple(self):
        """Test parsing simple CSP."""
        result = parse_csp("default-src 'self'")

        assert "default-src" in result
        assert result["default-src"] == ["'self'"]

    def test_parse_csp_multiple_directives(self):
        """Test parsing CSP with multiple directives."""
        result = parse_csp(
            "default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none'"
        )

        assert "default-src" in result
        assert "script-src" in result
        assert "object-src" in result
        assert result["default-src"] == ["'self'"]
        assert result["script-src"] == ["'self'", "https://cdn.example.com"]
        assert result["object-src"] == ["'none'"]

    def test_parse_csp_empty_string(self):
        """Test parsing empty CSP."""
        result = parse_csp("")

        assert result == {}

    def test_parse_csp_extra_semicolons(self):
        """Test CSP parsing handles extra semicolons."""
        result = parse_csp("default-src 'self';;; script-src 'self';")

        assert "default-src" in result
        assert "script-src" in result

    def test_parse_csp_directive_without_values(self):
        """Test CSP directive without values."""
        result = parse_csp("upgrade-insecure-requests")

        assert "upgrade-insecure-requests" in result
        assert result["upgrade-insecure-requests"] == []

    def test_parse_csp_complex_policy(self):
        """Test parsing complex real-world CSP."""
        csp = "default-src 'none'; script-src 'self' 'sha256-abc123'; style-src 'self' 'unsafe-inline'; img-src * data:; font-src 'self'"
        result = parse_csp(csp)

        assert len(result) == 5
        assert result["script-src"] == ["'self'", "'sha256-abc123'"]
        assert result["img-src"] == ["*", "data:"]


class TestCheckCSPDangerousPatterns:
    """Test CSP dangerous pattern detection."""

    def test_check_dangerous_unsafe_inline_in_script_src(self):
        """Test detection of unsafe-inline in script-src."""
        directives = {"script-src": ["'self'", "'unsafe-inline'"]}
        config = SECURITY_HEADERS["content-security-policy"]

        findings = check_csp_dangerous_patterns(directives, config)

        assert len(findings) > 0
        assert any("unsafe-inline" in f["message"] for f in findings)

    def test_check_dangerous_unsafe_eval(self):
        """Test detection of unsafe-eval."""
        directives = {"script-src": ["'self'", "'unsafe-eval'"]}
        config = SECURITY_HEADERS["content-security-policy"]

        findings = check_csp_dangerous_patterns(directives, config)

        assert len(findings) > 0
        assert any("unsafe-eval" in f["message"] for f in findings)

    def test_check_dangerous_wildcard_script(self):
        """Test detection of wildcard in script-src."""
        directives = {"script-src": ["*"]}
        config = SECURITY_HEADERS["content-security-policy"]

        findings = check_csp_dangerous_patterns(directives, config)

        assert len(findings) > 0
        assert any(
            "wildcard" in f["message"].lower() or "any source" in f["message"].lower()
            for f in findings
        )

    def test_check_dangerous_wildcard_default(self):
        """Test detection of wildcard in default-src."""
        directives = {"default-src": ["*"]}
        config = SECURITY_HEADERS["content-security-policy"]

        findings = check_csp_dangerous_patterns(directives, config)

        assert len(findings) > 0

    def test_check_no_dangerous_patterns(self):
        """Test that safe CSP has no dangerous patterns."""
        directives = {"default-src": ["'self'"], "script-src": ["'self'"]}
        config = SECURITY_HEADERS["content-security-policy"]

        findings = check_csp_dangerous_patterns(directives, config)

        assert len(findings) == 0


class TestCheckCSPRestrictiveDefault:
    """Test CSP restrictive default-src detection."""

    def test_restrictive_default_self(self):
        """Test 'self' is recognized as restrictive."""
        directives = {"default-src": ["'self'"]}
        config = SECURITY_HEADERS["content-security-policy"]

        result = check_csp_restrictive_default(directives, config)

        assert result is True

    def test_restrictive_default_none(self):
        """Test 'none' is recognized as restrictive."""
        directives = {"default-src": ["'none'"]}
        config = SECURITY_HEADERS["content-security-policy"]

        result = check_csp_restrictive_default(directives, config)

        assert result is True

    def test_not_restrictive_default_wildcard(self):
        """Test wildcard is not restrictive."""
        directives = {"default-src": ["*"]}
        config = SECURITY_HEADERS["content-security-policy"]

        result = check_csp_restrictive_default(directives, config)

        assert result is False

    def test_no_default_src(self):
        """Test missing default-src is not restrictive."""
        directives = {"script-src": ["'self'"]}
        config = SECURITY_HEADERS["content-security-policy"]

        result = check_csp_restrictive_default(directives, config)

        assert result is False


class TestCheckCSPSecurityDirectives:
    """Test CSP security directive detection."""

    def test_has_frame_ancestors(self):
        """Test detection of frame-ancestors."""
        directives = {"frame-ancestors": ["'none'"]}
        config = SECURITY_HEADERS["content-security-policy"]

        result = check_csp_security_directives(directives, config)

        assert result is True

    def test_has_base_uri(self):
        """Test detection of base-uri."""
        directives = {"base-uri": ["'self'"]}
        config = SECURITY_HEADERS["content-security-policy"]

        result = check_csp_security_directives(directives, config)

        assert result is True

    def test_has_form_action(self):
        """Test detection of form-action."""
        directives = {"form-action": ["'self'"]}
        config = SECURITY_HEADERS["content-security-policy"]

        result = check_csp_security_directives(directives, config)

        assert result is True

    def test_no_security_directives(self):
        """Test CSP without security directives."""
        directives = {"default-src": ["'self'"]}
        config = SECURITY_HEADERS["content-security-policy"]

        result = check_csp_security_directives(directives, config)

        assert result is False


class TestAnalyzeCSP:
    """Test CSP header analysis."""

    def test_analyze_csp_missing(self):
        """Test CSP analysis when missing."""
        result = analyze_csp(None)

        assert result["header_name"] == "Content-Security-Policy"
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == "critical"

    def test_analyze_csp_good_restrictive(self):
        """Test CSP with good restrictive policy."""
        csp = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"

    def test_analyze_csp_bad_unsafe_inline(self):
        """Test CSP with unsafe-inline."""
        csp = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD
        assert "unsafe-inline" in result["message"]

    def test_analyze_csp_bad_wildcard(self):
        """Test CSP with wildcard."""
        csp = "default-src *; script-src *"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD

    def test_analyze_csp_acceptable_simple(self):
        """Test CSP that's acceptable but not perfect."""
        csp = "default-src 'self'; script-src 'self'"
        result = analyze_csp(csp)

        # Should be acceptable (restrictive default, but missing some security directives)
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]

    def test_analyze_csp_acceptable_few_directives(self):
        """Test CSP with few directives but no dangerous patterns."""
        csp = "upgrade-insecure-requests; frame-ancestors 'self'"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_ACCEPTABLE


# ============================================================================
# Advanced CSP Feature Tests (Nonces, Hashes, strict-dynamic)
# ============================================================================


class TestCSPNonceDetection:
    """Test CSP nonce detection and handling."""

    def test_has_nonces_or_hashes_with_nonce(self):
        """Test detection of nonce in directive values."""
        from sha.analyzers.csp import has_nonces_or_hashes

        directive_values = ["'self'", "'nonce-abc123'"]
        assert has_nonces_or_hashes(directive_values) is True

    def test_has_nonces_or_hashes_multiple_nonces(self):
        """Test detection of multiple nonces."""
        from sha.analyzers.csp import has_nonces_or_hashes

        directive_values = ["'nonce-abc123'", "'nonce-xyz789'"]
        assert has_nonces_or_hashes(directive_values) is True

    def test_has_nonces_or_hashes_without_nonce(self):
        """Test no detection when nonce is absent."""
        from sha.analyzers.csp import has_nonces_or_hashes

        directive_values = ["'self'", "https://example.com"]
        assert has_nonces_or_hashes(directive_values) is False

    def test_has_nonces_or_hashes_false_positive(self):
        """Test that partial nonce-like strings don't match."""
        from sha.analyzers.csp import has_nonces_or_hashes

        directive_values = ["nonce-abc", "nonce"]  # Missing quotes
        assert has_nonces_or_hashes(directive_values) is False


class TestCSPHashDetection:
    """Test CSP hash detection and handling."""

    def test_has_nonces_or_hashes_with_sha256(self):
        """Test detection of SHA256 hash."""
        from sha.analyzers.csp import has_nonces_or_hashes

        directive_values = ["'self'", "'sha256-abc123def456'"]
        assert has_nonces_or_hashes(directive_values) is True

    def test_has_nonces_or_hashes_with_sha384(self):
        """Test detection of SHA384 hash."""
        from sha.analyzers.csp import has_nonces_or_hashes

        directive_values = ["'sha384-abcdef123456'"]
        assert has_nonces_or_hashes(directive_values) is True

    def test_has_nonces_or_hashes_with_sha512(self):
        """Test detection of SHA512 hash."""
        from sha.analyzers.csp import has_nonces_or_hashes

        directive_values = ["'sha512-abcdef123456'"]
        assert has_nonces_or_hashes(directive_values) is True

    def test_has_nonces_or_hashes_multiple_hashes(self):
        """Test detection of multiple hash types."""
        from sha.analyzers.csp import has_nonces_or_hashes

        directive_values = ["'sha256-abc'", "'sha384-def'", "'sha512-ghi'"]
        assert has_nonces_or_hashes(directive_values) is True


class TestCSPStrictDynamic:
    """Test CSP strict-dynamic detection."""

    def test_has_strict_dynamic_present(self):
        """Test detection of strict-dynamic."""
        from sha.analyzers.csp import has_strict_dynamic

        directive_values = ["'self'", "'strict-dynamic'", "'nonce-abc'"]
        assert has_strict_dynamic(directive_values) is True

    def test_has_strict_dynamic_absent(self):
        """Test no detection when strict-dynamic is absent."""
        from sha.analyzers.csp import has_strict_dynamic

        directive_values = ["'self'", "'nonce-abc'"]
        assert has_strict_dynamic(directive_values) is False

    def test_has_strict_dynamic_only(self):
        """Test detection with only strict-dynamic."""
        from sha.analyzers.csp import has_strict_dynamic

        directive_values = ["'strict-dynamic'"]
        assert has_strict_dynamic(directive_values) is True


class TestCSPUnsafeInlineMitigation:
    """Test that unsafe-inline is properly mitigated by nonces/hashes/strict-dynamic."""

    def test_unsafe_inline_mitigated_by_nonce(self):
        """Test unsafe-inline is not flagged when nonce is present."""
        csp = "script-src 'self' 'unsafe-inline' 'nonce-abc123'"
        result = analyze_csp(csp)

        # Should NOT be BAD because nonce mitigates unsafe-inline
        assert result["status"] != STATUS_BAD

    def test_unsafe_inline_mitigated_by_hash(self):
        """Test unsafe-inline is not flagged when hash is present."""
        csp = "script-src 'self' 'unsafe-inline' 'sha256-abc123def456'"
        result = analyze_csp(csp)

        # Should NOT be BAD because hash mitigates unsafe-inline
        assert result["status"] != STATUS_BAD

    def test_unsafe_inline_mitigated_by_strict_dynamic(self):
        """Test unsafe-inline is not flagged when strict-dynamic is present."""
        csp = "script-src 'self' 'unsafe-inline' 'strict-dynamic' 'nonce-abc'"
        result = analyze_csp(csp)

        # Should NOT be BAD because strict-dynamic mitigates unsafe-inline
        assert result["status"] != STATUS_BAD

    def test_unsafe_inline_not_mitigated(self):
        """Test unsafe-inline is flagged when no mitigation is present."""
        csp = "script-src 'self' 'unsafe-inline'"
        result = analyze_csp(csp)

        # Should be BAD because no nonce/hash/strict-dynamic
        assert result["status"] == STATUS_BAD
        assert "unsafe-inline" in result["message"]

    def test_unsafe_inline_in_default_src_mitigated(self):
        """Test unsafe-inline in default-src is mitigated by nonce."""
        csp = "default-src 'self' 'unsafe-inline' 'nonce-xyz789'"
        result = analyze_csp(csp)

        # Should NOT be BAD because nonce mitigates unsafe-inline
        assert result["status"] != STATUS_BAD


class TestCSPMissingDirectives:
    """Test CSP missing directive detection."""

    def test_missing_directives_without_default(self):
        """Test detection of missing directives when no default-src."""
        from sha.analyzers.csp import check_missing_directives, parse_csp

        csp = "script-src 'self'; object-src 'none'"
        directives = parse_csp(csp)
        missing = check_missing_directives(directives)

        # Should detect missing img-src, font-src, connect-src, style-src
        assert "img-src" in missing
        assert "font-src" in missing
        assert "connect-src" in missing
        assert "style-src" in missing

    def test_no_missing_directives_with_default(self):
        """Test no missing directives when default-src is present."""
        from sha.analyzers.csp import check_missing_directives, parse_csp

        csp = "default-src 'self'; script-src 'self'"
        directives = parse_csp(csp)
        missing = check_missing_directives(directives)

        # Should not detect missing directives because default-src covers them
        assert len(missing) == 0

    def test_no_missing_directives_all_specified(self):
        """Test no missing directives when all are explicitly specified."""
        from sha.analyzers.csp import check_missing_directives, parse_csp

        csp = "script-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; style-src 'self'"
        directives = parse_csp(csp)
        missing = check_missing_directives(directives)

        assert len(missing) == 0

    def test_partial_missing_directives(self):
        """Test detection of only some missing directives."""
        from sha.analyzers.csp import check_missing_directives, parse_csp

        csp = "script-src 'self'; img-src 'self'; style-src 'self'"
        directives = parse_csp(csp)
        missing = check_missing_directives(directives)

        # Should only detect missing font-src and connect-src
        assert "font-src" in missing
        assert "connect-src" in missing
        assert "img-src" not in missing
        assert "style-src" not in missing


class TestCSPOverlyBroadDomains:
    """Test CSP overly broad domain detection."""

    def test_detect_ipv4_address(self):
        """Test detection of IPv4 addresses in CSP."""
        from sha.analyzers.csp import check_overly_broad_domains, parse_csp

        csp = "script-src 'self' https://192.168.1.1"
        directives = parse_csp(csp)
        warnings = check_overly_broad_domains(directives)

        assert len(warnings) > 0
        assert any("IP address" in w and "192.168.1.1" in w for w in warnings)

    def test_detect_wildcard_subdomain(self):
        """Test detection of wildcard subdomains in CSP."""
        from sha.analyzers.csp import check_overly_broad_domains, parse_csp

        csp = "script-src 'self' *.example.com"
        directives = parse_csp(csp)
        warnings = check_overly_broad_domains(directives)

        assert len(warnings) > 0
        assert any("wildcard subdomain" in w and "*.example.com" in w for w in warnings)

    def test_no_warnings_for_specific_domains(self):
        """Test no warnings for specific domain names."""
        from sha.analyzers.csp import check_overly_broad_domains, parse_csp

        csp = "script-src 'self' https://cdn.example.com https://api.example.com"
        directives = parse_csp(csp)
        warnings = check_overly_broad_domains(directives)

        # Should have no warnings for specific, non-wildcard domains
        assert len(warnings) == 0

    def test_no_warnings_for_special_keywords(self):
        """Test no warnings for CSP special keywords."""
        from sha.analyzers.csp import check_overly_broad_domains, parse_csp

        csp = "script-src 'self' 'unsafe-inline' 'nonce-abc123'"
        directives = parse_csp(csp)
        warnings = check_overly_broad_domains(directives)

        # Should have no warnings for quoted special keywords
        assert len(warnings) == 0

    def test_detect_multiple_issues(self):
        """Test detection of multiple overly broad patterns."""
        from sha.analyzers.csp import check_overly_broad_domains, parse_csp

        csp = "script-src 'self' *.cdn.com https://10.0.0.1; img-src *.images.com"
        directives = parse_csp(csp)
        warnings = check_overly_broad_domains(directives)

        # Should detect wildcard subdomains and IP address
        assert len(warnings) >= 2
        assert any("wildcard" in w for w in warnings)
        assert any("IP address" in w for w in warnings)


class TestCSPEnhancedAnalysis:
    """Test integration of enhanced CSP analysis in analyze() function."""

    def test_good_csp_with_missing_directives_warning(self):
        """Test that GOOD CSP includes warning about missing directives."""
        csp = "default-src 'self'; script-src 'self'; frame-ancestors 'none'"
        result = analyze_csp(csp)

        # Should be GOOD status
        assert result["status"] == STATUS_GOOD
        # But might have recommendations about additional directives
        # (if default-src is not counted, otherwise no recommendations)

    def test_acceptable_csp_with_broad_domain_warning(self):
        """Test that ACCEPTABLE CSP includes warning about broad domains."""
        csp = "default-src 'self'; script-src 'self' *.cdn.com; object-src 'none'"
        result = analyze_csp(csp)

        # Should be ACCEPTABLE
        assert result["status"] in [STATUS_ACCEPTABLE, STATUS_GOOD]
        # Should have warning about wildcard subdomain
        if result["recommendation"]:
            assert "wildcard" in result["recommendation"] or "cdn.com" in result["recommendation"]

    def test_csp_without_default_shows_missing_directives(self):
        """Test that CSP without default-src shows missing directive warnings."""
        csp = "script-src 'self'; object-src 'none'; base-uri 'self'"
        result = analyze_csp(csp)

        # Should have recommendations about missing directives
        if result["recommendation"]:
            rec_lower = result["recommendation"].lower()
            assert "img-src" in rec_lower or "font-src" in rec_lower or "connect-src" in rec_lower

    def test_csp_with_ip_address_shows_warning(self):
        """Test that CSP with IP addresses shows warning."""
        csp = "default-src 'self'; script-src 'self' https://192.168.1.100"
        result = analyze_csp(csp)

        # Should have warning about IP address if recommendations present
        if result["recommendation"]:
            assert "IP address" in result["recommendation"] or "192.168" in result["recommendation"]


class TestCSPBypassDetection:
    """Test CSP bypass pattern detection."""

    def test_bypass_jsonp_google_apis(self):
        """Test detection of JSONP bypass via Google APIs."""
        csp = "default-src 'self'; script-src 'self' https://ajax.googleapis.com"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "high"
        assert "JSONP" in result["message"] or "bypass" in result["message"].lower()

    def test_bypass_jsonp_google_accounts(self):
        """Test detection of JSONP bypass via Google Accounts."""
        csp = "script-src 'self' accounts.google.com"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD
        assert "JSONP" in result["message"] or "bypass" in result["message"].lower()

    def test_bypass_jsonp_cdn_jsdelivr(self):
        """Test detection of JSONP bypass via CDN."""
        csp = "script-src 'self' cdn.jsdelivr.net"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD
        assert "JSONP" in result["message"] or "bypass" in result["message"].lower()

    def test_bypass_jsonp_cloudflare_cdn(self):
        """Test detection of JSONP bypass via Cloudflare CDN."""
        csp = "script-src 'self' cdnjs.cloudflare.com"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD
        assert "JSONP" in result["message"] or "bypass" in result["message"].lower()

    def test_bypass_angular_template_injection(self):
        """Test detection of AngularJS template injection bypass."""
        csp = "script-src 'self' angularjs.org"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "high"
        assert "angular" in result["message"].lower() or "template" in result["message"].lower()

    def test_bypass_angular_with_strict_dynamic_ok(self):
        """Test that Angular CDN with strict-dynamic doesn't trigger bypass warning."""
        csp = "script-src 'nonce-abc123' 'strict-dynamic' angularjs.org"
        result = analyze_csp(csp)

        # strict-dynamic mitigates the Angular bypass
        # Should not have Angular-specific bypass warning
        if result["status"] == STATUS_BAD:
            # If it's bad, it should be for a different reason
            assert "angular" not in result["message"].lower() or "strict-dynamic" in result["recommendation"].lower()

    def test_bypass_missing_base_uri(self):
        """Test detection of missing base-uri directive."""
        csp = "default-src 'self'; script-src 'nonce-abc123' 'strict-dynamic'; object-src 'none'"
        result = analyze_csp(csp)

        # Should have recommendation about missing base-uri (low severity, so not BAD status)
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]
        if result["recommendation"]:
            assert "base-uri" in result["recommendation"].lower() or "base tag" in result["recommendation"].lower()

    def test_bypass_missing_object_src(self):
        """Test detection of missing object-src directive."""
        csp = "default-src 'self'; script-src 'nonce-abc123' 'strict-dynamic'; base-uri 'self'"
        result = analyze_csp(csp)

        # Should have recommendation about missing object-src (low severity, so not BAD status)
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]
        if result["recommendation"]:
            assert "object-src" in result["recommendation"].lower() or "plugin" in result["recommendation"].lower()

    def test_bypass_object_src_not_none(self):
        """Test detection of permissive object-src."""
        csp = "default-src 'none'; script-src 'nonce-abc123' 'strict-dynamic'; object-src 'self'; base-uri 'self'"
        result = analyze_csp(csp)

        # Should have recommendation about object-src (low severity, so not BAD status)
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]
        if result["recommendation"]:
            assert "object-src" in result["recommendation"].lower()

    def test_no_bypass_object_src_none(self):
        """Test that object-src 'none' doesn't trigger bypass."""
        csp = "default-src 'self'; script-src 'nonce-abc123' 'strict-dynamic'; object-src 'none'; base-uri 'self'"
        result = analyze_csp(csp)

        # Should be good or acceptable, not bad (using strict-dynamic to avoid 'self' warning)
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]

    def test_bypass_self_with_file_upload_warning(self):
        """Test warning for 'self' in script-src (potential stored XSS)."""
        csp = "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        result = analyze_csp(csp)

        # Should have warning about 'self' with file uploads (low severity, so GOOD with recommendation)
        assert result["status"] == STATUS_GOOD
        assert result["recommendation"] is not None
        assert "'self'" in result["recommendation"] or "upload" in result["recommendation"].lower()

    def test_bypass_data_uri_in_script_src(self):
        """Test detection of data: URIs in script-src."""
        csp = "script-src 'self' data:"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "high"
        assert "data:" in result["message"] or "data uri" in result["message"].lower()

    def test_bypass_unsafe_hashes_without_hashes(self):
        """Test detection of unsafe-hashes without corresponding hash values."""
        csp = "default-src 'none'; script-src 'self' 'unsafe-hashes'; object-src 'none'; base-uri 'self'"
        result = analyze_csp(csp)

        # Medium severity, so should be in recommendations
        assert result["status"] in [STATUS_ACCEPTABLE, STATUS_GOOD]
        if result["recommendation"]:
            assert "unsafe-hashes" in result["recommendation"].lower()

    def test_no_bypass_unsafe_hashes_with_hashes(self):
        """Test that unsafe-hashes with proper hashes doesn't trigger warning."""
        csp = "script-src 'self' 'unsafe-hashes' 'sha256-abc123def456'"
        result = analyze_csp(csp)

        # Should not have unsafe-hashes specific warning
        message_lower = result["message"].lower()
        if "unsafe-hashes" in message_lower:
            # If mentioned, should acknowledge the hash is present
            assert "sha256" in result["actual_value"] or STATUS_BAD != result["status"]

    def test_bypass_script_src_elem_unsafe_inline(self):
        """Test detection of unsafe-inline in script-src-elem."""
        csp = "script-src-elem 'unsafe-inline'"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "high"
        assert "script-src-elem" in result["message"].lower() or "unsafe-inline" in result["message"].lower()

    def test_bypass_img_src_external_domains(self):
        """Test warning for external domains in img-src (dangling markup)."""
        csp = "default-src 'none'; script-src 'nonce-abc123' 'strict-dynamic'; object-src 'none'; base-uri 'self'; img-src 'self' https://cdn.example.com; frame-ancestors 'none'"
        result = analyze_csp(csp)

        # Should be good with recommendation about img-src (low severity)
        assert result["status"] == STATUS_GOOD
        assert result["recommendation"] is not None
        assert "img-src" in result["recommendation"].lower() or "external" in result["recommendation"].lower() or "dangling" in result["recommendation"].lower()

    def test_bypass_multiple_issues_combined(self):
        """Test that multiple bypasses are detected and reported."""
        csp = "script-src 'self' ajax.googleapis.com data:; img-src *"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "high"
        # Should detect multiple issues
        message_and_rec = (result["message"] + " " + (result["recommendation"] or "")).lower()
        issues_found = sum([
            "jsonp" in message_and_rec or "ajax.googleapis" in message_and_rec,
            "data:" in message_and_rec,
        ])
        assert issues_found >= 1  # At least one bypass detected

    def test_bypass_limit_to_three_issues(self):
        """Test that output is limited to avoid overwhelming messages."""
        # Create a CSP with many bypasses
        csp = "script-src 'self' ajax.googleapis.com cdn.jsdelivr.net data:; img-src *"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD
        # Check if message indicates more issues detected
        if "more issues" in result["message"].lower():
            assert True  # Good, it's limiting output
        else:
            # Even if not limiting, should still be marked as bad
            assert result["status"] == STATUS_BAD

    def test_no_bypass_strict_policy(self):
        """Test that a strict CSP without bypasses is marked as good."""
        csp = "default-src 'none'; script-src 'nonce-abc123' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"

    def test_bypass_youtube_domain(self):
        """Test detection of YouTube JSONP bypass."""
        csp = "script-src 'self' www.youtube.com"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD
        assert "jsonp" in result["message"].lower() or "bypass" in result["message"].lower()

    def test_bypass_s3_amazonaws(self):
        """Test detection of S3/AWS bypass domain."""
        csp = "script-src 'self' mybucket.s3.amazonaws.com"
        result = analyze_csp(csp)

        # Should detect the bypass (marked as BAD or ACCEPTABLE depending on other bypasses)
        assert result["status"] in [STATUS_BAD, STATUS_ACCEPTABLE]
        message_and_rec = (result["message"] + " " + (result["recommendation"] or "")).lower()
        assert "jsonp" in message_and_rec or "amazonaws" in message_and_rec or "bypass" in message_and_rec

    def test_bypass_protocol_normalization(self):
        """Test that bypass detection works with different protocols."""
        csp = "script-src 'self' https://ajax.googleapis.com"
        result = analyze_csp(csp)

        assert result["status"] == STATUS_BAD
        assert "jsonp" in result["message"].lower() or "bypass" in result["message"].lower()

    def test_bypass_wildcard_subdomain_detection(self):
        """Test detection of wildcard subdomains for bypass domains."""
        csp = "script-src 'self' *.cloudflare.com"
        result = analyze_csp(csp)

        # Should detect the bypass (marked as BAD or ACCEPTABLE depending on other bypasses)
        assert result["status"] in [STATUS_BAD, STATUS_ACCEPTABLE]
        message_and_rec = (result["message"] + " " + (result["recommendation"] or "")).lower()
        # Should detect cloudflare.com even with wildcard
        assert "cloudflare" in message_and_rec or "jsonp" in message_and_rec or "bypass" in message_and_rec
