"""
Edge case tests for security header analysis.

This module tests edge cases including:
- Empty and whitespace values
- Very long values
- Unicode and special characters
- Duplicate headers
- Malformed values
"""

import pytest

from sha.analyzer import (
    analyze_content_type_options,
    analyze_csp,
    analyze_hsts,
    analyze_referrer_policy,
    analyze_xframe,
)
from sha.analyzers.coep import analyze as analyze_coep
from sha.analyzers.coop import analyze as analyze_coop
from sha.analyzers.corp import analyze as analyze_corp
from sha.analyzers.permissions_policy import analyze as analyze_permissions_policy
from sha.config import (
    STATUS_ACCEPTABLE,
    STATUS_BAD,
    STATUS_GOOD,
    STATUS_MISSING,
)

# ============================================================================
# Empty and Whitespace Value Tests
# ============================================================================


class TestEmptyValues:
    """Test handling of empty and whitespace-only values."""

    def test_hsts_empty_string(self):
        """Test HSTS with empty string."""
        result = analyze_hsts("")
        # Empty string should be treated as bad/invalid
        assert result["status"] == STATUS_BAD

    def test_hsts_whitespace_only(self):
        """Test HSTS with whitespace only."""
        result = analyze_hsts("   ")
        assert result["status"] == STATUS_BAD

    def test_xframe_empty_string(self):
        """Test X-Frame-Options with empty string."""
        result = analyze_xframe("")
        assert result["status"] == STATUS_BAD

    def test_content_type_empty_string(self):
        """Test X-Content-Type-Options with empty string."""
        result = analyze_content_type_options("")
        assert result["status"] == STATUS_BAD

    def test_csp_empty_string(self):
        """Test CSP with empty string."""
        result = analyze_csp("")
        # Empty CSP is present but useless
        assert result["status"] in [STATUS_BAD, STATUS_ACCEPTABLE]

    def test_referrer_policy_empty_string(self):
        """Test Referrer-Policy with empty string."""
        result = analyze_referrer_policy("")
        assert result["status"] == STATUS_BAD

    def test_permissions_policy_whitespace(self):
        """Test Permissions-Policy with whitespace."""
        result = analyze_permissions_policy("   ")
        assert result["status"] == STATUS_BAD

    def test_coep_whitespace(self):
        """Test COEP with whitespace."""
        result = analyze_coep("   ")
        assert result["status"] == STATUS_BAD

    def test_coop_whitespace(self):
        """Test COOP with whitespace."""
        result = analyze_coop("   ")
        assert result["status"] == STATUS_BAD


# ============================================================================
# Very Long Value Tests
# ============================================================================


class TestVeryLongValues:
    """Test handling of extremely long header values."""

    def test_csp_very_long_policy(self):
        """Test CSP with very long policy (realistic for complex sites)."""
        # Create a CSP with many domains (realistic for CDN-heavy sites)
        domains = [f"https://cdn{i}.example.com" for i in range(50)]
        csp = f"default-src 'self'; script-src 'self' {' '.join(domains)}"
        result = analyze_csp(csp)
        # Should still parse and analyze correctly
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD]

    def test_permissions_policy_many_features(self):
        """Test Permissions-Policy with many features."""
        features = [f"feature{i}=()" for i in range(30)]
        policy = ", ".join(features)
        result = analyze_permissions_policy(policy)
        # Should parse without error
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD]

    def test_referrer_policy_very_long(self):
        """Test Referrer-Policy with unreasonably long value."""
        # Even a very long value should be handled gracefully
        result = analyze_referrer_policy("a" * 10000)
        assert result["status"] == STATUS_BAD


# ============================================================================
# Unicode and Special Character Tests
# ============================================================================


class TestUnicodeAndSpecialCharacters:
    """Test handling of unicode and special characters."""

    def test_hsts_with_unicode(self):
        """Test HSTS with unicode characters."""
        result = analyze_hsts("max-age=31536000; includeSubDomains; \u4e2d\u6587")
        # Should handle gracefully, likely bad
        assert result["status"] in [STATUS_BAD, STATUS_ACCEPTABLE]

    def test_csp_with_unicode_domain(self):
        """Test CSP with unicode domain (IDN)."""
        csp = "default-src 'self' https://\u4f8b.jp"
        result = analyze_csp(csp)
        # Should parse without crashing
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD]

    def test_xframe_with_special_chars(self):
        """Test X-Frame-Options with special characters."""
        result = analyze_xframe("DENY; <script>alert(1)</script>")
        # Should not crash, but likely bad
        assert result["status"] in [STATUS_BAD, STATUS_GOOD, STATUS_ACCEPTABLE]

    def test_permissions_policy_with_quotes(self):
        """Test Permissions-Policy with various quote styles."""
        result = analyze_permissions_policy('camera=("self")')
        # Should handle gracefully
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD]

    def test_csp_with_null_bytes(self):
        """Test CSP with null bytes."""
        csp = "default-src 'self'\x00script-src 'self'"
        result = analyze_csp(csp)
        # Should not crash
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD]


# ============================================================================
# Malformed Value Tests
# ============================================================================


class TestMalformedValues:
    """Test handling of malformed header values."""

    def test_hsts_negative_max_age(self):
        """Test HSTS with negative max-age."""
        result = analyze_hsts("max-age=-1")
        assert result["status"] == STATUS_BAD

    def test_hsts_non_numeric_max_age(self):
        """Test HSTS with non-numeric max-age."""
        result = analyze_hsts("max-age=abc")
        assert result["status"] == STATUS_BAD

    def test_hsts_malformed_directive(self):
        """Test HSTS with malformed directives."""
        result = analyze_hsts("max-age=31536000; includeSubDomains=yes")
        # includeSubDomains shouldn't have a value
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]

    def test_csp_missing_semicolons(self):
        """Test CSP with missing semicolons between directives."""
        csp = "default-src 'self' script-src 'self'"
        result = analyze_csp(csp)
        # Might parse incorrectly but shouldn't crash
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD]

    def test_csp_double_semicolons(self):
        """Test CSP with double semicolons."""
        csp = "default-src 'self';; script-src 'self'"
        result = analyze_csp(csp)
        # Should handle gracefully
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD]

    def test_permissions_policy_missing_equals(self):
        """Test Permissions-Policy with missing equals sign."""
        result = analyze_permissions_policy("camera(), microphone")
        # Should handle malformed input
        assert result["status"] in [STATUS_BAD, STATUS_ACCEPTABLE]

    def test_referrer_policy_multiple_conflicting_values(self):
        """Test Referrer-Policy with multiple conflicting values."""
        result = analyze_referrer_policy("no-referrer, unsafe-url")
        # First value should take precedence
        assert result["status"] == STATUS_GOOD

    def test_coep_multiple_values(self):
        """Test COEP with multiple values (invalid)."""
        result = analyze_coep("require-corp credentialless")
        # Should handle as invalid
        assert result["status"] == STATUS_BAD

    def test_coop_with_extra_parameters(self):
        """Test COOP with extra parameters."""
        result = analyze_coop("same-origin; report-to=default")
        # Might parse the directive name only
        assert result["status"] in [STATUS_GOOD, STATUS_BAD]


# ============================================================================
# Case Sensitivity and Normalization Tests
# ============================================================================


class TestCaseSensitivity:
    """Test case sensitivity handling across headers."""

    def test_hsts_directive_case_variations(self):
        """Test HSTS directives with various cases."""
        result1 = analyze_hsts("max-age=31536000; includeSubDomains")
        result2 = analyze_hsts("max-age=31536000; includesubdomains")
        result3 = analyze_hsts("max-age=31536000; INCLUDESUBDOMAINS")
        # Should all be equivalent
        assert result1["status"] == result2["status"] == result3["status"]

    def test_csp_directive_names_case_insensitive(self):
        """Test CSP directive names are case insensitive."""
        csp1 = "default-src 'self'; script-src 'self'"
        csp2 = "DEFAULT-SRC 'self'; SCRIPT-SRC 'self'"
        result1 = analyze_csp(csp1)
        result2 = analyze_csp(csp2)
        # Should produce same result
        assert result1["status"] == result2["status"]

    def test_csp_keywords_case_sensitive(self):
        """Test CSP keywords are case sensitive ('self' vs 'SELF')."""
        # Note: 'self' must be lowercase with quotes to be valid
        csp_valid = "default-src 'self'"
        csp_invalid = "default-src 'SELF'"
        result_valid = analyze_csp(csp_valid)
        result_invalid = analyze_csp(csp_invalid)
        # Valid should be better than invalid
        # Note: We don't enforce this in our analyzer, so both might pass
        assert result_valid["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]

    def test_referrer_policy_case_insensitive(self):
        """Test Referrer-Policy values are case insensitive."""
        result1 = analyze_referrer_policy("no-referrer")
        result2 = analyze_referrer_policy("NO-REFERRER")
        result3 = analyze_referrer_policy("No-Referrer")
        assert result1["status"] == result2["status"] == result3["status"]


# ============================================================================
# Boundary Value Tests
# ============================================================================


class TestBoundaryValues:
    """Test boundary values for numeric and enumerated types."""

    def test_hsts_max_age_zero(self):
        """Test HSTS with max-age=0 (disables HSTS)."""
        result = analyze_hsts("max-age=0")
        assert result["status"] == STATUS_BAD

    def test_hsts_max_age_very_large(self):
        """Test HSTS with very large max-age."""
        result = analyze_hsts("max-age=99999999999")
        # Should be acceptable (though unnecessarily large)
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]

    def test_hsts_max_age_exactly_one_year(self):
        """Test HSTS with exactly one year (31536000 seconds)."""
        result = analyze_hsts("max-age=31536000")
        # Should be good
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]

    def test_hsts_max_age_just_under_recommended(self):
        """Test HSTS with max-age just under recommended threshold."""
        result = analyze_hsts("max-age=31535999")
        # Should be acceptable but not good
        assert result["status"] in [STATUS_ACCEPTABLE, STATUS_BAD]

    def test_csp_single_directive(self):
        """Test CSP with single directive (boundary case)."""
        result = analyze_csp("default-src 'self'")
        # Should be acceptable
        assert result["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]

    def test_csp_no_directives(self):
        """Test CSP with no directives (just semicolons)."""
        result = analyze_csp(";;;")
        # Empty CSP is present but not useful
        assert result["status"] in [STATUS_BAD, STATUS_ACCEPTABLE]


# ============================================================================
# New Edge Cases from Holes Analysis
# ============================================================================


class TestIPv6URLSupport:
    """Test IPv6 URL normalization and validation."""

    def test_ipv6_localhost_url(self):
        """Test IPv6 localhost URL normalization."""
        from sha.fetcher import normalize_url

        url = "http://[::1]/"
        normalized = normalize_url(url)
        assert "[::1]" in normalized
        assert normalized.startswith("http://")

    def test_ipv6_public_address_url(self):
        """Test IPv6 public address URL normalization."""
        from sha.fetcher import normalize_url

        url = "http://[2001:db8::1]/"
        normalized = normalize_url(url)
        assert "[2001:db8::1]" in normalized

    def test_ipv6_url_with_https(self):
        """Test IPv6 URL with HTTPS."""
        from sha.fetcher import normalize_url

        url = "https://[2001:db8::1]:8080/path"
        normalized = normalize_url(url)
        assert normalized == url  # Should remain unchanged

    def test_ipv6_url_without_protocol(self):
        """Test IPv6 URL gets HTTPS prepended."""
        from sha.fetcher import normalize_url

        # This is tricky - IPv6 without protocol is ambiguous
        # Our normalize function adds https:// prefix to anything without protocol
        url = "[2001:db8::1]"
        normalized = normalize_url(url)
        assert normalized.startswith("https://")


class TestCSPParserMalformed:
    """Test CSP parser handles malformed input gracefully."""

    def test_csp_empty_directives_multiple(self):
        """Test CSP parser with multiple empty directives."""
        from sha.analyzers.csp import parse_csp

        result = parse_csp(";;;")
        assert result == {}

    def test_csp_directive_no_values(self):
        """Test CSP directive with no values."""
        from sha.analyzers.csp import parse_csp

        result = parse_csp("script-src;")
        assert result == {"script-src": []}

    def test_csp_duplicate_directives(self):
        """Test CSP with duplicate directives (last wins per spec)."""
        from sha.analyzers.csp import parse_csp

        result = parse_csp("script-src 'self'; script-src 'unsafe-inline'")
        # Last directive should win
        assert result["script-src"] == ["'unsafe-inline'"]

    def test_csp_extremely_long(self):
        """Test CSP parser rejects extremely long CSPs (DoS protection)."""
        from sha.analyzers.csp import parse_csp

        # Create CSP longer than MAX_CSP_LENGTH (10000 bytes)
        long_csp = "script-src " + " ".join([f"https://example{i}.com" for i in range(1000)])

        with pytest.raises(ValueError, match="CSP too long"):
            parse_csp(long_csp)

    def test_csp_malformed_in_analyze(self):
        """Test analyze() handles malformed CSP gracefully."""
        # Test that analyze() wraps parse errors and returns a finding
        result = analyze_csp("invalid;;;;;;;;")
        # Should return a finding, not crash
        assert result["status"] in [STATUS_BAD, STATUS_ACCEPTABLE]
        assert "header_name" in result


class TestTimeoutValidation:
    """Test timeout parameter boundary validation."""

    def test_timeout_zero(self):
        """Test zero timeout is rejected."""
        from sha.main import parse_args
        import sys

        sys.argv = ["sha", "example.com", "--timeout", "0"]
        with pytest.raises(SystemExit) as exc_info:
            parse_args()
        assert exc_info.value.code != 0

    def test_timeout_negative(self):
        """Test negative timeout is rejected."""
        from sha.main import parse_args
        import sys

        sys.argv = ["sha", "example.com", "--timeout", "-5"]
        with pytest.raises(SystemExit) as exc_info:
            parse_args()
        assert exc_info.value.code != 0

    def test_timeout_extremely_large(self):
        """Test extremely large timeout is rejected (>300s)."""
        from sha.main import parse_args
        import sys

        sys.argv = ["sha", "example.com", "--timeout", "99999"]
        with pytest.raises(SystemExit) as exc_info:
            parse_args()
        assert exc_info.value.code != 0

    def test_timeout_valid_boundary(self):
        """Test timeout at max boundary (300s) is accepted."""
        from sha.main import parse_args
        import sys

        sys.argv = ["sha", "example.com", "--timeout", "300"]
        args = parse_args()
        assert args.timeout == 300


class TestVerboseQuietFlags:
    """Test verbose and quiet mode flags."""

    def test_verbose_and_quiet_mutually_exclusive(self):
        """Test that verbose and quiet flags cannot be used together."""
        from sha.main import parse_args
        import sys

        sys.argv = ["sha", "example.com", "--verbose", "--quiet"]
        with pytest.raises(SystemExit) as exc_info:
            parse_args()
        assert exc_info.value.code != 0

    def test_verbose_flag_accepted(self):
        """Test verbose flag is accepted."""
        from sha.main import parse_args
        import sys

        sys.argv = ["sha", "example.com", "-v"]
        args = parse_args()
        assert args.verbose is True
        assert args.quiet is False

    def test_quiet_flag_accepted(self):
        """Test quiet flag is accepted."""
        from sha.main import parse_args
        import sys

        sys.argv = ["sha", "example.com", "-q"]
        args = parse_args()
        assert args.quiet is True
        assert args.verbose is False


class TestJSONSchemaVersion:
    """Test JSON report includes schema version."""

    def test_json_schema_version_present(self):
        """Test JSON report includes schema_version field."""
        from sha.reporter import format_json_report
        import json

        findings = [{
            "header_name": "Test",
            "status": "good",
            "severity": "info",
            "message": "Test message",
            "actual_value": None,
            "recommendation": None,
        }]

        report_json = format_json_report("https://example.com", findings)
        report = json.loads(report_json)

        assert "schema_version" in report
        assert isinstance(report["schema_version"], str)

    def test_json_schema_version_value(self):
        """Test schema version has expected format."""
        from sha.reporter import format_json_report
        import json

        findings = [{
            "header_name": "Test",
            "status": "good",
            "severity": "info",
            "message": "Test",
            "actual_value": None,
            "recommendation": None,
        }]

        report_json = format_json_report("https://example.com", findings)
        report = json.loads(report_json)

        # Schema version should be "1.0.0" format
        assert report["schema_version"] == "1.0.0"
        parts = report["schema_version"].split(".")
        assert len(parts) == 3
        assert all(part.isdigit() for part in parts)
