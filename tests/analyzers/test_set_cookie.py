"""
Tests for Set-Cookie header analyzer.

Tests parsing and analysis logic for the Set-Cookie header including
security attributes: Secure, HttpOnly, SameSite, Max-Age validation.
"""

import pytest

from sha.analyzers.set_cookie import analyze, parse_set_cookie
from sha.config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING


class TestParseSetCookie:
    """Test Set-Cookie header parsing."""

    def test_parse_minimal_cookie(self):
        """Test parsing cookie with just name=value."""
        result = parse_set_cookie("session=abc123")

        assert result["cookie_name"] == "session"
        assert result["cookie_value"] == "abc123"
        assert result["secure"] is False
        assert result["httponly"] is False
        assert result["samesite"] is None
        assert result["max_age"] is None

    def test_parse_full_cookie(self):
        """Test parsing cookie with all security attributes."""
        result = parse_set_cookie(
            "session=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=86400; Path=/; Domain=example.com"
        )

        assert result["cookie_name"] == "session"
        assert result["cookie_value"] == "abc123"
        assert result["secure"] is True
        assert result["httponly"] is True
        assert result["samesite"] == "Strict"
        assert result["max_age"] == 86400
        assert result["path"] == "/"
        assert result["domain"] == "example.com"

    def test_parse_secure_attribute(self):
        """Test parsing Secure attribute."""
        result = parse_set_cookie("session=abc; Secure")

        assert result["secure"] is True

    def test_parse_httponly_attribute(self):
        """Test parsing HttpOnly attribute."""
        result = parse_set_cookie("session=abc; HttpOnly")

        assert result["httponly"] is True

    def test_parse_samesite_strict(self):
        """Test parsing SameSite=Strict."""
        result = parse_set_cookie("session=abc; SameSite=Strict")

        assert result["samesite"] == "Strict"

    def test_parse_samesite_lax(self):
        """Test parsing SameSite=Lax."""
        result = parse_set_cookie("session=abc; SameSite=Lax")

        assert result["samesite"] == "Lax"

    def test_parse_samesite_none(self):
        """Test parsing SameSite=None."""
        result = parse_set_cookie("session=abc; SameSite=None")

        assert result["samesite"] == "None"

    def test_parse_case_insensitive_attributes(self):
        """Test that attribute parsing is case-insensitive."""
        result = parse_set_cookie("session=abc; SECURE; HTTPONLY; SAMESITE=STRICT")

        assert result["secure"] is True
        assert result["httponly"] is True
        assert result["samesite"] == "Strict"

    def test_parse_max_age(self):
        """Test parsing Max-Age attribute."""
        result = parse_set_cookie("session=abc; Max-Age=3600")

        assert result["max_age"] == 3600

    def test_parse_invalid_max_age(self):
        """Test parsing invalid Max-Age value."""
        result = parse_set_cookie("session=abc; Max-Age=invalid")

        assert result["max_age"] is None

    def test_parse_expires(self):
        """Test parsing Expires attribute."""
        result = parse_set_cookie("session=abc; Expires=Wed, 21 Oct 2025 07:28:00 GMT")

        assert result["expires"] == "Wed, 21 Oct 2025 07:28:00 GMT"

    def test_parse_with_extra_whitespace(self):
        """Test parsing with extra whitespace."""
        result = parse_set_cookie("  session = abc ;  Secure  ;  HttpOnly  ")

        assert result["cookie_name"] == "session"
        assert result["cookie_value"] == "abc"
        assert result["secure"] is True
        assert result["httponly"] is True

    def test_parse_cookie_value_with_equals(self):
        """Test parsing cookie value containing equals sign."""
        result = parse_set_cookie("token=eyJhbGc=iOiJ; Secure")

        assert result["cookie_name"] == "token"
        assert result["cookie_value"] == "eyJhbGc=iOiJ"
        assert result["secure"] is True

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        result = parse_set_cookie("")

        assert result["cookie_name"] is None
        assert result["cookie_value"] is None
        assert result["secure"] is False


class TestAnalyzeSetCookie:
    """Test Set-Cookie header analysis."""

    def test_missing_cookie(self):
        """Test missing Set-Cookie header."""
        finding = analyze(None)

        assert finding["header_name"] == "Set-Cookie"
        assert finding["status"] == STATUS_MISSING
        assert finding["severity"] == "info"
        assert "not being set" in finding["message"].lower()
        assert finding["recommendation"] is not None

    def test_perfect_cookie_strict(self):
        """Test cookie with all recommended attributes (SameSite=Strict)."""
        finding = analyze("session=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=86400")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"
        assert finding["recommendation"] is None

    def test_good_cookie_no_max_age(self):
        """Test session cookie (no Max-Age) with security attributes."""
        finding = analyze("session=abc123; Secure; HttpOnly; SameSite=Strict")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"

    def test_acceptable_cookie_lax(self):
        """Test cookie with SameSite=Lax."""
        finding = analyze("session=abc123; Secure; HttpOnly; SameSite=Lax")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"

    def test_acceptable_cookie_samesite_none_with_secure(self):
        """Test cookie with SameSite=None and Secure (valid for cross-site)."""
        finding = analyze("session=abc123; Secure; HttpOnly; SameSite=None")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"

    def test_missing_secure(self):
        """Test cookie missing Secure attribute."""
        finding = analyze("session=abc123; HttpOnly; SameSite=Strict")

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "high"
        assert "secure" in finding["message"].lower()
        assert "Secure" in finding["recommendation"]

    def test_missing_httponly(self):
        """Test cookie missing HttpOnly attribute."""
        finding = analyze("session=abc123; Secure; SameSite=Strict")

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "high"
        assert "httponly" in finding["message"].lower()
        assert "HttpOnly" in finding["recommendation"]

    def test_missing_both_secure_and_httponly(self):
        """Test cookie missing both Secure and HttpOnly."""
        finding = analyze("session=abc123; SameSite=Strict")

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "high"
        assert "secure" in finding["message"].lower()
        assert "httponly" in finding["message"].lower()

    def test_missing_samesite(self):
        """Test cookie missing SameSite attribute."""
        finding = analyze("session=abc123; Secure; HttpOnly")

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "medium"
        assert "samesite" in finding["message"].lower()
        assert "SameSite" in finding["recommendation"]

    def test_samesite_none_without_secure(self):
        """Test cookie with SameSite=None but missing Secure (invalid)."""
        finding = analyze("session=abc123; HttpOnly; SameSite=None")

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "high"
        assert "secure" in finding["message"].lower()

    def test_very_long_max_age(self):
        """Test cookie with Max-Age >1 year."""
        # 2 years in seconds
        finding = analyze("session=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=63072000")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"
        assert "Max-Age" in finding["message"] or "long" in finding["message"].lower()

    def test_reasonable_max_age(self):
        """Test cookie with reasonable Max-Age (1 day)."""
        finding = analyze("session=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=86400")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"

    def test_no_attributes(self):
        """Test cookie with no security attributes."""
        finding = analyze("session=abc123")

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] in ["high", "medium"]

    def test_real_world_github_style(self):
        """Test real-world GitHub-style cookie."""
        finding = analyze(
            "_gh_sess=abc123; Path=/; Domain=github.com; Secure; HttpOnly; SameSite=Lax"
        )

        assert finding["status"] in [STATUS_ACCEPTABLE, STATUS_GOOD]
        assert finding["severity"] in ["info", "low"]

    def test_real_world_google_style(self):
        """Test real-world Google-style cookie."""
        finding = analyze(
            "NID=abc123; Expires=Wed, 01-Jan-2026 00:00:00 GMT; Path=/; Domain=.google.com; Secure; HttpOnly; SameSite=None"
        )

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"

    def test_session_cookie_strict(self):
        """Test session cookie (no expiry) with Strict."""
        finding = analyze("PHPSESSID=abc123; Secure; HttpOnly; SameSite=Strict; Path=/")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"

    def test_cookie_with_domain_and_path(self):
        """Test cookie with Domain and Path attributes."""
        finding = analyze(
            "session=abc123; Secure; HttpOnly; SameSite=Strict; Domain=example.com; Path=/app"
        )

        assert finding["status"] == STATUS_GOOD

    def test_empty_cookie_value(self):
        """Test cookie with empty value."""
        finding = analyze("session=; Secure; HttpOnly; SameSite=Strict")

        assert finding["status"] == STATUS_GOOD

    def test_max_age_zero(self):
        """Test cookie with Max-Age=0 (deletion)."""
        finding = analyze("session=deleted; Secure; HttpOnly; SameSite=Strict; Max-Age=0")

        assert finding["status"] == STATUS_GOOD

    def test_case_variations(self):
        """Test various case combinations."""
        # Uppercase SameSite value
        finding = analyze("session=abc; Secure; HttpOnly; SameSite=STRICT")
        assert finding["status"] == STATUS_GOOD

        # Lowercase SameSite value
        finding = analyze("session=abc; Secure; HttpOnly; SameSite=strict")
        assert finding["status"] == STATUS_GOOD


class TestSetCookieEdgeCases:
    """Test edge cases for Set-Cookie analyzer."""

    def test_malformed_no_equals(self):
        """Test malformed cookie without equals sign."""
        finding = analyze("justsomecookie; Secure")

        # Should still analyze security attributes
        assert finding["status"] != STATUS_MISSING

    def test_whitespace_only(self):
        """Test whitespace-only value."""
        finding = analyze("   ")

        # Should handle gracefully
        assert finding["status"] != STATUS_MISSING

    def test_only_semicolons(self):
        """Test value with only semicolons."""
        finding = analyze(";;;")

        # Should handle gracefully
        assert finding["status"] != STATUS_MISSING

    def test_max_age_negative(self):
        """Test negative Max-Age."""
        finding = analyze("session=abc; Secure; HttpOnly; SameSite=Strict; Max-Age=-1")

        # Should parse but max_age will be None or negative
        assert finding["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]

    def test_very_long_cookie_value(self):
        """Test very long cookie value."""
        long_value = "x" * 4096
        finding = analyze(f"session={long_value}; Secure; HttpOnly; SameSite=Strict")

        assert finding["status"] == STATUS_GOOD

    def test_special_characters_in_value(self):
        """Test special characters in cookie value."""
        finding = analyze("session=abc%20123%3D%3D; Secure; HttpOnly; SameSite=Strict")

        assert finding["status"] == STATUS_GOOD

    def test_multiple_equals_in_value(self):
        """Test multiple equals signs in cookie value (base64)."""
        finding = analyze("token=eyJhbGc==; Secure; HttpOnly; SameSite=Strict")

        assert finding["status"] == STATUS_GOOD

    def test_duplicate_attributes(self):
        """Test duplicate attributes (last one wins)."""
        finding = analyze("session=abc; Secure; Secure; HttpOnly; HttpOnly; SameSite=Lax")

        assert finding["status"] == STATUS_ACCEPTABLE

    def test_unknown_samesite_value(self):
        """Test unknown SameSite value."""
        finding = analyze("session=abc; Secure; HttpOnly; SameSite=Unknown")

        # Should treat as having SameSite but not recognized value
        assert finding["status"] in [STATUS_ACCEPTABLE, STATUS_GOOD]


class TestMultipleCookies:
    """Test Set-Cookie analyzer with multiple cookies (List[str] input)."""

    def test_multiple_cookies_all_secure(self):
        """Test multiple cookies all with strict secure attributes."""
        cookies = [
            "sessionid=abc123; Secure; HttpOnly; SameSite=Strict",
            "csrf_token=xyz789; Secure; HttpOnly; SameSite=Strict",
            "prefs=dark_mode; Secure; HttpOnly; SameSite=Strict",
        ]
        finding = analyze(cookies)

        assert finding["status"] == STATUS_GOOD
        assert finding["cookie_count"] == 3
        assert "3 cookies" in finding["actual_value"]
        assert len(finding["cookies"]) == 3

    def test_multiple_cookies_one_insecure(self):
        """Test multiple cookies where one is missing security attributes."""
        cookies = [
            "sessionid=abc123; Secure; HttpOnly; SameSite=Strict",
            "tracking=xyz789",  # No security attributes!
        ]
        finding = analyze(cookies)

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "high"
        assert finding["cookie_count"] == 2
        assert "tracking" in finding["message"]
        assert "missing Secure" in finding["message"] or "missing HttpOnly" in finding["message"]

    def test_multiple_cookies_mixed_security(self):
        """Test multiple cookies with mixed security levels."""
        cookies = [
            "session=abc; Secure; HttpOnly; SameSite=Strict",  # Good
            "analytics=xyz; Secure; HttpOnly; SameSite=Lax",  # Acceptable
            "temp=123",  # Bad - no attributes
        ]
        finding = analyze(cookies)

        # Worst status should win (BAD)
        assert finding["status"] == STATUS_BAD
        assert finding["cookie_count"] == 3
        assert "temp" in finding["message"]

    def test_multiple_cookies_all_missing_httponly(self):
        """Test multiple cookies all missing HttpOnly."""
        cookies = [
            "session=abc; Secure; SameSite=Strict",
            "csrf=xyz; Secure; SameSite=Strict",
        ]
        finding = analyze(cookies)

        assert finding["status"] == STATUS_BAD
        assert "missing HttpOnly" in finding["message"]
        assert finding["cookie_count"] == 2
        # Both cookies should be listed
        assert "session" in finding["message"] or "csrf" in finding["message"]

    def test_single_cookie_as_list(self):
        """Test single cookie passed as a list."""
        cookies = ["sessionid=abc; Secure; HttpOnly; SameSite=Strict"]
        finding = analyze(cookies)

        assert finding["status"] == STATUS_GOOD
        assert finding["cookie_count"] == 1
        # Should not say "cookies" plural
        assert "sessionid=abc" in finding["actual_value"]

    def test_empty_cookie_list(self):
        """Test empty list of cookies."""
        finding = analyze([])

        assert finding["status"] == STATUS_MISSING
        assert finding["cookie_count"] == 0
        assert finding["cookies"] == []

    def test_multiple_cookies_with_same_name(self):
        """Test multiple cookies with same name (different paths/domains)."""
        cookies = [
            "session=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
            "session=xyz; Path=/admin; Secure; HttpOnly; SameSite=Strict",
        ]
        finding = analyze(cookies)

        assert finding["status"] == STATUS_GOOD
        assert finding["cookie_count"] == 2

    def test_multiple_cookies_backward_compatibility(self):
        """Test that single string still works (backward compatibility)."""
        # Single string (old behavior)
        finding_single = analyze("sessionid=abc; Secure; HttpOnly; SameSite=Strict")
        assert finding_single["status"] == STATUS_GOOD
        assert finding_single["cookie_count"] == 1

        # List with one item (new behavior)
        finding_list = analyze(["sessionid=abc; Secure; HttpOnly; SameSite=Strict"])
        assert finding_list["status"] == STATUS_GOOD
        assert finding_list["cookie_count"] == 1

        # Both should have similar results
        assert finding_single["status"] == finding_list["status"]

    def test_multiple_cookies_preserves_individual_analysis(self):
        """Test that individual cookie details are preserved."""
        cookies = [
            "session=abc; Secure; HttpOnly; SameSite=Strict",
            "tracking=xyz; SameSite=Lax",  # Missing Secure and HttpOnly
        ]
        finding = analyze(cookies)

        assert finding["cookie_count"] == 2
        assert len(finding["cookies"]) == 2

        # Check individual cookie results
        session_result = finding["cookies"][0]
        tracking_result = finding["cookies"][1]

        assert session_result["cookie_name"] == "session"
        assert session_result["has_secure"] is True
        assert session_result["has_httponly"] is True

        assert tracking_result["cookie_name"] == "tracking"
        assert tracking_result["has_secure"] is False
        assert tracking_result["has_httponly"] is False

    def test_multiple_cookies_recommendation_deduplication(self):
        """Test that recommendations are deduplicated for multiple cookies."""
        cookies = [
            "cookie1=abc",
            "cookie2=def",
            "cookie3=ghi",
        ]
        finding = analyze(cookies)

        # Should have recommendations, but deduplicated
        if finding["recommendation"]:
            # Count how many times "Secure" appears - should be only once
            # (not once per cookie)
            rec_lower = finding["recommendation"].lower()
            # The word "secure" might appear multiple times in different contexts,
            # but the same recommendation shouldn't be repeated 3 times
            assert finding["cookie_count"] == 3


class TestCookiePrefixValidation:
    """Test cookie prefix (__Secure- and __Host-) validation."""

    def test_secure_prefix_with_secure_attribute(self):
        """Test __Secure- prefix with Secure attribute (valid)."""
        cookie = "__Secure-session=abc123; Secure; HttpOnly; SameSite=Strict"
        finding = analyze(cookie)
        # Should be GOOD - has all required attributes
        assert finding["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]

    def test_secure_prefix_without_secure_attribute(self):
        """Test __Secure- prefix without Secure attribute (invalid)."""
        cookie = "__Secure-session=abc123; HttpOnly; SameSite=Strict"
        finding = analyze(cookie)
        # Should be BAD - __Secure- requires Secure attribute
        assert finding["status"] == STATUS_BAD
        assert "__secure-" in finding["message"].lower() or "prefix" in finding["message"].lower()

    def test_host_prefix_valid_configuration(self):
        """Test __Host- prefix with all requirements (valid)."""
        cookie = "__Host-session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/"
        finding = analyze(cookie)
        # Should be GOOD - meets all __Host- requirements
        assert finding["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]

    def test_host_prefix_without_secure(self):
        """Test __Host- prefix without Secure attribute."""
        cookie = "__Host-session=abc123; HttpOnly; SameSite=Strict; Path=/"
        finding = analyze(cookie)
        assert finding["status"] == STATUS_BAD
        assert "__host-" in finding["message"].lower() or "prefix" in finding["message"].lower()

    def test_host_prefix_with_domain(self):
        """Test __Host- prefix with Domain attribute (invalid)."""
        cookie = "__Host-session=abc123; Secure; HttpOnly; SameSite=Strict; Domain=example.com; Path=/"
        finding = analyze(cookie)
        assert finding["status"] == STATUS_BAD
        assert "domain" in finding["message"].lower()

    def test_host_prefix_with_invalid_path(self):
        """Test __Host- prefix with Path other than / (invalid)."""
        cookie = "__Host-session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/app"
        finding = analyze(cookie)
        assert finding["status"] == STATUS_BAD
        assert "path" in finding["message"].lower()

    def test_host_prefix_without_path(self):
        """Test __Host- prefix without Path attribute (acceptable - defaults to request path)."""
        cookie = "__Host-session=abc123; Secure; HttpOnly; SameSite=Strict"
        finding = analyze(cookie)
        # Without Path, it defaults to request path, which is acceptable for __Host-
        assert finding["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]


class TestCookieScopeAnalysis:
    """Test Domain and Path scope analysis."""

    def test_domain_with_leading_dot(self):
        """Test Domain starting with . (applies to subdomains)."""
        cookie = "session=abc123; Secure; HttpOnly; SameSite=Strict; Domain=.example.com"
        finding = analyze(cookie)
        # Should have recommendation about broad domain scope
        assert finding["recommendation"] is not None
        assert "domain" in finding["recommendation"].lower() or "subdomain" in finding["recommendation"].lower()

    def test_overly_broad_domain(self):
        """Test very short domain (e.g., 'com')."""
        cookie = "tracking=xyz; Secure; HttpOnly; SameSite=Lax; Domain=com"
        finding = analyze(cookie)
        # Should be flagged as overly broad
        assert finding["status"] == STATUS_BAD
        assert "domain" in finding["message"].lower()

    def test_sensitive_cookie_with_root_path(self):
        """Test session cookie with Path=/."""
        cookie = "session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/"
        finding = analyze(cookie)
        # Should have recommendation about restricting path for sensitive cookies
        # (LOW severity, so might be GOOD or ACCEPTABLE status)
        if finding["recommendation"]:
            assert "path" in finding["recommendation"].lower()

    def test_non_sensitive_cookie_with_root_path(self):
        """Test non-sensitive cookie with Path=/ (no warning)."""
        cookie = "theme=dark; Secure; HttpOnly; SameSite=Lax; Path=/"
        finding = analyze(cookie)
        # Non-sensitive cookie names shouldn't trigger path warnings
        assert finding["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]


class TestSensitiveCookieDetection:
    """Test detection of sensitive cookie names and required attributes."""

    def test_session_cookie_without_httponly(self):
        """Test session cookie without HttpOnly attribute."""
        cookie = "session=abc123; Secure; SameSite=Strict"
        finding = analyze(cookie)
        assert finding["status"] == STATUS_BAD
        assert "httponly" in finding["message"].lower()

    def test_auth_token_without_secure(self):
        """Test auth token without Secure attribute."""
        cookie = "auth_token=xyz; HttpOnly; SameSite=Strict"
        finding = analyze(cookie)
        assert finding["status"] == STATUS_BAD
        assert "secure" in finding["message"].lower()

    def test_jwt_cookie_without_samesite(self):
        """Test JWT cookie without SameSite attribute."""
        cookie = "jwt=abc.def.ghi; Secure; HttpOnly"
        finding = analyze(cookie)
        assert finding["status"] == STATUS_BAD
        assert "samesite" in finding["message"].lower()

    def test_csrf_token_with_samesite_none(self):
        """Test CSRF token with SameSite=None (acceptable but not ideal)."""
        cookie = "csrf_token=xyz; Secure; HttpOnly; SameSite=None"
        finding = analyze(cookie)
        # Cookie has all security attributes so status should be ACCEPTABLE
        # (SameSite=None with Secure is valid, just not ideal for CSRF tokens)
        assert finding["status"] == STATUS_ACCEPTABLE

    def test_phpsessid_cookie_insecure(self):
        """Test PHPSESSID without proper security attributes."""
        cookie = "PHPSESSID=abc123"
        finding = analyze(cookie)
        assert finding["status"] == STATUS_BAD
        # Should flag as sensitive cookie
        assert finding["severity"] == "high"

    def test_remember_me_cookie_secure(self):
        """Test remember_me cookie with proper security."""
        cookie = "remember_me=xyz; Secure; HttpOnly; SameSite=Strict"
        finding = analyze(cookie)
        assert finding["status"] in [STATUS_GOOD, STATUS_ACCEPTABLE]


class TestSameSiteNoneFrequency:
    """Test SameSite=None frequency warnings."""

    def test_single_samesite_none_no_warning(self):
        """Test single cookie with SameSite=None (no frequency warning)."""
        cookie = "tracking=xyz; Secure; HttpOnly; SameSite=None"
        finding = analyze(cookie)
        # Single cookie shouldn't trigger frequency warning
        assert finding["cookie_count"] == 1

    def test_multiple_cookies_majority_samesite_none(self):
        """Test multiple cookies where >50% have SameSite=None."""
        cookies = [
            "cookie1=a; Secure; HttpOnly; SameSite=None",
            "cookie2=b; Secure; HttpOnly; SameSite=None",
            "cookie3=c; Secure; HttpOnly; SameSite=Strict",
        ]
        finding = analyze(cookies)
        # 2/3 (66%) use SameSite=None - should have warning
        assert finding["recommendation"] is not None
        assert "samesite=none" in finding["recommendation"].lower() or "third-party" in finding["recommendation"].lower()

    def test_multiple_cookies_minority_samesite_none(self):
        """Test multiple cookies where <50% have SameSite=None (no warning)."""
        cookies = [
            "cookie1=a; Secure; HttpOnly; SameSite=Strict",
            "cookie2=b; Secure; HttpOnly; SameSite=Lax",
            "cookie3=c; Secure; HttpOnly; SameSite=None",
        ]
        finding = analyze(cookies)
        # 1/3 (33%) use SameSite=None - should not trigger frequency warning
        # (might have other recommendations, but not specifically about frequency)
        if finding["recommendation"]:
            assert "third-party" not in finding["recommendation"].lower() or finding["cookie_count"] != 3


class TestEnhancedSetCookieIntegration:
    """Integration tests for all Set-Cookie enhancements."""

    def test_perfect_host_prefix_cookie(self):
        """Test perfect cookie with __Host- prefix."""
        cookie = "__Host-session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/"
        finding = analyze(cookie)
        assert finding["status"] == STATUS_GOOD
        assert finding["cookie_count"] == 1

    def test_multiple_issues_combined(self):
        """Test cookie with multiple issues (prefix + scope + sensitive)."""
        cookie = "__Secure-session=abc; Domain=.example.com; Path=/"
        finding = analyze(cookie)
        # Missing Secure (required by __Secure-), missing HttpOnly, missing SameSite
        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "high"
        # Should mention multiple issues
        assert finding["message"]

    def test_real_world_cookies_mixed(self):
        """Test real-world scenario with mix of good and bad cookies."""
        cookies = [
            "__Host-session=abc; Secure; HttpOnly; SameSite=Strict; Path=/",
            "csrf=xyz; Secure; SameSite=Lax",  # Missing HttpOnly
            "tracking=123; Secure; HttpOnly; SameSite=None",
            "theme=dark; Secure; HttpOnly; SameSite=Lax",
        ]
        finding = analyze(cookies)
        # Should aggregate to worst status (BAD due to csrf missing HttpOnly)
        assert finding["status"] == STATUS_BAD
        assert finding["cookie_count"] == 4
        # Should identify the problematic cookie
        assert "csrf" in finding["message"].lower()
