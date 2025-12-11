"""
Tests for Cache-Control header analyzer.

Tests parsing and analysis logic for the Cache-Control header including
directives: no-store, no-cache, private, public, max-age, immutable.
"""

import pytest

from sha.analyzers.cache_control import analyze, parse_cache_control
from sha.config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING


class TestParseCacheControl:
    """Test Cache-Control header parsing."""

    def test_parse_no_store(self):
        """Test parsing no-store directive."""
        result = parse_cache_control("no-store")

        assert result["no_store"] is True
        assert result["no_cache"] is False
        assert result["private"] is False
        assert result["public"] is False

    def test_parse_no_cache(self):
        """Test parsing no-cache directive."""
        result = parse_cache_control("no-cache")

        assert result["no_cache"] is True
        assert result["no_store"] is False

    def test_parse_private(self):
        """Test parsing private directive."""
        result = parse_cache_control("private")

        assert result["private"] is True
        assert result["public"] is False

    def test_parse_public(self):
        """Test parsing public directive."""
        result = parse_cache_control("public")

        assert result["public"] is True
        assert result["private"] is False

    def test_parse_max_age(self):
        """Test parsing max-age directive."""
        result = parse_cache_control("max-age=3600")

        assert result["max_age"] == 3600

    def test_parse_max_age_zero(self):
        """Test parsing max-age=0."""
        result = parse_cache_control("max-age=0")

        assert result["max_age"] == 0

    def test_parse_s_maxage(self):
        """Test parsing s-maxage directive."""
        result = parse_cache_control("s-maxage=7200")

        assert result["s_maxage"] == 7200

    def test_parse_immutable(self):
        """Test parsing immutable directive."""
        result = parse_cache_control("immutable")

        assert result["immutable"] is True

    def test_parse_must_revalidate(self):
        """Test parsing must-revalidate directive."""
        result = parse_cache_control("must-revalidate")

        assert result["must_revalidate"] is True

    def test_parse_proxy_revalidate(self):
        """Test parsing proxy-revalidate directive."""
        result = parse_cache_control("proxy-revalidate")

        assert result["proxy_revalidate"] is True

    def test_parse_no_transform(self):
        """Test parsing no-transform directive."""
        result = parse_cache_control("no-transform")

        assert result["no_transform"] is True

    def test_parse_multiple_directives(self):
        """Test parsing multiple directives."""
        result = parse_cache_control("private, no-cache, must-revalidate")

        assert result["private"] is True
        assert result["no_cache"] is True
        assert result["must_revalidate"] is True

    def test_parse_complex_directive(self):
        """Test parsing complex directive combination."""
        result = parse_cache_control("public, max-age=31536000, immutable")

        assert result["public"] is True
        assert result["max_age"] == 31536000
        assert result["immutable"] is True

    def test_parse_case_insensitive(self):
        """Test that parsing is case-insensitive."""
        result = parse_cache_control("NO-STORE, PRIVATE")

        assert result["no_store"] is True
        assert result["private"] is True

    def test_parse_with_whitespace(self):
        """Test parsing with extra whitespace."""
        result = parse_cache_control("  no-store  ,  private  ,  max-age=3600  ")

        assert result["no_store"] is True
        assert result["private"] is True
        assert result["max_age"] == 3600

    def test_parse_invalid_max_age(self):
        """Test parsing invalid max-age value."""
        result = parse_cache_control("max-age=invalid")

        assert result["max_age"] is None

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        result = parse_cache_control("")

        assert result["no_store"] is False
        assert result["max_age"] is None


class TestAnalyzeCacheControl:
    """Test Cache-Control header analysis."""

    def test_missing_cache_control(self):
        """Test missing Cache-Control header."""
        finding = analyze(None)

        assert finding["header_name"] == "Cache-Control"
        assert finding["status"] == STATUS_MISSING
        assert finding["severity"] == "low"
        assert "missing" in finding["message"].lower()

    def test_no_store_good(self):
        """Test no-store directive (best for sensitive data)."""
        finding = analyze("no-store")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"
        assert "no-store" in finding["message"].lower()

    def test_max_age_zero_good(self):
        """Test max-age=0 (no caching)."""
        finding = analyze("max-age=0")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"

    def test_private_no_cache_good(self):
        """Test private + no-cache combination."""
        finding = analyze("private, no-cache")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"

    def test_public_bad(self):
        """Test public directive (warning for sensitive data)."""
        finding = analyze("public")

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "medium"
        assert "public" in finding["message"].lower()
        assert "sensitive" in finding["recommendation"].lower()

    def test_public_with_max_age_bad(self):
        """Test public with max-age (warning)."""
        finding = analyze("public, max-age=3600")

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "medium"

    def test_private_acceptable(self):
        """Test private directive (acceptable)."""
        finding = analyze("private")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] in ["info", "low"]

    def test_no_cache_acceptable(self):
        """Test no-cache directive (acceptable)."""
        finding = analyze("no-cache")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "info"

    def test_private_with_max_age(self):
        """Test private with reasonable max-age."""
        finding = analyze("private, max-age=3600")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] in ["info", "low"]

    def test_long_max_age_warning(self):
        """Test very long max-age without immutable (warning)."""
        # 2 years
        finding = analyze("private, max-age=63072000")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"
        assert (
            "long" in finding["message"].lower()
            or "Max-Age" in finding["recommendation"]
            or "long" in finding["recommendation"].lower()
        )

    def test_long_max_age_with_immutable(self):
        """Test long max-age with immutable (acceptable for static assets)."""
        finding = analyze("public, max-age=31536000, immutable")

        # Public is flagged, but that's expected
        assert finding["status"] == STATUS_BAD  # Due to public

    def test_no_store_private(self):
        """Test no-store with private (good)."""
        finding = analyze("no-store, private")

        assert finding["status"] == STATUS_GOOD

    def test_must_revalidate(self):
        """Test must-revalidate directive."""
        finding = analyze("private, max-age=3600, must-revalidate")

        assert finding["status"] == STATUS_ACCEPTABLE

    def test_real_world_sensitive_api(self):
        """Test real-world sensitive API response."""
        finding = analyze("no-store, no-cache, must-revalidate, private")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"

    def test_real_world_static_asset(self):
        """Test real-world static asset caching."""
        finding = analyze("public, max-age=31536000, immutable")

        # Public is flagged but appropriate for static assets
        assert finding["status"] == STATUS_BAD  # Generic warning about public

    def test_real_world_github_style(self):
        """Test real-world GitHub-style caching."""
        finding = analyze("private, max-age=0, must-revalidate")

        assert finding["status"] == STATUS_GOOD

    def test_real_world_cloudflare_style(self):
        """Test real-world Cloudflare-style caching."""
        finding = analyze("public, max-age=14400")

        assert finding["status"] == STATUS_BAD  # Public warning


class TestCacheControlEdgeCases:
    """Test edge cases for Cache-Control analyzer."""

    def test_only_commas(self):
        """Test value with only commas."""
        finding = analyze(",,,")

        # Should handle gracefully
        assert finding["status"] in [STATUS_ACCEPTABLE, STATUS_MISSING]

    def test_whitespace_only(self):
        """Test whitespace-only value."""
        finding = analyze("   ")

        assert finding["status"] in [STATUS_ACCEPTABLE, STATUS_MISSING]

    def test_unknown_directives(self):
        """Test unknown directives (should be ignored)."""
        finding = analyze("private, unknown-directive, max-age=3600")

        assert finding["status"] == STATUS_ACCEPTABLE

    def test_negative_max_age(self):
        """Test negative max-age."""
        finding = analyze("max-age=-1")

        # Should parse but be treated as cache control present
        assert finding["status"] != STATUS_MISSING

    def test_very_large_max_age(self):
        """Test extremely large max-age."""
        finding = analyze("max-age=999999999")

        assert finding["status"] in [STATUS_ACCEPTABLE, STATUS_BAD]

    def test_duplicate_directives(self):
        """Test duplicate directives (last wins)."""
        finding = analyze("max-age=100, max-age=200")

        # Should handle gracefully
        assert finding["status"] != STATUS_MISSING

    def test_conflicting_directives(self):
        """Test conflicting directives (private and public)."""
        finding = analyze("private, public")

        # Both will be set, analyzer should handle it
        assert finding["status"] != STATUS_MISSING

    def test_no_store_with_max_age(self):
        """Test no-store with max-age (no-store takes precedence)."""
        finding = analyze("no-store, max-age=3600")

        assert finding["status"] == STATUS_GOOD

    def test_quoted_values(self):
        """Test directives with quoted values (if any)."""
        finding = analyze('max-age="3600"')

        # May or may not parse correctly, should handle gracefully
        assert finding["status"] != STATUS_MISSING
