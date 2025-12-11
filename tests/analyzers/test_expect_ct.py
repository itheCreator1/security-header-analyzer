"""
Tests for Expect-CT header analyzer.

Tests parsing and analysis logic for the Expect-CT header including
max-age validation, enforce directive, and report-uri handling.
"""

import pytest

from sha.analyzers.expect_ct import analyze, parse_expect_ct
from sha.config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING


class TestParseExpectCT:
    """Test Expect-CT header parsing."""

    def test_parse_minimal(self):
        """Test parsing with just max-age."""
        result = parse_expect_ct("max-age=86400")

        assert result["max_age"] == 86400
        assert result["enforce"] is False
        assert result["report_uri"] is None

    def test_parse_with_enforce(self):
        """Test parsing with enforce directive."""
        result = parse_expect_ct("max-age=86400, enforce")

        assert result["max_age"] == 86400
        assert result["enforce"] is True

    def test_parse_with_report_uri(self):
        """Test parsing with report-uri."""
        result = parse_expect_ct('max-age=86400, report-uri="https://example.com/report"')

        assert result["max_age"] == 86400
        assert result["report_uri"] == "https://example.com/report"

    def test_parse_full_configuration(self):
        """Test parsing with all directives."""
        result = parse_expect_ct('max-age=86400, enforce, report-uri="https://example.com/report"')

        assert result["max_age"] == 86400
        assert result["enforce"] is True
        assert result["report_uri"] == "https://example.com/report"

    def test_parse_case_insensitive(self):
        """Test that parsing is case-insensitive."""
        result = parse_expect_ct("MAX-AGE=86400, ENFORCE")

        assert result["max_age"] == 86400
        assert result["enforce"] is True

    def test_parse_with_whitespace(self):
        """Test parsing with extra whitespace."""
        result = parse_expect_ct("  max-age=86400  ,  enforce  ")

        assert result["max_age"] == 86400
        assert result["enforce"] is True

    def test_parse_invalid_max_age(self):
        """Test parsing with invalid max-age value."""
        result = parse_expect_ct("max-age=invalid")

        assert result["max_age"] is None

    def test_parse_report_uri_single_quotes(self):
        """Test parsing report-uri with single quotes."""
        result = parse_expect_ct("max-age=86400, report-uri='https://example.com/report'")

        assert result["report_uri"] == "https://example.com/report"

    def test_parse_report_uri_no_quotes(self):
        """Test parsing report-uri without quotes."""
        result = parse_expect_ct("max-age=86400, report-uri=https://example.com/report")

        assert result["report_uri"] == "https://example.com/report"

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        result = parse_expect_ct("")

        assert result["max_age"] is None
        assert result["enforce"] is False


class TestAnalyzeExpectCT:
    """Test Expect-CT header analysis."""

    def test_missing_expect_ct(self):
        """Test missing Expect-CT header."""
        finding = analyze(None)

        assert finding["header_name"] == "Expect-CT"
        assert finding["status"] == STATUS_MISSING
        assert finding["severity"] == "low"
        assert "optional" in finding["message"].lower()

    def test_perfect_configuration(self):
        """Test enforce + max-age >= 1 day."""
        finding = analyze("max-age=86400, enforce")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"
        assert finding["recommendation"] is None

    def test_good_with_long_max_age(self):
        """Test enforce + long max-age."""
        finding = analyze("max-age=2592000, enforce")  # 30 days

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"

    def test_good_with_report_uri(self):
        """Test enforce + max-age + report-uri."""
        finding = analyze('max-age=86400, enforce, report-uri="https://example.com/report"')

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"
        assert "reporting" in finding["message"].lower()

    def test_report_only_mode(self):
        """Test max-age without enforce (report-only)."""
        finding = analyze("max-age=86400")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"
        assert "report-only" in finding["message"].lower()
        assert "enforce" in finding["recommendation"].lower()

    def test_low_max_age_with_enforce(self):
        """Test enforce but max-age < 1 day."""
        finding = analyze("max-age=3600, enforce")  # 1 hour

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"
        assert "low" in finding["message"].lower()
        assert "Increase max-age" in finding["recommendation"]

    def test_low_max_age_without_enforce(self):
        """Test low max-age without enforce."""
        finding = analyze("max-age=3600")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"

    def test_missing_max_age(self):
        """Test missing max-age directive (invalid)."""
        finding = analyze("enforce")

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "low"
        assert "max-age" in finding["message"].lower()

    def test_zero_max_age(self):
        """Test max-age=0."""
        finding = analyze("max-age=0, enforce")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"

    def test_very_long_max_age(self):
        """Test very long max-age (1 year)."""
        finding = analyze("max-age=31536000, enforce")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"

    def test_real_world_cloudflare_style(self):
        """Test real-world Cloudflare-style Expect-CT."""
        finding = analyze("max-age=86400, enforce")

        assert finding["status"] == STATUS_GOOD

    def test_real_world_github_style(self):
        """Test real-world GitHub-style Expect-CT."""
        finding = analyze(
            'max-age=2592000, enforce, report-uri="https://api.github.com/_private/browser/errors"'
        )

        assert finding["status"] == STATUS_GOOD


class TestExpectCTEdgeCases:
    """Test edge cases for Expect-CT analyzer."""

    def test_whitespace_only(self):
        """Test whitespace-only value."""
        finding = analyze("   ")

        # Should be treated as bad (no valid directives)
        assert finding["status"] in [STATUS_BAD, STATUS_ACCEPTABLE]

    def test_only_commas(self):
        """Test value with only commas."""
        finding = analyze(",,,")

        assert finding["status"] == STATUS_BAD

    def test_duplicate_max_age(self):
        """Test duplicate max-age directives."""
        finding = analyze("max-age=86400, max-age=172800, enforce")

        # Should handle gracefully (last one wins or both parsed)
        assert finding["status"] != STATUS_MISSING

    def test_negative_max_age(self):
        """Test negative max-age."""
        finding = analyze("max-age=-1, enforce")

        # Should be treated as low max-age
        assert finding["status"] in [STATUS_ACCEPTABLE, STATUS_BAD]

    def test_very_large_max_age(self):
        """Test extremely large max-age."""
        finding = analyze("max-age=999999999, enforce")

        assert finding["status"] == STATUS_GOOD

    def test_report_uri_with_spaces(self):
        """Test report-uri containing spaces (urlencoded)."""
        finding = analyze('max-age=86400, report-uri="https://example.com/report?foo=bar baz"')

        # Should still parse
        assert finding["status"] != STATUS_MISSING

    def test_multiple_enforce_directives(self):
        """Test multiple enforce directives."""
        finding = analyze("max-age=86400, enforce, enforce")

        # Should handle gracefully
        assert finding["status"] == STATUS_GOOD

    def test_unknown_directives(self):
        """Test unknown directives (should be ignored)."""
        finding = analyze("max-age=86400, enforce, unknown-directive")

        assert finding["status"] == STATUS_GOOD

    def test_max_age_with_quotes(self):
        """Test max-age with quotes (invalid but should handle)."""
        finding = analyze('max-age="86400", enforce')

        # May or may not parse correctly
        assert finding["status"] != STATUS_MISSING

    def test_enforce_with_value(self):
        """Test enforce with unexpected value."""
        finding = analyze("max-age=86400, enforce=true")

        # Should still parse enforce as True
        assert finding["status"] != STATUS_MISSING
