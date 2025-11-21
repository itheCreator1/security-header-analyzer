"""
Tests for Referrer-Policy header analyzer.

Tests analysis logic for the Referrer-Policy header including
various policy values from most to least restrictive.
"""

import pytest
from sha.analyzer import analyze_referrer_policy
from sha.config import STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING


class TestAnalyzeReferrerPolicy:
    """Test Referrer-Policy header analysis."""

    def test_analyze_referrer_policy_missing(self):
        """Test missing Referrer-Policy header."""
        finding = analyze_referrer_policy(None)

        assert finding["header_name"] == "Referrer-Policy"
        assert finding["status"] == STATUS_MISSING
        assert finding["severity"] == "high"
        assert finding["actual_value"] is None
        assert finding["recommendation"] is not None
        assert "strict-origin" in finding["recommendation"]

    def test_analyze_referrer_policy_strict_origin(self):
        """Test best practice strict-origin value."""
        finding = analyze_referrer_policy("strict-origin")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"
        assert finding["actual_value"] == "strict-origin"
        assert finding["recommendation"] is None

    def test_analyze_referrer_policy_no_referrer(self):
        """Test best practice no-referrer value."""
        finding = analyze_referrer_policy("no-referrer")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"
        assert finding["actual_value"] == "no-referrer"
        assert finding["recommendation"] is None

    def test_analyze_referrer_policy_strict_origin_when_cross_origin(self):
        """Test acceptable strict-origin-when-cross-origin value."""
        finding = analyze_referrer_policy("strict-origin-when-cross-origin")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"
        assert finding["actual_value"] == "strict-origin-when-cross-origin"
        # This is the recommended default, so no recommendation needed
        assert finding["recommendation"] is None

    def test_analyze_referrer_policy_same_origin(self):
        """Test acceptable same-origin value."""
        finding = analyze_referrer_policy("same-origin")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"
        assert finding["actual_value"] == "same-origin"
        assert finding["recommendation"] is None

    def test_analyze_referrer_policy_origin(self):
        """Test acceptable origin value with suggestion."""
        finding = analyze_referrer_policy("origin")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"
        assert finding["actual_value"] == "origin"
        # Should suggest upgrading to strict-origin
        assert finding["recommendation"] is not None
        assert "strict-origin" in finding["recommendation"]

    def test_analyze_referrer_policy_origin_when_cross_origin(self):
        """Test acceptable origin-when-cross-origin value with suggestion."""
        finding = analyze_referrer_policy("origin-when-cross-origin")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"
        assert finding["actual_value"] == "origin-when-cross-origin"
        # Should suggest upgrading to strict-origin
        assert finding["recommendation"] is not None
        assert "strict-origin" in finding["recommendation"]

    def test_analyze_referrer_policy_unsafe_url(self):
        """Test bad unsafe-url value."""
        finding = analyze_referrer_policy("unsafe-url")

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "high"
        assert finding["actual_value"] == "unsafe-url"
        assert finding["recommendation"] is not None
        assert "leak" in finding["message"].lower() or "sensitive" in finding["message"].lower()

    def test_analyze_referrer_policy_no_referrer_when_downgrade(self):
        """Test bad no-referrer-when-downgrade value."""
        finding = analyze_referrer_policy("no-referrer-when-downgrade")

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "high"
        assert finding["actual_value"] == "no-referrer-when-downgrade"
        assert finding["recommendation"] is not None

    def test_analyze_referrer_policy_case_insensitive(self):
        """Test Referrer-Policy is case insensitive."""
        finding_upper = analyze_referrer_policy("STRICT-ORIGIN")
        finding_mixed = analyze_referrer_policy("Strict-Origin")
        finding_lower = analyze_referrer_policy("strict-origin")

        assert finding_upper["status"] == STATUS_GOOD
        assert finding_mixed["status"] == STATUS_GOOD
        assert finding_lower["status"] == STATUS_GOOD

    def test_analyze_referrer_policy_whitespace_handling(self):
        """Test Referrer-Policy handles whitespace."""
        finding = analyze_referrer_policy("  strict-origin  ")

        assert finding["status"] == STATUS_GOOD
        assert finding["actual_value"] == "  strict-origin  "  # Original value preserved

    def test_analyze_referrer_policy_unknown_value(self):
        """Test unknown Referrer-Policy value is treated as bad."""
        finding = analyze_referrer_policy("invalid-policy")

        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "high"
        assert finding["actual_value"] == "invalid-policy"
        assert "unknown value" in finding["message"]
        assert finding["recommendation"] is not None

    def test_analyze_referrer_policy_comma_separated_values(self):
        """Test comma-separated values (fallback mechanism)."""
        # First value takes precedence
        finding = analyze_referrer_policy("origin-when-cross-origin, strict-origin-when-cross-origin")

        assert finding["status"] == STATUS_ACCEPTABLE
        assert finding["severity"] == "low"
        # Should evaluate based on first value (origin-when-cross-origin)
        assert finding["recommendation"] is not None
        assert "strict-origin" in finding["recommendation"]

    def test_analyze_referrer_policy_comma_separated_best_value_first(self):
        """Test comma-separated values with best value first."""
        finding = analyze_referrer_policy("strict-origin, no-referrer")

        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"
        assert finding["recommendation"] is None
