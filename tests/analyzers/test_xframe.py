"""
Tests for X-Frame-Options header analyzer.

Tests analysis logic for the X-Frame-Options header including
DENY, SAMEORIGIN, and deprecated ALLOW-FROM directives.
"""

import pytest
from sha.analyzer import analyze_xframe
from sha.config import STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING


class TestAnalyzeXFrame:
    """Test X-Frame-Options header analysis."""

    def test_analyze_xframe_missing(self):
        """Test X-Frame-Options analysis when missing."""
        result = analyze_xframe(None)

        assert result["header_name"] == "X-Frame-Options"
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == "high"
        assert result["actual_value"] is None

    def test_analyze_xframe_deny(self):
        """Test X-Frame-Options with DENY."""
        result = analyze_xframe("DENY")

        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"
        assert result["recommendation"] is None

    def test_analyze_xframe_deny_case_insensitive(self):
        """Test DENY is case insensitive."""
        result1 = analyze_xframe("DENY")
        result2 = analyze_xframe("deny")
        result3 = analyze_xframe("Deny")

        assert result1["status"] == result2["status"] == result3["status"] == STATUS_GOOD

    def test_analyze_xframe_sameorigin(self):
        """Test X-Frame-Options with SAMEORIGIN."""
        result = analyze_xframe("SAMEORIGIN")

        assert result["status"] == STATUS_ACCEPTABLE
        assert result["severity"] == "low"
        assert result["recommendation"] is not None

    def test_analyze_xframe_sameorigin_case_insensitive(self):
        """Test SAMEORIGIN is case insensitive."""
        result1 = analyze_xframe("SAMEORIGIN")
        result2 = analyze_xframe("sameorigin")
        result3 = analyze_xframe("SameOrigin")

        assert result1["status"] == result2["status"] == result3["status"] == STATUS_ACCEPTABLE

    def test_analyze_xframe_allow_from(self):
        """Test X-Frame-Options with deprecated ALLOW-FROM."""
        result = analyze_xframe("ALLOW-FROM https://example.com")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "high"
        assert "deprecated" in result["message"].lower()

    def test_analyze_xframe_invalid_value(self):
        """Test X-Frame-Options with invalid value."""
        result = analyze_xframe("INVALID")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "high"
