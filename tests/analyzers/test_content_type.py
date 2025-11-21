"""
Tests for X-Content-Type-Options header analyzer.

Tests analysis logic for the X-Content-Type-Options header
which should be set to 'nosniff' for security.
"""

import pytest
from sha.analyzer import analyze_content_type_options
from sha.config import STATUS_GOOD, STATUS_BAD, STATUS_MISSING


class TestAnalyzeContentTypeOptions:
    """Test X-Content-Type-Options header analysis."""

    def test_analyze_content_type_missing(self):
        """Test X-Content-Type-Options when missing."""
        result = analyze_content_type_options(None)

        assert result["header_name"] == "X-Content-Type-Options"
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == "medium-high"

    def test_analyze_content_type_nosniff(self):
        """Test X-Content-Type-Options with nosniff."""
        result = analyze_content_type_options("nosniff")

        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"
        assert result["recommendation"] is None

    def test_analyze_content_type_nosniff_case_insensitive(self):
        """Test nosniff is case insensitive."""
        result1 = analyze_content_type_options("nosniff")
        result2 = analyze_content_type_options("NOSNIFF")
        result3 = analyze_content_type_options("NoSniff")

        assert result1["status"] == result2["status"] == result3["status"] == STATUS_GOOD

    def test_analyze_content_type_wrong_value(self):
        """Test X-Content-Type-Options with wrong value."""
        result = analyze_content_type_options("wrong-value")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium-high"
        assert "nosniff" in result["recommendation"]
