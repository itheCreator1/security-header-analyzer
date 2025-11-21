"""
Tests for HSTS (Strict-Transport-Security) header analyzer.

Tests parsing and analysis logic for the HSTS header including
max-age validation, includeSubDomains, and preload directives.
"""

import pytest
from sha.analyzer import analyze_hsts, parse_hsts
from sha.config import STATUS_GOOD, STATUS_ACCEPTABLE, STATUS_BAD, STATUS_MISSING


class TestParseHSTS:
    """Test HSTS header parsing."""

    def test_parse_hsts_full(self):
        """Test parsing HSTS with all directives."""
        result = parse_hsts("max-age=31536000; includeSubDomains; preload")

        assert result["max_age"] == 31536000
        assert result["include_subdomains"] is True
        assert result["preload"] is True

    def test_parse_hsts_minimal(self):
        """Test parsing HSTS with only max-age."""
        result = parse_hsts("max-age=10886400")

        assert result["max_age"] == 10886400
        assert result["include_subdomains"] is False
        assert result["preload"] is False

    def test_parse_hsts_case_insensitive(self):
        """Test HSTS parsing is case insensitive."""
        result = parse_hsts("MAX-AGE=31536000; INCLUDESUBDOMAINS; PRELOAD")

        assert result["max_age"] == 31536000
        assert result["include_subdomains"] is True
        assert result["preload"] is True

    def test_parse_hsts_no_max_age(self):
        """Test parsing HSTS without max-age."""
        result = parse_hsts("includeSubDomains; preload")

        assert result["max_age"] is None
        assert result["include_subdomains"] is True
        assert result["preload"] is True

    def test_parse_hsts_extra_whitespace(self):
        """Test HSTS parsing handles extra whitespace."""
        result = parse_hsts("  max-age=31536000  ;  includeSubDomains  ;  preload  ")

        assert result["max_age"] == 31536000
        assert result["include_subdomains"] is True
        assert result["preload"] is True


class TestAnalyzeHSTS:
    """Test HSTS header analysis."""

    def test_analyze_hsts_missing(self):
        """Test HSTS analysis when header is missing."""
        result = analyze_hsts(None)

        assert result["header_name"] == "Strict-Transport-Security"
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == "critical"
        assert result["actual_value"] is None
        assert result["recommendation"] is not None

    def test_analyze_hsts_perfect(self):
        """Test HSTS analysis with perfect configuration."""
        result = analyze_hsts("max-age=31536000; includeSubDomains; preload")

        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"
        assert result["actual_value"] == "max-age=31536000; includeSubDomains; preload"
        assert result["recommendation"] is None

    def test_analyze_hsts_acceptable_with_subdomains(self):
        """Test HSTS with good max-age and includeSubDomains but no preload."""
        result = analyze_hsts("max-age=31536000; includeSubDomains")

        assert result["status"] == STATUS_ACCEPTABLE
        assert result["severity"] == "low"
        assert result["recommendation"] is not None

    def test_analyze_hsts_acceptable_without_subdomains(self):
        """Test HSTS with good max-age but no includeSubDomains."""
        result = analyze_hsts("max-age=31536000")

        assert result["status"] == STATUS_ACCEPTABLE
        assert result["severity"] == "medium"
        assert "includeSubDomains" in result["recommendation"]

    def test_analyze_hsts_low_max_age(self):
        """Test HSTS with max-age below minimum."""
        result = analyze_hsts("max-age=1000")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "critical"
        assert "too low" in result["message"]

    def test_analyze_hsts_malformed_no_max_age(self):
        """Test malformed HSTS without max-age."""
        result = analyze_hsts("includeSubDomains; preload")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "critical"
        assert "malformed" in result["message"].lower()

    def test_analyze_hsts_minimum_max_age(self):
        """Test HSTS with minimum acceptable max-age."""
        result = analyze_hsts("max-age=10886400; includeSubDomains")

        assert result["status"] == STATUS_ACCEPTABLE
        assert result["severity"] == "low"
