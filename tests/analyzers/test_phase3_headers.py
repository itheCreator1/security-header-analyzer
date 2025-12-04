"""
Tests for Phase 3 security header analyzers.

This module contains tests for the three headers added in Phase 3:
- X-XSS-Protection
- X-Download-Options
- X-Permitted-Cross-Domain-Policies
"""

import pytest

from sha.analyzers.x_download_options import analyze as analyze_x_download_options
from sha.analyzers.x_permitted_cross_domain_policies import (
    analyze as analyze_x_permitted_cross_domain_policies,
)
from sha.analyzers.x_xss_protection import analyze as analyze_x_xss_protection
from sha.config import STATUS_ACCEPTABLE, STATUS_BAD, STATUS_GOOD, STATUS_MISSING

# ============================================================================
# X-XSS-Protection Tests
# ============================================================================


class TestAnalyzeXXSSProtection:
    """Test X-XSS-Protection header analysis."""

    def test_analyze_missing(self):
        """Test analysis when header is missing."""
        result = analyze_x_xss_protection(None)

        assert result["header_name"] == "X-XSS-Protection"
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == "low"
        assert "missing" in result["message"].lower()
        assert result["actual_value"] is None
        assert result["recommendation"] is not None
        assert "0" in result["recommendation"]

    def test_analyze_zero(self):
        """Test analysis with recommended 0 value (disabled)."""
        result = analyze_x_xss_protection("0")

        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"
        assert result["actual_value"] == "0"
        assert result["recommendation"] is None

    def test_analyze_one_mode_block(self):
        """Test analysis with 1; mode=block value (legacy acceptable)."""
        result = analyze_x_xss_protection("1; mode=block")

        assert result["status"] == STATUS_ACCEPTABLE
        assert result["severity"] == "low"
        assert "legacy" in result["message"].lower()
        assert result["actual_value"] == "1; mode=block"
        assert result["recommendation"] is not None

    def test_analyze_one_only(self):
        """Test analysis with plain 1 value (bad - creates vulnerabilities)."""
        result = analyze_x_xss_protection("1")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium"
        assert "vulnerabilities" in result["message"].lower()
        assert result["actual_value"] == "1"
        assert result["recommendation"] is not None

    def test_analyze_case_insensitive(self):
        """Test X-XSS-Protection is case insensitive."""
        result1 = analyze_x_xss_protection("0")
        result2 = analyze_x_xss_protection("0")

        assert result1["status"] == result2["status"] == STATUS_GOOD

    def test_analyze_case_insensitive_mode_block(self):
        """Test mode=block is case insensitive."""
        result1 = analyze_x_xss_protection("1; mode=block")
        result2 = analyze_x_xss_protection("1; MODE=BLOCK")
        result3 = analyze_x_xss_protection("1; Mode=Block")

        assert result1["status"] == result2["status"] == result3["status"] == STATUS_ACCEPTABLE

    def test_analyze_whitespace_handling(self):
        """Test analysis handles whitespace correctly."""
        result = analyze_x_xss_protection("  0  ")

        assert result["status"] == STATUS_GOOD
        assert result["actual_value"] == "  0  "

    def test_analyze_whitespace_mode_block(self):
        """Test whitespace handling with mode=block."""
        result = analyze_x_xss_protection("  1; mode=block  ")

        assert result["status"] == STATUS_ACCEPTABLE
        assert result["actual_value"] == "  1; mode=block  "

    def test_analyze_invalid_value(self):
        """Test analysis with invalid value."""
        result = analyze_x_xss_protection("invalid-value")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "low"
        assert "unknown value" in result["message"].lower()
        assert result["recommendation"] is not None

    def test_analyze_empty_value(self):
        """Test analysis with empty value."""
        result = analyze_x_xss_protection("")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "low"
        assert "empty value" in result["message"].lower()

    def test_analyze_numeric_values(self):
        """Test other numeric values besides 0 and 1."""
        for value in ["2", "3", "999"]:
            result = analyze_x_xss_protection(value)
            assert result["status"] == STATUS_BAD
            assert "unknown value" in result["message"].lower()


# ============================================================================
# X-Download-Options Tests
# ============================================================================


class TestAnalyzeXDownloadOptions:
    """Test X-Download-Options header analysis."""

    def test_analyze_missing(self):
        """Test analysis when header is missing."""
        result = analyze_x_download_options(None)

        assert result["header_name"] == "X-Download-Options"
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == "low"
        assert "missing" in result["message"].lower()
        assert result["actual_value"] is None
        assert result["recommendation"] is not None
        assert "noopen" in result["recommendation"]

    def test_analyze_noopen(self):
        """Test analysis with noopen value."""
        result = analyze_x_download_options("noopen")

        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"
        assert result["actual_value"] == "noopen"
        assert result["recommendation"] is None

    def test_analyze_noopen_case_insensitive(self):
        """Test noopen is case insensitive."""
        result1 = analyze_x_download_options("noopen")
        result2 = analyze_x_download_options("NOOPEN")
        result3 = analyze_x_download_options("NoOpen")
        result4 = analyze_x_download_options("nOoPeN")

        assert (
            result1["status"]
            == result2["status"]
            == result3["status"]
            == result4["status"]
            == STATUS_GOOD
        )

    def test_analyze_whitespace_handling(self):
        """Test analysis handles whitespace correctly."""
        result = analyze_x_download_options("  noopen  ")

        assert result["status"] == STATUS_GOOD
        assert result["actual_value"] == "  noopen  "

    def test_analyze_invalid_value(self):
        """Test analysis with invalid value."""
        result = analyze_x_download_options("invalid-value")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "low"
        assert "unknown value" in result["message"].lower()
        assert "noopen" in result["message"]
        assert result["recommendation"] is not None

    def test_analyze_empty_value(self):
        """Test analysis with empty value."""
        result = analyze_x_download_options("")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "low"
        assert "empty value" in result["message"].lower()

    def test_analyze_similar_values(self):
        """Test values similar to noopen are rejected."""
        for value in ["no-open", "no_open", "noopening", "open", "no"]:
            result = analyze_x_download_options(value)
            assert result["status"] == STATUS_BAD
            assert "unknown value" in result["message"].lower()

    def test_analyze_numeric_value(self):
        """Test numeric values are rejected."""
        result = analyze_x_download_options("0")

        assert result["status"] == STATUS_BAD
        assert "unknown value" in result["message"].lower()


# ============================================================================
# X-Permitted-Cross-Domain-Policies Tests
# ============================================================================


class TestAnalyzeXPermittedCrossDomainPolicies:
    """Test X-Permitted-Cross-Domain-Policies header analysis."""

    def test_analyze_missing(self):
        """Test analysis when header is missing."""
        result = analyze_x_permitted_cross_domain_policies(None)

        assert result["header_name"] == "X-Permitted-Cross-Domain-Policies"
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == "medium"
        assert "missing" in result["message"].lower()
        assert result["actual_value"] is None
        assert result["recommendation"] is not None
        assert "none" in result["recommendation"]

    def test_analyze_none(self):
        """Test analysis with none value (best practice)."""
        result = analyze_x_permitted_cross_domain_policies("none")

        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"
        assert result["actual_value"] == "none"
        assert result["recommendation"] is None

    def test_analyze_none_case_insensitive(self):
        """Test none is case insensitive."""
        result1 = analyze_x_permitted_cross_domain_policies("none")
        result2 = analyze_x_permitted_cross_domain_policies("NONE")
        result3 = analyze_x_permitted_cross_domain_policies("None")
        result4 = analyze_x_permitted_cross_domain_policies("nOnE")

        assert (
            result1["status"]
            == result2["status"]
            == result3["status"]
            == result4["status"]
            == STATUS_GOOD
        )

    def test_analyze_master_only(self):
        """Test analysis with master-only value (acceptable)."""
        result = analyze_x_permitted_cross_domain_policies("master-only")

        assert result["status"] == STATUS_ACCEPTABLE
        assert result["severity"] == "low"
        assert result["actual_value"] == "master-only"
        assert result["recommendation"] is not None
        assert "none" in result["recommendation"]

    def test_analyze_master_only_case_insensitive(self):
        """Test master-only is case insensitive."""
        result1 = analyze_x_permitted_cross_domain_policies("master-only")
        result2 = analyze_x_permitted_cross_domain_policies("MASTER-ONLY")
        result3 = analyze_x_permitted_cross_domain_policies("Master-Only")

        assert result1["status"] == result2["status"] == result3["status"] == STATUS_ACCEPTABLE

    def test_analyze_all(self):
        """Test analysis with all value (very insecure - high severity)."""
        result = analyze_x_permitted_cross_domain_policies("all")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "high"
        assert "insecure" in result["message"].lower()
        assert "anywhere" in result["message"].lower()
        assert result["actual_value"] == "all"
        assert result["recommendation"] is not None

    def test_analyze_by_content_type(self):
        """Test analysis with by-content-type value (bad - medium severity)."""
        result = analyze_x_permitted_cross_domain_policies("by-content-type")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium"
        assert "permissive" in result["message"].lower()
        assert result["actual_value"] == "by-content-type"
        assert result["recommendation"] is not None

    def test_analyze_by_ftp_filename(self):
        """Test analysis with by-ftp-filename value (bad - medium severity)."""
        result = analyze_x_permitted_cross_domain_policies("by-ftp-filename")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium"
        assert "legacy" in result["message"].lower()
        assert "insecure" in result["message"].lower()
        assert result["actual_value"] == "by-ftp-filename"
        assert result["recommendation"] is not None

    def test_analyze_whitespace_handling(self):
        """Test analysis handles whitespace correctly."""
        result = analyze_x_permitted_cross_domain_policies("  none  ")

        assert result["status"] == STATUS_GOOD
        assert result["actual_value"] == "  none  "

    def test_analyze_whitespace_master_only(self):
        """Test whitespace handling with master-only."""
        result = analyze_x_permitted_cross_domain_policies("  master-only  ")

        assert result["status"] == STATUS_ACCEPTABLE
        assert result["actual_value"] == "  master-only  "

    def test_analyze_invalid_value(self):
        """Test analysis with invalid value."""
        result = analyze_x_permitted_cross_domain_policies("invalid-value")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium"
        assert "unknown value" in result["message"].lower()
        assert result["recommendation"] is not None

    def test_analyze_empty_value(self):
        """Test analysis with empty value."""
        result = analyze_x_permitted_cross_domain_policies("")

        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium"
        assert "empty value" in result["message"].lower()

    def test_analyze_all_case_variations(self):
        """Test all value case variations."""
        for value in ["all", "ALL", "All", "aLl"]:
            result = analyze_x_permitted_cross_domain_policies(value)
            assert result["status"] == STATUS_BAD
            assert result["severity"] == "high"

    def test_analyze_by_content_type_case_variations(self):
        """Test by-content-type case variations."""
        for value in [
            "by-content-type",
            "BY-CONTENT-TYPE",
            "By-Content-Type",
            "BY-content-TYPE",
        ]:
            result = analyze_x_permitted_cross_domain_policies(value)
            assert result["status"] == STATUS_BAD
            assert result["severity"] == "medium"

    def test_analyze_by_ftp_filename_case_variations(self):
        """Test by-ftp-filename case variations."""
        for value in [
            "by-ftp-filename",
            "BY-FTP-FILENAME",
            "By-Ftp-Filename",
            "BY-ftp-FILENAME",
        ]:
            result = analyze_x_permitted_cross_domain_policies(value)
            assert result["status"] == STATUS_BAD
            assert result["severity"] == "medium"
