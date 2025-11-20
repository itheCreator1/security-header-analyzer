"""
Tests for reporter module.

Tests report generation, formatting, and summary calculation.
"""

import json
import pytest
from datetime import datetime
from sha.reporter import (
    generate_report,
    format_text_report,
    format_json_report,
    calculate_summary,
    sort_findings_by_severity,
    get_severity_label,
    get_timestamp,
    get_total_issues,
    format_summary_oneline,
)


@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return [
        {
            "header_name": "Strict-Transport-Security",
            "status": "missing",
            "severity": "critical",
            "message": "HSTS header is missing",
            "actual_value": None,
            "recommendation": "Add HSTS header",
        },
        {
            "header_name": "X-Frame-Options",
            "status": "good",
            "severity": "info",
            "message": "X-Frame-Options is properly configured",
            "actual_value": "DENY",
            "recommendation": None,
        },
        {
            "header_name": "X-Content-Type-Options",
            "status": "acceptable",
            "severity": "low",
            "message": "Header is acceptable",
            "actual_value": "nosniff",
            "recommendation": "Consider improvements",
        },
        {
            "header_name": "Content-Security-Policy",
            "status": "bad",
            "severity": "high",
            "message": "CSP has dangerous directives",
            "actual_value": "default-src *; script-src 'unsafe-inline'",
            "recommendation": "Remove unsafe-inline",
        },
    ]


@pytest.fixture
def all_missing_findings():
    """All headers missing for testing."""
    return [
        {
            "header_name": "Strict-Transport-Security",
            "status": "missing",
            "severity": "critical",
            "message": "HSTS is missing",
            "actual_value": None,
            "recommendation": "Add HSTS",
        },
        {
            "header_name": "Content-Security-Policy",
            "status": "missing",
            "severity": "critical",
            "message": "CSP is missing",
            "actual_value": None,
            "recommendation": "Add CSP",
        },
        {
            "header_name": "X-Frame-Options",
            "status": "missing",
            "severity": "high",
            "message": "X-Frame-Options is missing",
            "actual_value": None,
            "recommendation": "Add X-Frame-Options",
        },
        {
            "header_name": "X-Content-Type-Options",
            "status": "missing",
            "severity": "medium-high",
            "message": "X-Content-Type-Options is missing",
            "actual_value": None,
            "recommendation": "Add X-Content-Type-Options",
        },
    ]


class TestCalculateSummary:
    """Test summary calculation."""

    def test_calculate_summary_mixed_findings(self, sample_findings):
        """Test summary with mixed severity findings."""
        summary = calculate_summary(sample_findings)

        assert summary["critical_issues"] == 1  # HSTS missing
        assert summary["high_issues"] == 1  # CSP bad
        assert summary["medium_issues"] == 0
        assert summary["low_issues"] == 1  # X-Content-Type acceptable

    def test_calculate_summary_all_missing(self, all_missing_findings):
        """Test summary with all missing headers."""
        summary = calculate_summary(all_missing_findings)

        assert summary["critical_issues"] == 2  # HSTS, CSP
        assert summary["high_issues"] == 1  # X-Frame-Options
        assert summary["medium_issues"] == 1  # X-Content-Type (medium-high)
        assert summary["low_issues"] == 0

    def test_calculate_summary_ignores_good_status(self, sample_findings):
        """Test that good status findings are not counted as issues."""
        summary = calculate_summary(sample_findings)

        # X-Frame-Options has "good" status, should not be counted
        total = (
            summary["critical_issues"]
            + summary["high_issues"]
            + summary["medium_issues"]
            + summary["low_issues"]
        )
        assert total == 3  # Only missing, bad, acceptable are counted

    def test_calculate_summary_empty_findings(self):
        """Test summary with no findings."""
        summary = calculate_summary([])

        assert summary["critical_issues"] == 0
        assert summary["high_issues"] == 0
        assert summary["medium_issues"] == 0
        assert summary["low_issues"] == 0

    def test_calculate_summary_medium_high_as_medium(self, all_missing_findings):
        """Test that medium-high severity is counted as medium."""
        summary = calculate_summary(all_missing_findings)

        # X-Content-Type-Options has medium-high severity
        assert summary["medium_issues"] == 1


class TestSortFindingsBySeverity:
    """Test sorting findings by severity."""

    def test_sort_findings_by_severity(self, sample_findings):
        """Test findings are sorted correctly."""
        sorted_findings = sort_findings_by_severity(sample_findings)

        # Order should be: critical, high, low, info
        assert sorted_findings[0]["severity"] == "critical"
        assert sorted_findings[1]["severity"] == "high"
        assert sorted_findings[2]["severity"] == "low"
        assert sorted_findings[3]["severity"] == "info"

    def test_sort_findings_preserves_data(self, sample_findings):
        """Test that sorting doesn't modify finding data."""
        sorted_findings = sort_findings_by_severity(sample_findings)

        # Should still have all 4 findings
        assert len(sorted_findings) == 4

        # Check that actual data is preserved
        critical_finding = sorted_findings[0]
        assert critical_finding["header_name"] == "Strict-Transport-Security"
        assert critical_finding["status"] == "missing"

    def test_sort_empty_findings(self):
        """Test sorting empty findings list."""
        sorted_findings = sort_findings_by_severity([])
        assert sorted_findings == []


class TestGetSeverityLabel:
    """Test severity label conversion."""

    def test_get_severity_label_standard(self):
        """Test standard severity labels."""
        assert get_severity_label("critical") == "Critical"
        assert get_severity_label("high") == "High"
        assert get_severity_label("medium") == "Medium"
        assert get_severity_label("low") == "Low"
        assert get_severity_label("info") == "Info"

    def test_get_severity_label_medium_high(self):
        """Test medium-high is displayed as Medium."""
        assert get_severity_label("medium-high") == "Medium"

    def test_get_severity_label_unknown(self):
        """Test unknown severity is capitalized."""
        assert get_severity_label("unknown") == "Unknown"


class TestGetTimestamp:
    """Test timestamp generation."""

    def test_get_timestamp_format(self):
        """Test timestamp is in ISO 8601 format."""
        timestamp = get_timestamp()

        # Should be parseable as ISO 8601
        parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        assert isinstance(parsed, datetime)

    def test_get_timestamp_ends_with_z(self):
        """Test timestamp ends with Z (UTC indicator)."""
        timestamp = get_timestamp()
        assert timestamp.endswith("Z")


class TestGetTotalIssues:
    """Test total issue counting."""

    def test_get_total_issues(self):
        """Test total issues calculation."""
        summary = {
            "critical_issues": 2,
            "high_issues": 1,
            "medium_issues": 3,
            "low_issues": 0,
        }

        total = get_total_issues(summary)
        assert total == 6

    def test_get_total_issues_zero(self):
        """Test total with no issues."""
        summary = {
            "critical_issues": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0,
        }

        total = get_total_issues(summary)
        assert total == 0


class TestFormatSummaryOneline:
    """Test one-line summary formatting."""

    def test_format_summary_oneline(self):
        """Test one-line summary format."""
        summary = {
            "critical_issues": 2,
            "high_issues": 1,
            "medium_issues": 0,
            "low_issues": 3,
        }

        oneline = format_summary_oneline(summary)

        assert "Critical: 2" in oneline
        assert "High: 1" in oneline
        assert "Medium: 0" in oneline
        assert "Low: 3" in oneline


class TestTextReport:
    """Test text report generation."""

    def test_format_text_report_structure(self, sample_findings):
        """Test text report has correct structure."""
        report = format_text_report("https://example.com", sample_findings)

        # Check for main sections
        assert "SECURITY HEADER ANALYSIS REPORT" in report
        assert "URL: https://example.com" in report
        assert "SUMMARY" in report
        assert "DETAILED FINDINGS" in report

        # Check for separators
        assert "=" * 70 in report
        assert "-" * 70 in report

    def test_format_text_report_summary(self, sample_findings):
        """Test summary section in text report."""
        report = format_text_report("https://example.com", sample_findings)

        assert "Critical Issues: 1" in report
        assert "High Issues:     1" in report
        assert "Medium Issues:   0" in report
        assert "Low Issues:      1" in report

    def test_format_text_report_findings(self, sample_findings):
        """Test findings are included in text report."""
        report = format_text_report("https://example.com", sample_findings)

        # Check all header names are present
        assert "Strict-Transport-Security" in report
        assert "X-Frame-Options" in report
        assert "X-Content-Type-Options" in report
        assert "Content-Security-Policy" in report

    def test_format_text_report_severity_labels(self, sample_findings):
        """Test severity labels are included."""
        report = format_text_report("https://example.com", sample_findings)

        assert "[Critical]" in report
        assert "[High]" in report
        assert "[Low]" in report
        assert "[Info]" in report

    def test_format_text_report_values_shown(self, sample_findings):
        """Test actual values are shown when present."""
        report = format_text_report("https://example.com", sample_findings)

        assert "Value: DENY" in report  # X-Frame-Options value
        assert "Value: nosniff" in report  # X-Content-Type value

    def test_format_text_report_recommendations(self, sample_findings):
        """Test recommendations are shown when present."""
        report = format_text_report("https://example.com", sample_findings)

        assert "Recommendation: Add HSTS header" in report
        assert "Recommendation: Remove unsafe-inline" in report

    def test_format_text_report_no_recommendation_when_none(self, sample_findings):
        """Test recommendation field is not shown when None."""
        report = format_text_report("https://example.com", sample_findings)

        # X-Frame-Options has no recommendation (status is good)
        # Count how many times "Recommendation:" appears
        recommendation_count = report.count("Recommendation:")

        # Should appear 3 times (HSTS, X-Content-Type, CSP)
        # X-Frame-Options (good status) should not have recommendation
        assert recommendation_count == 3

    def test_format_text_report_long_value_truncation(self):
        """Test very long values are truncated."""
        findings = [
            {
                "header_name": "Content-Security-Policy",
                "status": "good",
                "severity": "info",
                "message": "CSP is good",
                "actual_value": "a" * 150,  # Very long value
                "recommendation": None,
            }
        ]

        report = format_text_report("https://example.com", findings)

        # Should be truncated to 100 chars with "..."
        assert "..." in report
        # The truncated value should be in the report
        assert "Value: " + "a" * 97 + "..." in report


class TestJsonReport:
    """Test JSON report generation."""

    def test_format_json_report_valid_json(self, sample_findings):
        """Test JSON report is valid JSON."""
        report = format_json_report("https://example.com", sample_findings)

        # Should be parseable as JSON
        parsed = json.loads(report)
        assert isinstance(parsed, dict)

    def test_format_json_report_structure(self, sample_findings):
        """Test JSON report has correct structure."""
        report = format_json_report("https://example.com", sample_findings)
        parsed = json.loads(report)

        assert "url" in parsed
        assert "timestamp" in parsed
        assert "summary" in parsed
        assert "findings" in parsed

    def test_format_json_report_url(self, sample_findings):
        """Test URL is included in JSON report."""
        report = format_json_report("https://example.com", sample_findings)
        parsed = json.loads(report)

        assert parsed["url"] == "https://example.com"

    def test_format_json_report_summary(self, sample_findings):
        """Test summary is correct in JSON report."""
        report = format_json_report("https://example.com", sample_findings)
        parsed = json.loads(report)

        summary = parsed["summary"]
        assert summary["critical_issues"] == 1
        assert summary["high_issues"] == 1
        assert summary["medium_issues"] == 0
        assert summary["low_issues"] == 1

    def test_format_json_report_findings(self, sample_findings):
        """Test findings are included in JSON report."""
        report = format_json_report("https://example.com", sample_findings)
        parsed = json.loads(report)

        findings = parsed["findings"]
        assert len(findings) == 4
        assert findings == sample_findings

    def test_format_json_report_timestamp_format(self, sample_findings):
        """Test timestamp format in JSON report."""
        report = format_json_report("https://example.com", sample_findings)
        parsed = json.loads(report)

        timestamp = parsed["timestamp"]
        # Should be ISO 8601 format
        parsed_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        assert isinstance(parsed_time, datetime)

    def test_format_json_report_no_truncation(self):
        """Test JSON report doesn't truncate long values."""
        findings = [
            {
                "header_name": "Content-Security-Policy",
                "status": "good",
                "severity": "info",
                "message": "CSP is good",
                "actual_value": "a" * 200,  # Very long value
                "recommendation": None,
            }
        ]

        report = format_json_report("https://example.com", findings)
        parsed = json.loads(report)

        # Should NOT be truncated in JSON
        assert len(parsed["findings"][0]["actual_value"]) == 200
        assert "..." not in parsed["findings"][0]["actual_value"]


class TestGenerateReport:
    """Test main report generation function."""

    def test_generate_report_text_format(self, sample_findings):
        """Test generating text format report."""
        report = generate_report("https://example.com", sample_findings, format="text")

        assert isinstance(report, str)
        assert "SECURITY HEADER ANALYSIS REPORT" in report

    def test_generate_report_json_format(self, sample_findings):
        """Test generating JSON format report."""
        report = generate_report("https://example.com", sample_findings, format="json")

        assert isinstance(report, str)
        # Should be valid JSON
        parsed = json.loads(report)
        assert "url" in parsed

    def test_generate_report_default_format(self, sample_findings):
        """Test default format is text."""
        report = generate_report("https://example.com", sample_findings)

        # Default should be text
        assert "SECURITY HEADER ANALYSIS REPORT" in report

    def test_generate_report_invalid_format(self, sample_findings):
        """Test invalid format raises ValueError."""
        with pytest.raises(ValueError, match="Unknown format"):
            generate_report("https://example.com", sample_findings, format="xml")
