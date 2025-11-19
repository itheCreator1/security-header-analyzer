"""
Reporter module for Security Header Analyzer.

This module generates formatted reports from security header analysis findings.
Supports both human-readable text output and JSON output for automation.
"""

import json
from datetime import datetime
from typing import List, Dict, Any

from .config import STATUS_MISSING, STATUS_BAD, STATUS_ACCEPTABLE, STATUS_GOOD


# Type alias for finding
Finding = Dict[str, Any]


def generate_report(url: str, findings: List[Finding], format: str = "text") -> str:
    """
    Generate a report from analysis findings.

    Args:
        url: The analyzed URL
        findings: List of finding dictionaries from analyzer
        format: Output format - "text" or "json"

    Returns:
        Formatted report string

    Raises:
        ValueError: If format is not "text" or "json"
    """
    if format == "text":
        return format_text_report(url, findings)
    elif format == "json":
        return format_json_report(url, findings)
    else:
        raise ValueError(f"Unknown format: {format}. Must be 'text' or 'json'")


def format_text_report(url: str, findings: List[Finding]) -> str:
    """
    Generate human-readable text report.

    Args:
        url: The analyzed URL
        findings: List of findings

    Returns:
        Formatted text report
    """
    lines = []
    separator = "=" * 70
    subseparator = "-" * 70

    # Header
    lines.append(separator)
    lines.append("SECURITY HEADER ANALYSIS REPORT")
    lines.append(separator)
    lines.append("")

    # URL and timestamp
    lines.append(f"URL: {url}")
    lines.append(f"Timestamp: {get_timestamp()}")
    lines.append("")

    # Summary
    summary = calculate_summary(findings)
    lines.append("SUMMARY")
    lines.append(subseparator)
    lines.append(f"Critical Issues: {summary['critical_issues']}")
    lines.append(f"High Issues:     {summary['high_issues']}")
    lines.append(f"Medium Issues:   {summary['medium_issues']}")
    lines.append(f"Low Issues:      {summary['low_issues']}")
    lines.append("")

    # Detailed findings
    lines.append("DETAILED FINDINGS")
    lines.append(subseparator)
    lines.append("")

    # Sort findings by severity (most severe first)
    sorted_findings = sort_findings_by_severity(findings)

    for finding in sorted_findings:
        lines.extend(format_finding_text(finding))
        lines.append("")  # Blank line between findings

    lines.append(separator)

    return "\n".join(lines)


def format_finding_text(finding: Finding) -> List[str]:
    """
    Format a single finding for text output.

    Args:
        finding: Finding dictionary

    Returns:
        List of formatted lines
    """
    lines = []

    # Header: [Severity] Header Name
    severity_label = get_severity_label(finding["severity"])
    lines.append(f"[{severity_label}] {finding['header_name']}")

    # Status
    status_label = finding["status"].upper()
    lines.append(f"Status: {status_label}")

    # Message
    lines.append(f"Message: {finding['message']}")

    # Actual value (if present)
    if finding["actual_value"] is not None:
        # Truncate very long values (like CSP)
        value = finding["actual_value"]
        if len(value) > 100:
            value = value[:97] + "..."
        lines.append(f"Value: {value}")

    # Recommendation (if present)
    if finding["recommendation"]:
        lines.append(f"Recommendation: {finding['recommendation']}")

    return lines


def format_json_report(url: str, findings: List[Finding]) -> str:
    """
    Generate JSON report for automation.

    Args:
        url: The analyzed URL
        findings: List of findings

    Returns:
        JSON string (pretty-printed)
    """
    summary = calculate_summary(findings)

    report = {
        "url": url,
        "timestamp": get_timestamp(),
        "summary": summary,
        "findings": findings,
    }

    return json.dumps(report, indent=2, ensure_ascii=False)


def calculate_summary(findings: List[Finding]) -> Dict[str, int]:
    """
    Calculate summary statistics from findings.

    Counts issues by severity. Only counts findings with status
    "missing", "bad", or "acceptable" (not "good").

    Args:
        findings: List of findings

    Returns:
        Dictionary with issue counts:
        {
            "critical_issues": int,
            "high_issues": int,
            "medium_issues": int,
            "low_issues": int
        }
    """
    summary = {
        "critical_issues": 0,
        "high_issues": 0,
        "medium_issues": 0,
        "low_issues": 0,
    }

    for finding in findings:
        # Only count issues (not "good" status)
        if finding["status"] == STATUS_GOOD:
            continue

        severity = finding["severity"]

        if severity == "critical":
            summary["critical_issues"] += 1
        elif severity == "high":
            summary["high_issues"] += 1
        elif severity in ("medium", "medium-high"):
            summary["medium_issues"] += 1
        elif severity == "low":
            summary["low_issues"] += 1
        # "info" severity is not counted as an issue

    return summary


def sort_findings_by_severity(findings: List[Finding]) -> List[Finding]:
    """
    Sort findings by severity (most severe first).

    Order: critical > high > medium-high > medium > low > info

    Args:
        findings: List of findings

    Returns:
        Sorted list of findings
    """
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium-high": 2,
        "medium": 3,
        "low": 4,
        "info": 5,
    }

    return sorted(findings, key=lambda f: severity_order.get(f["severity"], 99))


def get_severity_label(severity: str) -> str:
    """
    Convert severity string to display label.

    Args:
        severity: Severity string (e.g., "critical", "medium-high")

    Returns:
        Display label (e.g., "Critical", "Medium")
    """
    severity_labels = {
        "critical": "Critical",
        "high": "High",
        "medium-high": "Medium",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }

    return severity_labels.get(severity, severity.capitalize())


def get_timestamp() -> str:
    """
    Get current timestamp in ISO 8601 format.

    Returns:
        Timestamp string (e.g., "2025-11-19T10:30:00Z")
    """
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def get_total_issues(summary: Dict[str, int]) -> int:
    """
    Get total number of issues from summary.

    Args:
        summary: Summary dictionary from calculate_summary()

    Returns:
        Total issue count
    """
    return (
        summary["critical_issues"]
        + summary["high_issues"]
        + summary["medium_issues"]
        + summary["low_issues"]
    )


def format_summary_oneline(summary: Dict[str, int]) -> str:
    """
    Format summary as a single line for compact output.

    Args:
        summary: Summary dictionary

    Returns:
        Formatted string (e.g., "Critical: 2, High: 1, Medium: 0, Low: 0")
    """
    return (
        f"Critical: {summary['critical_issues']}, "
        f"High: {summary['high_issues']}, "
        f"Medium: {summary['medium_issues']}, "
        f"Low: {summary['low_issues']}"
    )
