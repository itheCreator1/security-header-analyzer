"""
Tests using real-world header data from popular websites.

These tests validate that our analyzers work correctly with
actual headers captured from production websites. This ensures
our analysis logic handles real-world configurations correctly
and doesn't break on edge cases we might not think to test.
"""

import pytest

from sha.analyzer import analyze_headers


def test_github_headers_analysis(github_headers):
    """Test analysis of GitHub's actual security headers.

    GitHub is known for having excellent security headers,
    so we expect minimal critical/high severity findings.
    """
    findings = analyze_headers(github_headers)

    # Should analyze all 12 headers
    assert len(findings) == 12, "Should analyze all headers"

    # GitHub should have excellent security
    critical_findings = [f for f in findings if f["severity"] == "critical"]
    high_findings = [f for f in findings if f["severity"] == "high"]

    assert len(critical_findings) == 0, "GitHub should have no critical issues"
    assert len(high_findings) <= 1, "GitHub should have minimal high severity issues"


def test_google_headers_analysis(google_headers):
    """Test analysis of Google's actual security headers.

    Google typically has a complex CSP and strong security posture.
    """
    findings = analyze_headers(google_headers)

    assert len(findings) == 12, "Should analyze all headers"

    # Verify no analysis errors occurred
    for finding in findings:
        assert "error" not in finding.get("message", "").lower()


def test_cloudflare_headers_analysis(cloudflare_headers):
    """Test analysis of Cloudflare's actual security headers.

    Cloudflare typically has modern security header configurations.
    """
    findings = analyze_headers(cloudflare_headers)

    assert len(findings) == 12, "Should analyze all headers"

    # Verify findings have proper structure
    for finding in findings:
        assert "header_name" in finding
        assert "status" in finding
        assert "severity" in finding
        assert "message" in finding


def test_mozilla_headers_analysis(mozilla_headers):
    """Test analysis of Mozilla's actual security headers.

    Mozilla is a security-focused organization and should have
    strong security header configurations.
    """
    findings = analyze_headers(mozilla_headers)

    assert len(findings) == 12, "Should analyze all headers"

    critical_findings = [f for f in findings if f["severity"] == "critical"]

    # Mozilla should have minimal critical issues
    assert len(critical_findings) <= 1, "Mozilla should have minimal critical security issues"


def test_aws_headers_analysis(aws_headers):
    """Test analysis of AWS CloudFront's actual security headers.

    AWS CloudFront defaults may not be as strict as other sites.
    """
    findings = analyze_headers(aws_headers)

    assert len(findings) == 12, "Should analyze all headers"

    # Just verify analysis completes without errors
    for finding in findings:
        assert isinstance(finding, dict)
        assert "status" in finding


def test_all_real_world_sites(all_real_world_fixtures):
    """Test analyzer against all captured real-world sites.

    This comprehensive test ensures our analyzer works correctly
    with all types of real-world header configurations.
    """
    for site_name, fixture in all_real_world_fixtures.items():
        if "headers" not in fixture:
            continue

        findings = analyze_headers(fixture["headers"])

        # Verify analysis completes without errors
        assert len(findings) == 12, f"{site_name}: Should analyze all 12 headers"

        # Verify all findings have required fields
        for finding in findings:
            assert "header_name" in finding, f"{site_name}: Finding missing header_name"
            assert "status" in finding, f"{site_name}: Finding missing status"
            assert "severity" in finding, f"{site_name}: Finding missing severity"
            assert "message" in finding, f"{site_name}: Finding missing message"

        # Verify expected results if provided in fixture
        if "expected_analysis" in fixture:
            expected = fixture["expected_analysis"]

            if "critical_count" in expected:
                critical = [f for f in findings if f["severity"] == "critical"]
                assert (
                    len(critical) == expected["critical_count"]
                ), f"{site_name}: Expected {expected['critical_count']} critical issues, got {len(critical)}"

            if "high_count" in expected:
                high = [f for f in findings if f["severity"] == "high"]
                assert (
                    len(high) == expected["high_count"]
                ), f"{site_name}: Expected {expected['high_count']} high issues, got {len(high)}"

            if "medium_count" in expected:
                medium = [f for f in findings if f["severity"] == "medium"]
                assert (
                    len(medium) == expected["medium_count"]
                ), f"{site_name}: Expected {expected['medium_count']} medium issues, got {len(medium)}"

            if "low_count" in expected:
                low = [f for f in findings if f["severity"] == "low"]
                assert (
                    len(low) == expected["low_count"]
                ), f"{site_name}: Expected {expected['low_count']} low issues, got {len(low)}"


def test_weak_site_detection(weak_headers):
    """Test that weak security posture is properly detected.

    A site with minimal or no security headers should generate
    multiple critical and high severity findings.
    """
    findings = analyze_headers(weak_headers)

    assert len(findings) == 12, "Should analyze all headers"

    critical = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]

    # Should detect multiple critical/high issues on weak site
    assert (
        len(critical) + len(high) >= 3
    ), "Weak site should have multiple critical/high severity issues"


def test_missing_critical_headers(missing_critical_headers):
    """Test detection of missing critical security headers.

    A site missing HSTS and CSP should be flagged appropriately.
    """
    findings = analyze_headers(missing_critical_headers)

    assert len(findings) == 12, "Should analyze all headers"

    # Find HSTS and CSP findings
    hsts_finding = next(
        (f for f in findings if f["header_name"] == "Strict-Transport-Security"), None
    )
    csp_finding = next((f for f in findings if f["header_name"] == "Content-Security-Policy"), None)

    assert hsts_finding is not None, "Should have HSTS finding"
    assert csp_finding is not None, "Should have CSP finding"

    # Both should be critical severity
    assert hsts_finding["severity"] == "critical", "Missing HSTS should be critical severity"
    assert csp_finding["severity"] == "critical", "Missing CSP should be critical severity"


def test_real_world_fixtures_have_metadata(all_real_world_fixtures):
    """Verify all real-world fixtures have proper metadata.

    Ensures fixture files are properly formatted with required fields.
    """
    for site_name, fixture in all_real_world_fixtures.items():
        # Check required fields
        assert "site" in fixture, f"{site_name}: Missing 'site' field"
        assert "url" in fixture, f"{site_name}: Missing 'url' field"
        assert "captured_date" in fixture, f"{site_name}: Missing 'captured_date' field"
        assert "status_code" in fixture, f"{site_name}: Missing 'status_code' field"
        assert "headers" in fixture, f"{site_name}: Missing 'headers' field"

        # Verify headers is a dict
        assert isinstance(fixture["headers"], dict), f"{site_name}: Headers should be a dictionary"

        # Verify all header keys are lowercase (normalization)
        for key in fixture["headers"].keys():
            assert key == key.lower(), f"{site_name}: Header key '{key}' should be lowercase"


def test_fixture_consistency():
    """Test that fixture loading is consistent.

    The same fixture loaded twice should return identical data.
    """
    from tests.fixtures.headers import load_headers_fixture

    # Load GitHub fixture twice
    github1 = load_headers_fixture("github_com")
    github2 = load_headers_fixture("github_com")

    assert github1 == github2, "Fixture loading should be consistent"
    assert github1["headers"] == github2["headers"], "Headers should be identical across loads"
