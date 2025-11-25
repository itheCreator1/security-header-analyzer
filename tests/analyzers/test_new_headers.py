"""
Tests for new security header analyzers.

This module contains tests for the four headers added in Phase 2:
- Permissions-Policy
- Cross-Origin-Embedder-Policy (COEP)
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Resource-Policy (CORP)
"""

import pytest

from sha.config import (
    STATUS_GOOD,
    STATUS_ACCEPTABLE,
    STATUS_BAD,
    STATUS_MISSING,
)
from sha.analyzers.permissions_policy import (
    parse_permissions_policy,
    analyze as analyze_permissions_policy,
)
from sha.analyzers.coep import analyze as analyze_coep
from sha.analyzers.coop import analyze as analyze_coop
from sha.analyzers.corp import analyze as analyze_corp


# ============================================================================
# Permissions-Policy Tests
# ============================================================================


class TestParsePermissionsPolicy:
    """Test Permissions-Policy header parsing."""

    def test_parse_single_feature_empty_list(self):
        """Test parsing single feature with empty allowlist."""
        result = parse_permissions_policy("camera=()")
        assert result == {"camera": "()"}

    def test_parse_single_feature_self(self):
        """Test parsing single feature with self."""
        result = parse_permissions_policy("microphone=(self)")
        assert result == {"microphone": "(self)"}

    def test_parse_multiple_features(self):
        """Test parsing multiple features."""
        result = parse_permissions_policy("camera=(), microphone=(self), geolocation=*")
        assert result == {
            "camera": "()",
            "microphone": "(self)",
            "geolocation": "*",
        }

    def test_parse_feature_with_origins(self):
        """Test parsing feature with specific origins."""
        result = parse_permissions_policy("geolocation=(self 'https://example.com')")
        assert result == {"geolocation": "(self 'https://example.com')"}

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        result = parse_permissions_policy("")
        assert result == {}

    def test_parse_whitespace_handling(self):
        """Test parsing handles whitespace correctly."""
        result = parse_permissions_policy("  camera=() ,  microphone=(self)  ")
        assert result == {"camera": "()", "microphone": "(self)"}

    def test_parse_case_insensitive_feature_names(self):
        """Test feature names are normalized to lowercase."""
        result = parse_permissions_policy("Camera=(), MICROPHONE=(self)")
        assert result == {"camera": "()", "microphone": "(self)"}

    def test_parse_no_equals_sign(self):
        """Test parsing handles malformed directive without equals sign."""
        result = parse_permissions_policy("camera")
        assert result == {}


class TestAnalyzePermissionsPolicy:
    """Test Permissions-Policy header analysis."""

    def test_analyze_missing(self):
        """Test analysis when header is missing."""
        result = analyze_permissions_policy(None)
        assert result["header_name"] == "Permissions-Policy"
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == "high"
        assert "missing" in result["message"].lower()
        assert result["actual_value"] is None
        assert result["recommendation"] is not None

    def test_analyze_good_multiple_restrictions(self):
        """Test analysis with multiple sensitive features restricted."""
        result = analyze_permissions_policy("camera=(), microphone=(), geolocation=()")
        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"
        assert result["recommendation"] is None

    def test_analyze_good_with_self(self):
        """Test analysis with features restricted to self."""
        result = analyze_permissions_policy("camera=(self), microphone=(self), geolocation=(self)")
        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"

    def test_analyze_acceptable_some_restrictions(self):
        """Test analysis with only some restrictions."""
        result = analyze_permissions_policy("camera=(), microphone=()")
        assert result["status"] == STATUS_ACCEPTABLE
        assert result["severity"] == "low"

    def test_analyze_acceptable_non_sensitive_features(self):
        """Test analysis with only non-sensitive features."""
        result = analyze_permissions_policy("fullscreen=*, autoplay=()")
        assert result["status"] == STATUS_ACCEPTABLE
        assert result["severity"] == "medium"
        assert "doesn't restrict sensitive features" in result["message"]

    def test_analyze_bad_wildcard_sensitive(self):
        """Test analysis with sensitive features allowed via wildcard."""
        result = analyze_permissions_policy("camera=*, microphone=(), geolocation=()")
        assert result["status"] == STATUS_BAD
        assert result["severity"] == "high"
        assert "camera" in result["message"]

    def test_analyze_bad_empty_policy(self):
        """Test analysis with empty policy string."""
        result = analyze_permissions_policy("")
        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium"
        assert "no directives" in result["message"].lower()

    def test_analyze_comprehensive_good_policy(self):
        """Test analysis with comprehensive restrictive policy."""
        policy = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        result = analyze_permissions_policy(policy)
        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"


# ============================================================================
# Cross-Origin-Embedder-Policy (COEP) Tests
# ============================================================================


class TestAnalyzeCOEP:
    """Test Cross-Origin-Embedder-Policy header analysis."""

    def test_analyze_missing(self):
        """Test analysis when header is missing."""
        result = analyze_coep(None)
        assert result["header_name"] == "Cross-Origin-Embedder-Policy"
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == "medium"
        assert "missing" in result["message"].lower()
        assert result["actual_value"] is None
        assert result["recommendation"] is not None

    def test_analyze_require_corp(self):
        """Test analysis with require-corp value."""
        result = analyze_coep("require-corp")
        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"
        assert result["recommendation"] is None

    def test_analyze_require_corp_case_insensitive(self):
        """Test require-corp is case insensitive."""
        result1 = analyze_coep("require-corp")
        result2 = analyze_coep("REQUIRE-CORP")
        result3 = analyze_coep("Require-Corp")
        assert result1["status"] == result2["status"] == result3["status"] == STATUS_GOOD

    def test_analyze_credentialless(self):
        """Test analysis with credentialless value."""
        result = analyze_coep("credentialless")
        assert result["status"] == STATUS_ACCEPTABLE
        assert result["severity"] == "low"
        assert "credentialless" in result["message"].lower()
        assert result["recommendation"] is not None

    def test_analyze_credentialless_case_insensitive(self):
        """Test credentialless is case insensitive."""
        result1 = analyze_coep("credentialless")
        result2 = analyze_coep("CREDENTIALLESS")
        result3 = analyze_coep("Credentialless")
        assert result1["status"] == result2["status"] == result3["status"] == STATUS_ACCEPTABLE

    def test_analyze_invalid_value(self):
        """Test analysis with invalid value."""
        result = analyze_coep("unsafe-none")
        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium"
        assert "invalid" in result["message"].lower()

    def test_analyze_empty_value(self):
        """Test analysis with empty value."""
        result = analyze_coep("")
        assert result["status"] == STATUS_BAD

    def test_analyze_unknown_value(self):
        """Test analysis with unknown value."""
        result = analyze_coep("unknown-value")
        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium"

    def test_analyze_whitespace_handling(self):
        """Test analysis handles whitespace correctly."""
        result = analyze_coep("  require-corp  ")
        assert result["status"] == STATUS_GOOD


# ============================================================================
# Cross-Origin-Opener-Policy (COOP) Tests
# ============================================================================


class TestAnalyzeCOOP:
    """Test Cross-Origin-Opener-Policy header analysis."""

    def test_analyze_missing(self):
        """Test analysis when header is missing."""
        result = analyze_coop(None)
        assert result["header_name"] == "Cross-Origin-Opener-Policy"
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == "medium"
        assert "missing" in result["message"].lower()
        assert result["actual_value"] is None
        assert result["recommendation"] is not None

    def test_analyze_same_origin(self):
        """Test analysis with same-origin value."""
        result = analyze_coop("same-origin")
        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"
        assert "same-origin isolation" in result["message"]
        assert result["recommendation"] is None

    def test_analyze_same_origin_case_insensitive(self):
        """Test same-origin is case insensitive."""
        result1 = analyze_coop("same-origin")
        result2 = analyze_coop("SAME-ORIGIN")
        result3 = analyze_coop("Same-Origin")
        assert result1["status"] == result2["status"] == result3["status"] == STATUS_GOOD

    def test_analyze_same_origin_allow_popups(self):
        """Test analysis with same-origin-allow-popups value."""
        result = analyze_coop("same-origin-allow-popups")
        assert result["status"] == STATUS_ACCEPTABLE
        assert result["severity"] == "low"
        assert "same-origin-allow-popups" in result["message"]
        assert result["recommendation"] is not None

    def test_analyze_same_origin_allow_popups_case_insensitive(self):
        """Test same-origin-allow-popups is case insensitive."""
        result1 = analyze_coop("same-origin-allow-popups")
        result2 = analyze_coop("SAME-ORIGIN-ALLOW-POPUPS")
        result3 = analyze_coop("Same-Origin-Allow-Popups")
        assert result1["status"] == result2["status"] == result3["status"] == STATUS_ACCEPTABLE

    def test_analyze_unsafe_none(self):
        """Test analysis with unsafe-none value."""
        result = analyze_coop("unsafe-none")
        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium"
        assert "unsafe-none" in result["message"]

    def test_analyze_unsafe_none_case_insensitive(self):
        """Test unsafe-none is case insensitive."""
        result1 = analyze_coop("unsafe-none")
        result2 = analyze_coop("UNSAFE-NONE")
        assert result1["status"] == result2["status"] == STATUS_BAD

    def test_analyze_invalid_value(self):
        """Test analysis with invalid value."""
        result = analyze_coop("invalid-value")
        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium"
        assert "unknown value" in result["message"].lower()

    def test_analyze_empty_value(self):
        """Test analysis with empty value."""
        result = analyze_coop("")
        assert result["status"] == STATUS_BAD

    def test_analyze_whitespace_handling(self):
        """Test analysis handles whitespace correctly."""
        result = analyze_coop("  same-origin  ")
        assert result["status"] == STATUS_GOOD


# ============================================================================
# Cross-Origin-Resource-Policy (CORP) Tests
# ============================================================================


class TestAnalyzeCORP:
    """Test Cross-Origin-Resource-Policy header analysis."""

    def test_analyze_missing(self):
        """Test analysis when header is missing."""
        result = analyze_corp(None)
        assert result["header_name"] == "Cross-Origin-Resource-Policy"
        assert result["status"] == STATUS_MISSING
        assert result["severity"] == "medium"
        assert "missing" in result["message"].lower()
        assert result["actual_value"] is None
        assert result["recommendation"] is not None

    def test_analyze_same_origin(self):
        """Test analysis with same-origin value."""
        result = analyze_corp("same-origin")
        assert result["status"] == STATUS_GOOD
        assert result["severity"] == "info"
        assert "same-origin restriction" in result["message"]
        assert result["recommendation"] is None

    def test_analyze_same_origin_case_insensitive(self):
        """Test same-origin is case insensitive."""
        result1 = analyze_corp("same-origin")
        result2 = analyze_corp("SAME-ORIGIN")
        result3 = analyze_corp("Same-Origin")
        assert result1["status"] == result2["status"] == result3["status"] == STATUS_GOOD

    def test_analyze_same_site(self):
        """Test analysis with same-site value."""
        result = analyze_corp("same-site")
        assert result["status"] == STATUS_ACCEPTABLE
        assert result["severity"] == "low"
        assert "same-site" in result["message"]
        assert result["recommendation"] is not None

    def test_analyze_same_site_case_insensitive(self):
        """Test same-site is case insensitive."""
        result1 = analyze_corp("same-site")
        result2 = analyze_corp("SAME-SITE")
        result3 = analyze_corp("Same-Site")
        assert result1["status"] == result2["status"] == result3["status"] == STATUS_ACCEPTABLE

    def test_analyze_cross_origin(self):
        """Test analysis with cross-origin value."""
        result = analyze_corp("cross-origin")
        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium"
        assert "cross-origin" in result["message"]

    def test_analyze_cross_origin_case_insensitive(self):
        """Test cross-origin is case insensitive."""
        result1 = analyze_corp("cross-origin")
        result2 = analyze_corp("CROSS-ORIGIN")
        assert result1["status"] == result2["status"] == STATUS_BAD

    def test_analyze_invalid_value(self):
        """Test analysis with invalid value."""
        result = analyze_corp("invalid-value")
        assert result["status"] == STATUS_BAD
        assert result["severity"] == "medium"
        assert "unknown value" in result["message"].lower()

    def test_analyze_empty_value(self):
        """Test analysis with empty value."""
        result = analyze_corp("")
        assert result["status"] == STATUS_BAD

    def test_analyze_whitespace_handling(self):
        """Test analysis handles whitespace correctly."""
        result = analyze_corp("  same-origin  ")
        assert result["status"] == STATUS_GOOD
