"""
Tests for Cross-Origin Isolation Validator.

This module tests cross-header interactions between COEP, COOP, and CORP
to validate SharedArrayBuffer eligibility and cross-origin isolation detection.
"""

import pytest

from sha.analyzers.cross_origin_validator import validate_cross_origin_isolation
from sha.config import STATUS_BAD, STATUS_GOOD


class TestCrossOriginIsolationFullMode:
    """Test cases for full cross-origin isolation (require-corp + same-origin)."""

    def test_full_isolation_enabled(self):
        """Test that require-corp + same-origin enables full cross-origin isolation."""
        headers = {
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-opener-policy": "same-origin",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding is not None
        assert finding["header_name"] == "Cross-Origin Isolation"
        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"
        assert "SharedArrayBuffer" in finding["message"]
        assert "ENABLED" in finding["message"]
        assert "full isolation" in finding["message"]
        assert finding["recommendation"] is None

    def test_full_isolation_case_insensitive(self):
        """Test that full isolation detection is case-insensitive."""
        headers = {
            "cross-origin-embedder-policy": "REQUIRE-CORP",
            "cross-origin-opener-policy": "Same-Origin",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding["status"] == STATUS_GOOD
        assert "ENABLED" in finding["message"]

    def test_full_isolation_with_whitespace(self):
        """Test that full isolation handles whitespace in values."""
        headers = {
            "cross-origin-embedder-policy": "  require-corp  ",
            "cross-origin-opener-policy": "  same-origin  ",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding["status"] == STATUS_GOOD
        assert "ENABLED" in finding["message"]


class TestCrossOriginIsolationCredentiallessMode:
    """Test cases for credentialless cross-origin isolation."""

    def test_credentialless_isolation_enabled(self):
        """Test that credentialless + same-origin enables cross-origin isolation."""
        headers = {
            "cross-origin-embedder-policy": "credentialless",
            "cross-origin-opener-policy": "same-origin",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding is not None
        assert finding["status"] == STATUS_GOOD
        assert finding["severity"] == "info"
        assert "SharedArrayBuffer" in finding["message"]
        assert "ENABLED" in finding["message"]
        assert "credentialless mode" in finding["message"]
        assert finding["recommendation"] is not None
        assert "require-corp" in finding["recommendation"].lower()

    def test_credentialless_recommends_require_corp(self):
        """Test that credentialless mode recommends upgrading to require-corp."""
        headers = {
            "cross-origin-embedder-policy": "credentialless",
            "cross-origin-opener-policy": "same-origin",
        }

        finding = validate_cross_origin_isolation(headers)

        assert "require-corp" in finding["recommendation"]
        assert "stricter" in finding["recommendation"].lower()


class TestPartialIsolationCOEPOnly:
    """Test cases for partial isolation when only COEP is set."""

    def test_coep_require_corp_without_coop(self):
        """Test that COEP: require-corp without COOP is partial isolation."""
        headers = {
            "cross-origin-embedder-policy": "require-corp",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding is not None
        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "medium"
        assert "Partial" in finding["message"]
        assert "COOP is missing" in finding["message"]
        assert "NOT available" in finding["message"]
        assert "Cross-Origin-Opener-Policy: same-origin" in finding["recommendation"]

    def test_coep_credentialless_without_coop(self):
        """Test that COEP: credentialless without COOP is partial isolation."""
        headers = {
            "cross-origin-embedder-policy": "credentialless",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding["status"] == STATUS_BAD
        assert "Partial" in finding["message"]
        assert "COOP is missing" in finding["message"]

    def test_coep_with_coop_allow_popups(self):
        """Test that COEP + same-origin-allow-popups is incompatible."""
        headers = {
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-opener-policy": "same-origin-allow-popups",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding["status"] == STATUS_BAD
        assert "Partial" in finding["message"]
        assert "same-origin-allow-popups" in finding["message"]
        assert "must be 'same-origin'" in finding["message"]
        assert "Change" in finding["recommendation"]

    def test_coep_with_coop_unsafe_none(self):
        """Test that COEP + unsafe-none is incompatible."""
        headers = {
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-opener-policy": "unsafe-none",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding["status"] == STATUS_BAD
        assert "Incompatible" in finding["message"]
        assert "unsafe-none" in finding["message"]


class TestPartialIsolationCOOPOnly:
    """Test cases for partial isolation when only COOP is set."""

    def test_coop_same_origin_without_coep(self):
        """Test that COOP: same-origin without COEP is partial isolation."""
        headers = {
            "cross-origin-opener-policy": "same-origin",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding is not None
        assert finding["status"] == STATUS_BAD
        assert finding["severity"] == "medium"
        assert "Partial" in finding["message"]
        assert "COEP is missing" in finding["message"]
        assert "NOT available" in finding["message"]
        assert "Cross-Origin-Embedder-Policy" in finding["recommendation"]
        assert "require-corp" in finding["recommendation"] or "credentialless" in finding["recommendation"]


class TestIncompatibleCombinations:
    """Test cases for incompatible cross-origin header combinations."""

    def test_invalid_coep_with_valid_coop(self):
        """Test that invalid COEP value with valid COOP shows incompatibility."""
        headers = {
            "cross-origin-embedder-policy": "invalid-value",
            "cross-origin-opener-policy": "same-origin",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding["status"] == STATUS_BAD
        assert "Incompatible" in finding["message"]
        assert "NOT available" in finding["message"]

    def test_valid_coep_with_invalid_coop(self):
        """Test that valid COEP with invalid COOP shows incompatibility."""
        headers = {
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-opener-policy": "invalid-value",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding["status"] == STATUS_BAD
        # Could be partial or incompatible depending on value
        assert "NOT available" in finding["message"]


class TestNoIsolation:
    """Test cases for when no cross-origin headers are set."""

    def test_no_headers_returns_none(self):
        """Test that absence of both headers returns None (no finding)."""
        headers = {}

        finding = validate_cross_origin_isolation(headers)

        assert finding is None

    def test_neither_coep_nor_coop_returns_none(self):
        """Test that unrelated headers return None."""
        headers = {
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding is None


class TestActualValueFormatting:
    """Test cases for actual_value field formatting."""

    def test_actual_value_shows_both_headers(self):
        """Test that actual_value shows both COEP and COOP values."""
        headers = {
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-opener-policy": "same-origin",
        }

        finding = validate_cross_origin_isolation(headers)

        assert "COEP:" in finding["actual_value"]
        assert "COOP:" in finding["actual_value"]
        assert "require-corp" in finding["actual_value"]
        assert "same-origin" in finding["actual_value"]

    def test_actual_value_shows_missing_header(self):
        """Test that actual_value shows (missing) for absent headers."""
        headers = {
            "cross-origin-embedder-policy": "require-corp",
        }

        finding = validate_cross_origin_isolation(headers)

        assert "COEP:" in finding["actual_value"]
        assert "COOP: (missing)" in finding["actual_value"]


class TestEdgeCases:
    """Test cases for edge cases and boundary conditions."""

    def test_empty_header_values(self):
        """Test that empty header values are handled gracefully."""
        headers = {
            "cross-origin-embedder-policy": "",
            "cross-origin-opener-policy": "",
        }

        finding = validate_cross_origin_isolation(headers)

        # Should return None or incompatible finding
        # (empty strings after strip become falsy)
        assert finding is None or finding["status"] == STATUS_BAD

    def test_coep_same_origin_allow_popups_with_coop_same_origin(self):
        """Test that COOP: same-origin-allow-popups doesn't enable isolation."""
        # Note: This tests COOP having allow-popups, not COEP
        # The validator checks if COOP is exactly "same-origin"
        headers = {
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-opener-policy": "same-origin-allow-popups",
        }

        finding = validate_cross_origin_isolation(headers)

        assert finding["status"] == STATUS_BAD
        assert "NOT available" in finding["message"]

    def test_multiple_values_normalized(self):
        """Test that multiple capitalization patterns work."""
        test_cases = [
            ("Require-Corp", "Same-Origin"),
            ("REQUIRE-CORP", "SAME-ORIGIN"),
            ("require-CORP", "same-ORIGIN"),
        ]

        for coep_val, coop_val in test_cases:
            headers = {
                "cross-origin-embedder-policy": coep_val,
                "cross-origin-opener-policy": coop_val,
            }

            finding = validate_cross_origin_isolation(headers)

            assert finding["status"] == STATUS_GOOD, f"Failed for {coep_val}, {coop_val}"
            assert "ENABLED" in finding["message"]


class TestRecommendations:
    """Test cases for recommendation quality."""

    def test_recommendations_are_actionable(self):
        """Test that recommendations provide clear next steps."""
        test_cases = [
            {
                "headers": {"cross-origin-embedder-policy": "require-corp"},
                "expected_in_recommendation": "Cross-Origin-Opener-Policy",
            },
            {
                "headers": {"cross-origin-opener-policy": "same-origin"},
                "expected_in_recommendation": "Cross-Origin-Embedder-Policy",
            },
            {
                "headers": {
                    "cross-origin-embedder-policy": "require-corp",
                    "cross-origin-opener-policy": "same-origin-allow-popups",
                },
                "expected_in_recommendation": "same-origin",
            },
        ]

        for case in test_cases:
            finding = validate_cross_origin_isolation(case["headers"])
            assert finding is not None
            assert finding["recommendation"] is not None
            assert case["expected_in_recommendation"] in finding["recommendation"]


class TestMessageClarity:
    """Test cases for message clarity and completeness."""

    def test_full_isolation_mentions_sharedarraybuffer(self):
        """Test that full isolation message mentions SharedArrayBuffer."""
        headers = {
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-opener-policy": "same-origin",
        }

        finding = validate_cross_origin_isolation(headers)

        assert "SharedArrayBuffer" in finding["message"]
        assert "high-resolution timers" in finding["message"]

    def test_partial_isolation_explains_why_not_enabled(self):
        """Test that partial isolation explains what's missing."""
        headers = {
            "cross-origin-embedder-policy": "require-corp",
        }

        finding = validate_cross_origin_isolation(headers)

        assert "COOP is missing" in finding["message"]
        assert "Cross-Origin-Opener-Policy: same-origin" in finding["recommendation"]

    def test_credentialless_mode_explains_difference(self):
        """Test that credentialless mode explains how it differs from require-corp."""
        headers = {
            "cross-origin-embedder-policy": "credentialless",
            "cross-origin-opener-policy": "same-origin",
        }

        finding = validate_cross_origin_isolation(headers)

        assert "credentialless mode" in finding["message"]
        assert "without credentials" in finding["message"]
        assert "require-corp" in finding["recommendation"]
