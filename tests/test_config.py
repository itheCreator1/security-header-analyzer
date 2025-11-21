"""
Tests for config module.

Tests configuration data structures, constants, exception classes,
and utility functions.
"""

import pytest
from sha.config import (
    SECURITY_HEADERS,
    SEVERITY_LEVELS,
    STATUS_GOOD,
    STATUS_ACCEPTABLE,
    STATUS_BAD,
    STATUS_MISSING,
    DEFAULT_TIMEOUT,
    DEFAULT_MAX_REDIRECTS,
    PRIVATE_IP_RANGES,
    SecurityHeaderAnalyzerError,
    NetworkError,
    InvalidURLError,
    HTTPError,
    get_header_config,
    get_all_header_names,
    get_severity_rank,
    is_valid_severity,
)


class TestSecurityHeadersConfiguration:
    """Test security headers configuration data structure."""

    def test_all_headers_defined(self):
        """Test that all expected headers are defined."""
        expected_headers = [
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "content-security-policy",
        ]

        for header in expected_headers:
            assert header in SECURITY_HEADERS, f"{header} not found in SECURITY_HEADERS"

    def test_header_config_structure(self):
        """Test that each header config has required fields."""
        required_fields = ["display_name", "severity_missing", "description", "validation", "messages", "recommendations"]

        for header_key, config in SECURITY_HEADERS.items():
            for field in required_fields:
                assert field in config, f"{header_key} missing required field: {field}"

    def test_header_display_names(self):
        """Test that display names are properly formatted."""
        assert SECURITY_HEADERS["strict-transport-security"]["display_name"] == "Strict-Transport-Security"
        assert SECURITY_HEADERS["x-frame-options"]["display_name"] == "X-Frame-Options"
        assert SECURITY_HEADERS["x-content-type-options"]["display_name"] == "X-Content-Type-Options"
        assert SECURITY_HEADERS["content-security-policy"]["display_name"] == "Content-Security-Policy"

    def test_severity_levels_defined(self):
        """Test that all severity levels are defined for each header."""
        for header_key, config in SECURITY_HEADERS.items():
            severity_missing = config["severity_missing"]
            assert severity_missing in SEVERITY_LEVELS, f"Invalid severity_missing for {header_key}: {severity_missing}"

    def test_messages_for_all_statuses(self):
        """Test that each header has messages for all statuses."""
        for header_key, config in SECURITY_HEADERS.items():
            messages = config["messages"]
            # At minimum, should have messages for good, acceptable, bad, missing
            assert STATUS_GOOD in messages or STATUS_ACCEPTABLE in messages
            assert STATUS_BAD in messages or STATUS_MISSING in messages
            assert STATUS_MISSING in messages

    def test_hsts_validation_rules(self):
        """Test HSTS-specific validation rules."""
        hsts_config = SECURITY_HEADERS["strict-transport-security"]
        validation = hsts_config["validation"]

        assert "min_max_age" in validation
        assert validation["min_max_age"] == 10886400  # 126 days
        assert "best_max_age" in validation
        assert validation["best_max_age"] == 31536000  # 1 year
        assert "required_directives" in validation
        assert "includesubdomains" in validation["required_directives"]

    def test_xframe_validation_rules(self):
        """Test X-Frame-Options validation rules."""
        xframe_config = SECURITY_HEADERS["x-frame-options"]
        validation = xframe_config["validation"]

        assert "best_values" in validation
        assert "deny" in validation["best_values"]
        assert "acceptable_values" in validation
        assert "sameorigin" in validation["acceptable_values"]

    def test_content_type_validation_rules(self):
        """Test X-Content-Type-Options validation rules."""
        content_type_config = SECURITY_HEADERS["x-content-type-options"]
        validation = content_type_config["validation"]

        assert "required_value" in validation
        assert validation["required_value"] == "nosniff"

    def test_csp_validation_rules(self):
        """Test CSP validation rules."""
        csp_config = SECURITY_HEADERS["content-security-policy"]
        validation = csp_config["validation"]

        assert "dangerous_patterns" in validation
        assert "good_patterns" in validation

        # Check dangerous patterns
        dangerous = validation["dangerous_patterns"]
        assert "unsafe_inline_script" in dangerous
        assert "unsafe_eval" in dangerous
        assert "wildcard_script" in dangerous


class TestConstants:
    """Test configuration constants."""

    def test_default_timeout(self):
        """Test default timeout is reasonable."""
        assert DEFAULT_TIMEOUT == 10
        assert DEFAULT_TIMEOUT > 0

    def test_default_max_redirects(self):
        """Test default max redirects is reasonable."""
        assert DEFAULT_MAX_REDIRECTS == 5
        assert DEFAULT_MAX_REDIRECTS >= 0

    def test_severity_levels_order(self):
        """Test severity levels are in correct order."""
        expected_order = ["critical", "high", "medium-high", "medium", "low", "info"]
        assert SEVERITY_LEVELS == expected_order

    def test_status_constants(self):
        """Test status constants are defined."""
        assert STATUS_GOOD == "good"
        assert STATUS_ACCEPTABLE == "acceptable"
        assert STATUS_BAD == "bad"
        assert STATUS_MISSING == "missing"

    def test_private_ip_ranges(self):
        """Test private IP ranges are defined."""
        assert len(PRIVATE_IP_RANGES) > 0
        assert "127.0.0.0/8" in PRIVATE_IP_RANGES  # Loopback
        assert "10.0.0.0/8" in PRIVATE_IP_RANGES  # Private
        assert "192.168.0.0/16" in PRIVATE_IP_RANGES  # Private


class TestExceptionClasses:
    """Test custom exception classes."""

    def test_base_exception(self):
        """Test base SecurityHeaderAnalyzerError can be instantiated."""
        error = SecurityHeaderAnalyzerError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_network_error(self):
        """Test NetworkError can be instantiated."""
        error = NetworkError("Connection failed")
        assert str(error) == "Connection failed"
        assert isinstance(error, SecurityHeaderAnalyzerError)
        assert isinstance(error, Exception)

    def test_invalid_url_error(self):
        """Test InvalidURLError can be instantiated."""
        error = InvalidURLError("Bad URL")
        assert str(error) == "Bad URL"
        assert isinstance(error, SecurityHeaderAnalyzerError)

    def test_http_error_basic(self):
        """Test HTTPError can be instantiated."""
        error = HTTPError("404 Not Found")
        assert str(error) == "404 Not Found"
        assert isinstance(error, SecurityHeaderAnalyzerError)

    def test_http_error_with_status_code(self):
        """Test HTTPError stores status code."""
        error = HTTPError("Not found", status_code=404)
        assert error.status_code == 404

    def test_http_error_with_headers(self):
        """Test HTTPError stores headers."""
        headers = {"content-type": "text/html"}
        error = HTTPError("Error", status_code=500, headers=headers)
        assert error.status_code == 500
        assert error.headers == headers

    def test_http_error_defaults(self):
        """Test HTTPError defaults."""
        error = HTTPError("Error")
        assert error.status_code is None
        assert error.headers == {}


class TestUtilityFunctions:
    """Test configuration utility functions."""

    def test_get_header_config_valid(self):
        """Test getting config for valid header."""
        config = get_header_config("strict-transport-security")
        assert config is not None
        assert "display_name" in config
        assert config["display_name"] == "Strict-Transport-Security"

    def test_get_header_config_case_insensitive(self):
        """Test get_header_config is case insensitive."""
        config1 = get_header_config("strict-transport-security")
        config2 = get_header_config("Strict-Transport-Security")
        config3 = get_header_config("STRICT-TRANSPORT-SECURITY")

        assert config1 == config2 == config3

    def test_get_header_config_invalid(self):
        """Test getting config for invalid header raises KeyError."""
        with pytest.raises(KeyError):
            get_header_config("invalid-header")

    def test_get_all_header_names(self):
        """Test getting all header names."""
        names = get_all_header_names()

        assert isinstance(names, list)
        assert len(names) == 9
        assert "strict-transport-security" in names
        assert "x-frame-options" in names
        assert "x-content-type-options" in names
        assert "content-security-policy" in names
        assert "referrer-policy" in names
        assert "permissions-policy" in names
        assert "cross-origin-embedder-policy" in names
        assert "cross-origin-opener-policy" in names
        assert "cross-origin-resource-policy" in names

    def test_get_severity_rank_valid(self):
        """Test getting severity rank for valid severities."""
        assert get_severity_rank("critical") == 0  # Most severe
        assert get_severity_rank("high") == 1
        assert get_severity_rank("medium-high") == 2
        assert get_severity_rank("medium") == 3
        assert get_severity_rank("low") == 4
        assert get_severity_rank("info") == 5  # Least severe

    def test_get_severity_rank_case_insensitive(self):
        """Test severity rank is case insensitive."""
        assert get_severity_rank("critical") == get_severity_rank("Critical")
        assert get_severity_rank("HIGH") == get_severity_rank("high")

    def test_get_severity_rank_invalid(self):
        """Test invalid severity raises ValueError."""
        with pytest.raises(ValueError, match="Unknown severity level"):
            get_severity_rank("invalid")

    def test_is_valid_severity_valid(self):
        """Test is_valid_severity for valid severities."""
        assert is_valid_severity("critical") is True
        assert is_valid_severity("high") is True
        assert is_valid_severity("medium") is True
        assert is_valid_severity("low") is True
        assert is_valid_severity("info") is True

    def test_is_valid_severity_case_insensitive(self):
        """Test is_valid_severity is case insensitive."""
        assert is_valid_severity("Critical") is True
        assert is_valid_severity("HIGH") is True
        assert is_valid_severity("LoW") is True

    def test_is_valid_severity_invalid(self):
        """Test is_valid_severity for invalid severities."""
        assert is_valid_severity("invalid") is False
        assert is_valid_severity("") is False
        assert is_valid_severity("super-critical") is False
