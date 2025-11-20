"""
Tests for fetcher module.

Tests URL normalization, SSRF protection, header fetching with mocked requests.
"""

import pytest
from unittest.mock import Mock, patch
import requests
from sha.fetcher import (
    normalize_url,
    is_private_ip,
    validate_url_safety,
    fetch_headers,
    fetch_headers_safe,
    get_final_url,
)
from sha.config import (
    NetworkError,
    InvalidURLError,
    HTTPError,
)


class TestNormalizeURL:
    """Test URL normalization."""

    def test_normalize_url_no_protocol(self):
        """Test URL without protocol gets https:// added."""
        assert normalize_url("example.com") == "https://example.com"

    def test_normalize_url_http(self):
        """Test HTTP URL is preserved."""
        assert normalize_url("http://example.com") == "http://example.com"

    def test_normalize_url_https(self):
        """Test HTTPS URL is preserved."""
        assert normalize_url("https://example.com") == "https://example.com"

    def test_normalize_url_with_path(self):
        """Test URL with path."""
        assert normalize_url("example.com/path") == "https://example.com/path"

    def test_normalize_url_with_query(self):
        """Test URL with query parameters."""
        assert normalize_url("example.com?foo=bar") == "https://example.com?foo=bar"

    def test_normalize_url_strips_whitespace(self):
        """Test URL normalization strips whitespace."""
        assert normalize_url("  example.com  ") == "https://example.com"
        assert normalize_url("\texample.com\n") == "https://example.com"


class TestIsPrivateIP:
    """Test private IP detection."""

    def test_is_private_ip_localhost(self):
        """Test localhost IPv4."""
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("127.0.0.2") is True

    def test_is_private_ip_10_network(self):
        """Test 10.0.0.0/8 private network."""
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True

    def test_is_private_ip_172_network(self):
        """Test 172.16.0.0/12 private network."""
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True

    def test_is_private_ip_192_network(self):
        """Test 192.168.0.0/16 private network."""
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.255.255") is True

    def test_is_private_ip_link_local(self):
        """Test 169.254.0.0/16 link-local."""
        assert is_private_ip("169.254.1.1") is True

    def test_is_private_ip_ipv6_loopback(self):
        """Test IPv6 loopback."""
        assert is_private_ip("::1") is True

    def test_is_private_ip_public(self):
        """Test public IPs are not private."""
        assert is_private_ip("8.8.8.8") is False  # Google DNS
        assert is_private_ip("1.1.1.1") is False  # Cloudflare DNS
        assert is_private_ip("93.184.216.34") is False  # example.com

    def test_is_private_ip_invalid(self):
        """Test invalid IP raises ValueError."""
        with pytest.raises(ValueError):
            is_private_ip("not-an-ip")


class TestValidateURLSafety:
    """Test URL safety validation (SSRF protection)."""

    def test_validate_url_safety_valid_public(self):
        """Test valid public URL passes validation."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            # Mock DNS resolution to public IP
            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))  # example.com
            ]

            # Should not raise
            validate_url_safety("https://example.com")

    def test_validate_url_safety_localhost_name(self):
        """Test localhost name is blocked."""
        with pytest.raises(InvalidURLError, match="localhost"):
            validate_url_safety("http://localhost")

    def test_validate_url_safety_localhost_variations(self):
        """Test various localhost names are blocked."""
        with pytest.raises(InvalidURLError):
            validate_url_safety("http://0.0.0.0")

    def test_validate_url_safety_private_ip_resolution(self):
        """Test URL resolving to private IP is blocked."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            # Mock DNS resolution to private IP
            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("10.0.0.1", 80))
            ]

            with pytest.raises(InvalidURLError, match="private IP"):
                validate_url_safety("https://internal.example.com")

    def test_validate_url_safety_127_0_0_1(self):
        """Test direct 127.0.0.1 IP is blocked."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("127.0.0.1", 80))
            ]

            with pytest.raises(InvalidURLError, match="private IP"):
                validate_url_safety("http://127.0.0.1")

    def test_validate_url_safety_invalid_scheme(self):
        """Test invalid URL scheme is rejected."""
        with pytest.raises(InvalidURLError, match="Invalid URL scheme"):
            validate_url_safety("ftp://example.com")

    def test_validate_url_safety_no_hostname(self):
        """Test URL without hostname is rejected."""
        with pytest.raises(InvalidURLError, match="hostname"):
            validate_url_safety("https://")

    def test_validate_url_safety_dns_failure(self):
        """Test DNS resolution failure is caught."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            import socket
            mock_getaddrinfo.side_effect = socket.gaierror("DNS lookup failed")

            with pytest.raises(InvalidURLError, match="Failed to resolve"):
                validate_url_safety("https://nonexistent.example.com")


class TestFetchHeaders:
    """Test header fetching with mocked requests."""

    def test_fetch_headers_success(self):
        """Test successful header fetch."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            # Mock DNS to public IP
            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            # Mock successful response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
            }

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            headers = fetch_headers("https://example.com")

            # Headers should be normalized to lowercase
            assert "strict-transport-security" in headers
            assert "x-frame-options" in headers
            assert headers["strict-transport-security"] == "max-age=31536000"
            assert headers["x-frame-options"] == "DENY"

    def test_fetch_headers_normalizes_to_lowercase(self):
        """Test header names are normalized to lowercase."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {
                "Content-Type": "text/html",
                "X-FRAME-OPTIONS": "DENY",
            }

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            headers = fetch_headers("https://example.com")

            assert "content-type" in headers
            assert "x-frame-options" in headers
            assert "Content-Type" not in headers  # Should be lowercase

    def test_fetch_headers_timeout(self):
        """Test timeout raises NetworkError."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_session = Mock()
            mock_session.head.side_effect = requests.exceptions.Timeout("Timeout")
            mock_session_class.return_value = mock_session

            with pytest.raises(NetworkError, match="timed out"):
                fetch_headers("https://example.com", timeout=1)

    def test_fetch_headers_connection_error(self):
        """Test connection error raises NetworkError."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_session = Mock()
            mock_session.head.side_effect = requests.exceptions.ConnectionError("Connection failed")
            mock_session_class.return_value = mock_session

            with pytest.raises(NetworkError, match="Failed to connect"):
                fetch_headers("https://example.com")

    def test_fetch_headers_ssl_error(self):
        """Test SSL error raises NetworkError."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_session = Mock()
            mock_session.head.side_effect = requests.exceptions.SSLError("SSL error")
            mock_session_class.return_value = mock_session

            with pytest.raises(NetworkError, match="SSL/TLS error"):
                fetch_headers("https://example.com")

    def test_fetch_headers_http_404(self):
        """Test HTTP 404 raises HTTPError with headers."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 404
            mock_response.headers = {
                "Content-Type": "text/html",
                "X-Frame-Options": "DENY",
            }

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            with pytest.raises(HTTPError) as exc_info:
                fetch_headers("https://example.com")

            error = exc_info.value
            assert error.status_code == 404
            assert "content-type" in error.headers
            assert "x-frame-options" in error.headers

    def test_fetch_headers_http_500(self):
        """Test HTTP 500 raises HTTPError."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.headers = {}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            with pytest.raises(HTTPError) as exc_info:
                fetch_headers("https://example.com")

            assert exc_info.value.status_code == 500

    def test_fetch_headers_custom_timeout(self):
        """Test custom timeout is passed to request."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            fetch_headers("https://example.com", timeout=30)

            # Verify timeout was passed
            mock_session.head.assert_called_once()
            call_kwargs = mock_session.head.call_args[1]
            assert call_kwargs["timeout"] == 30

    def test_fetch_headers_custom_user_agent(self):
        """Test custom user agent is used."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            fetch_headers("https://example.com", user_agent="CustomBot/1.0")

            # Verify custom user agent was passed
            call_kwargs = mock_session.head.call_args[1]
            assert call_kwargs["headers"]["User-Agent"] == "CustomBot/1.0"

    def test_fetch_headers_no_redirects(self):
        """Test disabling redirects."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            fetch_headers("https://example.com", follow_redirects=False)

            # Verify allow_redirects=False was passed
            call_kwargs = mock_session.head.call_args[1]
            assert call_kwargs["allow_redirects"] is False

    def test_fetch_headers_max_redirects(self):
        """Test max_redirects is set on session."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            fetch_headers("https://example.com", max_redirects=10)

            # Verify max_redirects was set on session
            assert mock_session.max_redirects == 10


class TestFetchHeadersSafe:
    """Test safe header fetching (non-throwing)."""

    def test_fetch_headers_safe_success(self):
        """Test successful fetch returns headers and no error."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {"X-Frame-Options": "DENY"}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            headers, error = fetch_headers_safe("https://example.com")

            assert error is None
            assert "x-frame-options" in headers

    def test_fetch_headers_safe_network_error(self):
        """Test network error returns empty headers and error."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_session = Mock()
            mock_session.head.side_effect = requests.exceptions.Timeout("Timeout")
            mock_session_class.return_value = mock_session

            headers, error = fetch_headers_safe("https://example.com")

            assert headers == {}
            assert isinstance(error, NetworkError)

    def test_fetch_headers_safe_http_error_with_headers(self):
        """Test HTTP error returns headers and error."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 404
            mock_response.headers = {"X-Frame-Options": "DENY"}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            headers, error = fetch_headers_safe("https://example.com")

            assert "x-frame-options" in headers
            assert isinstance(error, HTTPError)
            assert error.status_code == 404

    def test_fetch_headers_safe_invalid_url(self):
        """Test invalid URL returns empty headers and error."""
        headers, error = fetch_headers_safe("http://localhost")

        assert headers == {}
        assert isinstance(error, InvalidURLError)


class TestGetFinalURL:
    """Test getting final URL after redirects."""

    def test_get_final_url_no_redirect(self):
        """Test URL with no redirects."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.url = "https://example.com"

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            final_url = get_final_url("https://example.com")

            assert final_url == "https://example.com"

    def test_get_final_url_with_redirect(self):
        """Test URL with redirect."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.url = "https://www.example.com"  # Redirected

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            final_url = get_final_url("https://example.com")

            assert final_url == "https://www.example.com"

    def test_get_final_url_network_error(self):
        """Test network error raises NetworkError."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_session = Mock()
            mock_session.head.side_effect = requests.exceptions.ConnectionError("Failed")
            mock_session_class.return_value = mock_session

            with pytest.raises(NetworkError, match="Failed to get final URL"):
                get_final_url("https://example.com")
