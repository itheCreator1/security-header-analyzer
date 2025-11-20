"""
Integration tests for Security Header Analyzer.

Tests the complete CLI workflow including argument parsing,
header fetching, analysis, and reporting.
"""

import json
import sys
import pytest
from unittest.mock import Mock, patch
from io import StringIO
import requests

from sha.main import parse_args, main
from sha import __version__


class TestParseArgs:
    """Test CLI argument parsing."""

    def test_parse_args_url_only(self):
        """Test parsing with only URL argument."""
        with patch("sys.argv", ["sha", "https://example.com"]):
            args = parse_args()
            assert args.url == "https://example.com"
            assert args.json is False
            assert args.timeout == 10
            assert args.follow_redirects is True
            assert args.max_redirects == 5
            assert args.user_agent is None

    def test_parse_args_json_flag(self):
        """Test --json flag."""
        with patch("sys.argv", ["sha", "https://example.com", "--json"]):
            args = parse_args()
            assert args.json is True

    def test_parse_args_custom_timeout(self):
        """Test --timeout option."""
        with patch("sys.argv", ["sha", "https://example.com", "--timeout", "30"]):
            args = parse_args()
            assert args.timeout == 30

    def test_parse_args_no_redirects(self):
        """Test --no-redirects flag."""
        with patch("sys.argv", ["sha", "https://example.com", "--no-redirects"]):
            args = parse_args()
            assert args.follow_redirects is False

    def test_parse_args_max_redirects(self):
        """Test --max-redirects option."""
        with patch("sys.argv", ["sha", "https://example.com", "--max-redirects", "10"]):
            args = parse_args()
            assert args.max_redirects == 10

    def test_parse_args_custom_user_agent(self):
        """Test --user-agent option."""
        with patch("sys.argv", ["sha", "https://example.com", "--user-agent", "CustomBot/1.0"]):
            args = parse_args()
            assert args.user_agent == "CustomBot/1.0"

    def test_parse_args_version(self, capsys):
        """Test --version shows version."""
        with patch("sys.argv", ["sha", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                parse_args()

            assert exc_info.value.code == 0
            captured = capsys.readouterr()
            assert __version__ in captured.out

    def test_parse_args_invalid_timeout(self):
        """Test negative timeout is rejected."""
        with patch("sys.argv", ["sha", "https://example.com", "--timeout", "-1"]):
            with pytest.raises(SystemExit):
                parse_args()

    def test_parse_args_invalid_max_redirects(self):
        """Test negative max-redirects is rejected."""
        with patch("sys.argv", ["sha", "https://example.com", "--max-redirects", "-1"]):
            with pytest.raises(SystemExit):
                parse_args()


class TestMainFunction:
    """Test main CLI function with mocked network."""

    def test_main_success_all_good_headers(self, capsys):
        """Test successful analysis with all good headers."""
        test_args = ["sha", "https://example.com"]

        with patch("sys.argv", test_args), \
             patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class, \
             patch("sys.exit") as mock_exit:

            # Mock DNS to public IP
            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            # Mock successful response with good headers
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; base-uri 'self'; frame-ancestors 'none'",
            }

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            main()

            # Should exit with code 0
            mock_exit.assert_called_once_with(0)

            # Check output contains expected sections
            captured = capsys.readouterr()
            assert "SECURITY HEADER ANALYSIS REPORT" in captured.out
            assert "URL: https://example.com" in captured.out
            assert "SUMMARY" in captured.out
            assert "Critical Issues: 0" in captured.out

    def test_main_success_missing_headers(self, capsys):
        """Test analysis with missing headers."""
        test_args = ["sha", "https://example.com"]

        with patch("sys.argv", test_args), \
             patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class, \
             patch("sys.exit") as mock_exit:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            # Mock response with no security headers
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            main()

            mock_exit.assert_called_once_with(0)

            captured = capsys.readouterr()
            assert "Critical Issues: 2" in captured.out  # HSTS and CSP
            assert "High Issues:     2" in captured.out  # X-Frame-Options and Referrer-Policy

    def test_main_json_output(self, capsys):
        """Test JSON output format."""
        test_args = ["sha", "https://example.com", "--json"]

        with patch("sys.argv", test_args), \
             patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class, \
             patch("sys.exit") as mock_exit:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            main()

            mock_exit.assert_called_once_with(0)

            # Output should be valid JSON
            captured = capsys.readouterr()
            report = json.loads(captured.out)

            assert "url" in report
            assert "timestamp" in report
            assert "summary" in report
            assert "findings" in report
            assert report["url"] == "https://example.com"

    def test_main_network_error_exit_code_1(self, capsys):
        """Test network error exits with code 1."""
        test_args = ["sha", "https://example.com"]

        with patch("sys.argv", test_args), \
             patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class, \
             patch("sys.exit") as mock_exit:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_session = Mock()
            mock_session.head.side_effect = requests.exceptions.Timeout("Timeout")
            mock_session_class.return_value = mock_session

            main()

            # Should exit with code 1 for network error
            mock_exit.assert_called_once_with(1)

            captured = capsys.readouterr()
            assert "Network error" in captured.err

    def test_main_invalid_url_exit_code_2(self, capsys):
        """Test invalid URL exits with code 2."""
        test_args = ["sha", "http://localhost"]

        with patch("sys.argv", test_args), \
             patch("sys.exit") as mock_exit:

            main()

            # Should exit with code 2 for invalid URL
            mock_exit.assert_called_once_with(2)

            captured = capsys.readouterr()
            assert "Invalid URL" in captured.err

    def test_main_http_error_exit_code_3(self, capsys):
        """Test HTTP error exits with code 3."""
        test_args = ["sha", "https://example.com"]

        with patch("sys.argv", test_args), \
             patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class, \
             patch("sys.exit") as mock_exit:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            # Mock 404 response
            mock_response = Mock()
            mock_response.status_code = 404
            mock_response.headers = {
                "X-Frame-Options": "DENY",
            }

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            main()

            # Should exit with code 3 for HTTP error
            mock_exit.assert_called_once_with(3)

            # But should still analyze available headers
            captured = capsys.readouterr()
            assert "Warning: HTTP 404 error" in captured.err
            assert "SECURITY HEADER ANALYSIS REPORT" in captured.out

    def test_main_http_error_without_headers(self, capsys):
        """Test HTTP error without headers in exception."""
        test_args = ["sha", "https://example.com"]

        with patch("sys.argv", test_args), \
             patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class, \
             patch("sys.exit") as mock_exit:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_session = Mock()
            mock_session.head.side_effect = requests.exceptions.ConnectionError("Connection refused")
            mock_session_class.return_value = mock_session

            main()

            mock_exit.assert_called_once_with(1)

    def test_main_keyboard_interrupt(self, capsys):
        """Test Ctrl+C handling."""
        test_args = ["sha", "https://example.com"]

        with patch("sys.argv", test_args), \
             patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class, \
             patch("sys.exit") as mock_exit:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_session = Mock()
            mock_session.head.side_effect = KeyboardInterrupt()
            mock_session_class.return_value = mock_session

            main()

            # Should exit with code 130 for SIGINT
            mock_exit.assert_called_once_with(130)

            captured = capsys.readouterr()
            assert "Interrupted by user" in captured.err

    def test_main_url_normalization(self, capsys):
        """Test URL without protocol is normalized for fetching."""
        test_args = ["sha", "example.com"]

        with patch("sys.argv", test_args), \
             patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class, \
             patch("sys.exit") as mock_exit:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            main()

            mock_exit.assert_called_once_with(0)

            # Report shows original URL as entered by user
            captured = capsys.readouterr()
            assert "URL: example.com" in captured.out

            # But fetch was done with normalized URL (https://)
            call_args = mock_session.head.call_args[0]
            assert call_args[0] == "https://example.com"

    def test_main_custom_timeout(self):
        """Test custom timeout is passed through."""
        test_args = ["sha", "https://example.com", "--timeout", "30"]

        with patch("sys.argv", test_args), \
             patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class, \
             patch("sys.exit") as mock_exit:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            main()

            mock_exit.assert_called_once_with(0)

            # Verify timeout was passed to request
            call_kwargs = mock_session.head.call_args[1]
            assert call_kwargs["timeout"] == 30

    def test_main_custom_user_agent(self):
        """Test custom user agent is passed through."""
        test_args = ["sha", "https://example.com", "--user-agent", "TestBot/1.0"]

        with patch("sys.argv", test_args), \
             patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class, \
             patch("sys.exit") as mock_exit:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            main()

            mock_exit.assert_called_once_with(0)

            # Verify custom user agent was passed
            call_kwargs = mock_session.head.call_args[1]
            assert call_kwargs["headers"]["User-Agent"] == "TestBot/1.0"

    def test_main_no_redirects(self):
        """Test --no-redirects flag is respected."""
        test_args = ["sha", "https://example.com", "--no-redirects"]

        with patch("sys.argv", test_args), \
             patch("socket.getaddrinfo") as mock_getaddrinfo, \
             patch("requests.Session") as mock_session_class, \
             patch("sys.exit") as mock_exit:

            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("93.184.216.34", 80))
            ]

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}

            mock_session = Mock()
            mock_session.head.return_value = mock_response
            mock_session_class.return_value = mock_session

            main()

            mock_exit.assert_called_once_with(0)

            # Verify follow_redirects=False was passed
            call_kwargs = mock_session.head.call_args[1]
            assert call_kwargs["allow_redirects"] is False
