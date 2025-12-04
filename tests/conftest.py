"""
Shared test fixtures and utilities.

This module provides common fixtures used across all test modules
to reduce duplication and improve test maintainability.
"""

import pytest

from sha.config import (
    STATUS_ACCEPTABLE,
    STATUS_BAD,
    STATUS_GOOD,
    STATUS_MISSING,
)


@pytest.fixture
def sample_finding_good():
    """Sample finding with GOOD status."""
    return {
        "header_name": "Test-Header",
        "status": STATUS_GOOD,
        "severity": "info",
        "message": "Test header is properly configured",
        "actual_value": "test-value",
        "recommendation": None,
    }


@pytest.fixture
def sample_finding_bad():
    """Sample finding with BAD status."""
    return {
        "header_name": "Test-Header",
        "status": STATUS_BAD,
        "severity": "high",
        "message": "Test header has security issues",
        "actual_value": "bad-value",
        "recommendation": "Use better configuration",
    }


@pytest.fixture
def sample_finding_missing():
    """Sample finding with MISSING status."""
    return {
        "header_name": "Test-Header",
        "status": STATUS_MISSING,
        "severity": "critical",
        "message": "Test header is missing",
        "actual_value": None,
        "recommendation": "Add Test-Header: recommended-value",
    }


@pytest.fixture
def all_headers_missing():
    """Dictionary representing all security headers as missing."""
    return {}


@pytest.fixture
def all_headers_good():
    """Dictionary with all security headers properly configured."""
    return {
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'self'; script-src 'self'; base-uri 'self'; frame-ancestors 'none'",
        "referrer-policy": "strict-origin",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
    }


# ============================================================================
# Real-World Header Fixtures
# ============================================================================


@pytest.fixture
def github_headers():
    """Real headers from github.com."""
    from tests.fixtures.headers import load_headers_fixture

    return load_headers_fixture("github_com")["headers"]


@pytest.fixture
def google_headers():
    """Real headers from google.com."""
    from tests.fixtures.headers import load_headers_fixture

    return load_headers_fixture("google_com")["headers"]


@pytest.fixture
def cloudflare_headers():
    """Real headers from cloudflare.com."""
    from tests.fixtures.headers import load_headers_fixture

    return load_headers_fixture("cloudflare_com")["headers"]


@pytest.fixture
def mozilla_headers():
    """Real headers from mozilla.org."""
    from tests.fixtures.headers import load_headers_fixture

    return load_headers_fixture("mozilla_org")["headers"]


@pytest.fixture
def aws_headers():
    """Real headers from aws.amazon.com."""
    from tests.fixtures.headers import load_headers_fixture

    return load_headers_fixture("aws_amazon_com")["headers"]


@pytest.fixture
def weak_headers():
    """Headers from a site with weak security posture."""
    from tests.fixtures.headers import load_headers_fixture

    return load_headers_fixture("weak_site")["headers"]


@pytest.fixture
def missing_critical_headers():
    """Headers from a site missing only critical headers (HSTS, CSP)."""
    from tests.fixtures.headers import load_headers_fixture

    return load_headers_fixture("missing_critical")["headers"]


@pytest.fixture
def all_real_world_fixtures():
    """All available real-world header fixtures."""
    from tests.fixtures.headers import get_all_fixtures

    return get_all_fixtures()


# ============================================================================
# Mock Helper Fixtures
# ============================================================================


@pytest.fixture
def mock_response_factory():
    """Factory for creating mock HTTP responses.

    Usage:
        def test_something(mock_response_factory):
            response = mock_response_factory(
                status_code=200,
                headers={'x-frame-options': 'DENY'}
            )
    """
    from unittest.mock import Mock

    def _create(status_code=200, headers=None, url="https://example.com"):
        response = Mock()
        response.status_code = status_code
        response.headers = headers or {}
        response.url = url
        return response

    return _create


@pytest.fixture
def mock_session_factory(mock_response_factory):
    """Factory for creating mocked requests.Session objects.

    Usage:
        def test_something(mock_session_factory):
            response = mock_response_factory(headers={...})
            session = mock_session_factory(response)
    """
    from unittest.mock import Mock

    def _create(response=None):
        session = Mock()
        session.head.return_value = response or mock_response_factory()
        return session

    return _create


# Export commonly used constants for convenience
__all__ = [
    # Basic fixtures
    "sample_finding_good",
    "sample_finding_bad",
    "sample_finding_missing",
    "all_headers_missing",
    "all_headers_good",
    # Real-world fixtures
    "github_headers",
    "google_headers",
    "cloudflare_headers",
    "mozilla_headers",
    "aws_headers",
    "weak_headers",
    "missing_critical_headers",
    "all_real_world_fixtures",
    # Mock factories
    "mock_response_factory",
    "mock_session_factory",
    # Constants
    "STATUS_GOOD",
    "STATUS_ACCEPTABLE",
    "STATUS_BAD",
    "STATUS_MISSING",
]
