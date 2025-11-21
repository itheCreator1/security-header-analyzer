"""
Shared test fixtures and utilities.

This module provides common fixtures used across all test modules
to reduce duplication and improve test maintainability.
"""

import pytest
from sha.config import (
    STATUS_GOOD,
    STATUS_ACCEPTABLE,
    STATUS_BAD,
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


# Export commonly used constants for convenience
__all__ = [
    "sample_finding_good",
    "sample_finding_bad",
    "sample_finding_missing",
    "all_headers_missing",
    "all_headers_good",
    "STATUS_GOOD",
    "STATUS_ACCEPTABLE",
    "STATUS_BAD",
    "STATUS_MISSING",
]
