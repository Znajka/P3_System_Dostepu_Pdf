"""
Shared test configuration: JWT secret matches tokens used in tests; disable replay HTTP.
"""

import os
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("APP_JWT_SECRET", "test-secret-key-for-jwt-validation")
os.environ.setdefault("APP_INTERNAL_API_KEY", "test-internal-key")
os.environ.setdefault("APP_SECURITY_IP_PINNING_ENABLED", "false")


@pytest.fixture(autouse=True)
def mock_mark_ticket_used_spring():
    with patch(
        "app.routers.stream_ticket._mark_ticket_used_spring",
        new=AsyncMock(return_value=None),
    ):
        yield


@pytest.fixture(autouse=True)
def reset_jwt_validator_singleton():
    """Ensure JwtValidator picks up APP_JWT_SECRET after env is set."""
    import app.routers.stream_ticket as st

    st._jwt_validator = None
    yield
    st._jwt_validator = None
