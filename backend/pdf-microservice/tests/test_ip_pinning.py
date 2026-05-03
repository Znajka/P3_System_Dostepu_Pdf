"""
Tests for IP-pinning security in JWT validation.
"""

import pytest
import jwt
from datetime import datetime, timedelta
from app.security.jwt_validator import JwtValidator

SECRET_KEY = "test-secret-key-for-jwt-validation"


@pytest.fixture
def validator():
    return JwtValidator(secret_key=SECRET_KEY)


def test_validate_ip_pinning_matching_ip(validator):
    """Test validation passes when IPs match."""
    payload = {
        "sub": "user-123",
        "doc": "doc-456",
        "aud": "pdf-microservice",
        "jti": "ticket-789",
        "ip": "192.168.1.100",
        "ip_pinning_enabled": True,
        "exp": datetime.utcnow() + timedelta(minutes=1),
        "iat": datetime.utcnow()
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS512")

    # Should not raise
    result = validator.validate_open_ticket_with_ip_pinning(
        token, "doc-456", "user-123", "192.168.1.100"
    )

    assert result["sub"] == "user-123"


def test_validate_ip_pinning_mismatched_ip(validator):
    """Test validation fails when IPs don't match."""
    payload = {
        "sub": "user-123",
        "doc": "doc-456",
        "aud": "pdf-microservice",
        "jti": "ticket-789",
        "ip": "192.168.1.100",
        "ip_pinning_enabled": True,
        "exp": datetime.utcnow() + timedelta(minutes=1),
        "iat": datetime.utcnow()
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS512")

    # Should raise ValueError for IP mismatch
    with pytest.raises(ValueError, match="IP mismatch"):
        validator.validate_open_ticket_with_ip_pinning(
            token, "doc-456", "user-123", "203.0.113.1"
        )


def test_validate_ipv4_address_format(validator):
    """Test IPv4 address validation."""
    assert validator._is_valid_ip_address("192.168.1.1")
    assert validator._is_valid_ip_address("10.0.0.1")
    assert validator._is_valid_ip_address("255.255.255.255")
    assert not validator._is_valid_ip_address("256.1.1.1")
    assert not validator._is_valid_ip_address("invalid")


def test_mask_ip_address(validator):
    """Test IP address masking for logging."""
    masked = validator._mask_ip_address("192.168.1.100")
    assert masked == "192.168.1.*"

    masked_ipv6 = validator._mask_ip_address("2001:db8::1")
    assert "****" in masked_ipv6