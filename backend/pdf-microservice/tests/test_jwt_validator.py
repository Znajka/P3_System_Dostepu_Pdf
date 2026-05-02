"""
Unit tests for JWT validation.
"""

import pytest
import jwt
from datetime import datetime, timedelta
from app.security.jwt_validator import JwtValidator

SECRET_KEY = "test-secret-key-for-jwt-validation"


@pytest.fixture
def validator():
    return JwtValidator(secret_key=SECRET_KEY)


def test_validate_valid_token(validator):
    """Test validation of a valid token."""
    payload = {
        "sub": "user-123",
        "doc": "doc-456",
        "aud": "pdf-microservice",
        "jti": "ticket-789",
        "exp": datetime.utcnow() + timedelta(minutes=1),
        "iat": datetime.utcnow()
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS512")
    result = validator.validate_open_ticket(token)

    assert result["sub"] == "user-123"
    assert result["doc"] == "doc-456"
    assert result["aud"] == "pdf-microservice"


def test_validate_expired_token(validator):
    """Test validation fails for expired token."""
    payload = {
        "sub": "user-123",
        "doc": "doc-456",
        "aud": "pdf-microservice",
        "jti": "ticket-789",
        "exp": datetime.utcnow() - timedelta(minutes=1),  # Expired
        "iat": datetime.utcnow()
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS512")

    with pytest.raises(jwt.ExpiredSignatureError):
        validator.validate_open_ticket(token)


def test_validate_invalid_audience(validator):
    """Test validation fails for invalid audience."""
    payload = {
        "sub": "user-123",
        "doc": "doc-456",
        "aud": "wrong-service",  # Invalid
        "jti": "ticket-789",
        "exp": datetime.utcnow() + timedelta(minutes=1),
        "iat": datetime.utcnow()
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS512")

    with pytest.raises(ValueError, match="Invalid audience"):
        validator.validate_open_ticket(token)


def test_validate_document_id_mismatch(validator):
    """Test validation fails for document ID mismatch."""
    payload = {
        "sub": "user-123",
        "doc": "doc-456",
        "aud": "pdf-microservice",
        "jti": "ticket-789",
        "exp": datetime.utcnow() + timedelta(minutes=1),
        "iat": datetime.utcnow()
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS512")

    with pytest.raises(ValueError, match="Document ID mismatch"):
        validator.validate_open_ticket(token, expected_document_id="doc-wrong")


def test_extract_user_id(validator):
    """Test extracting user ID from token."""
    payload = {
        "sub": "user-123",
        "doc": "doc-456",
        "aud": "pdf-microservice",
        "exp": datetime.utcnow() + timedelta(minutes=1),
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS512")
    user_id = validator.extract_user_id(token)

    assert user_id == "user-123"


def test_extract_jti(validator):
    """Test extracting JTI (nonce) from token."""
    payload = {
        "sub": "user-123",
        "doc": "doc-456",
        "jti": "ticket-789",
        "aud": "pdf-microservice",
        "exp": datetime.utcnow() + timedelta(minutes=1),
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS512")
    jti = validator.extract_jti(token)

    assert jti == "ticket-789"