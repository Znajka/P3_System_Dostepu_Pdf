"""
Integration tests for streaming endpoint.
"""

import pytest
import jwt
import base64
from datetime import datetime, timedelta
from io import BytesIO
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, mock_open
import os

from app.main import app
from app.utils.crypto import AES256GCMEncryption

SECRET_KEY = "test-secret-key-for-jwt-validation"
client = TestClient(app)


@pytest.fixture
def valid_ticket():
    """Create a valid open-ticket JWT."""
    payload = {
        "sub": "user-123",
        "doc": "doc-456",
        "aud": "pdf-microservice",
        "jti": "ticket-789",
        "exp": datetime.utcnow() + timedelta(minutes=1),
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS512")
    return token


@pytest.fixture
def encryption_setup():
    """Create test encryption data."""
    plaintext = b"This is a test PDF content" * 100  # ~2.5 KB
    dek = os.urandom(32)
    ciphertext, nonce, tag = AES256GCMEncryption.encrypt_data(
        plaintext, dek, "doc-456"
    )
    return {
        "plaintext": plaintext,
        "dek": dek,
        "ciphertext": ciphertext,
        "nonce": nonce,
        "tag": tag
    }


def test_stream_with_valid_ticket(valid_ticket, encryption_setup):
    """Test streaming with valid ticket and encryption metadata."""
    headers = {
        "X-DEK": base64.b64encode(encryption_setup["dek"]).decode(),
        "X-Nonce": base64.b64encode(encryption_setup["nonce"]).decode(),
        "X-Tag": base64.b64encode(encryption_setup["tag"]).decode(),
    }

    with patch("builtins.open", mock_open(read_data=encryption_setup["ciphertext"])):
        response = client.get(
            f"/stream/{valid_ticket}",
            headers=headers
        )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "no-store" in response.headers["cache-control"]


def test_stream_with_expired_ticket(encryption_setup):
    """Test streaming fails with expired ticket."""
    payload = {
        "sub": "user-123",
        "doc": "doc-456",
        "aud": "pdf-microservice",
        "jti": "ticket-789",
        "exp": datetime.utcnow() - timedelta(minutes=1),  # Expired
        "iat": datetime.utcnow()
    }
    expired_token = jwt.encode(payload, SECRET_KEY, algorithm="HS512")

    headers = {
        "X-DEK": base64.b64encode(encryption_setup["dek"]).decode(),
        "X-Nonce": base64.b64encode(encryption_setup["nonce"]).decode(),
        "X-Tag": base64.b64encode(encryption_setup["tag"]).decode(),
    }

    response = client.get(
        f"/stream/{expired_token}",
        headers=headers
    )

    assert response.status_code == 401


def test_stream_with_missing_metadata(valid_ticket):
    """Test streaming fails without encryption metadata."""
    response = client.get(f"/stream/{valid_ticket}")

    assert response.status_code == 400
    assert "metadata" in response.json()["detail"].lower()


def test_stream_with_invalid_dek_size(valid_ticket, encryption_setup):
    """Test streaming fails with invalid DEK size."""
    headers = {
        "X-DEK": base64.b64encode(b"short-dek").decode(),  # Invalid size
        "X-Nonce": base64.b64encode(encryption_setup["nonce"]).decode(),
        "X-Tag": base64.b64encode(encryption_setup["tag"]).decode(),
    }

    response = client.get(
        f"/stream/{valid_ticket}",
        headers=headers
    )

    assert response.status_code == 400


def test_stream_with_blob_not_found(valid_ticket, encryption_setup):
    """Test streaming fails when encrypted blob not found."""
    headers = {
        "X-DEK": base64.b64encode(encryption_setup["dek"]).decode(),
        "X-Nonce": base64.b64encode(encryption_setup["nonce"]).decode(),
        "X-Tag": base64.b64encode(encryption_setup["tag"]).decode(),
    }

    with patch("builtins.open", side_effect=FileNotFoundError):
        response = client.get(
            f"/stream/{valid_ticket}",
            headers=headers
        )

    assert response.status_code == 404


def test_stream_security_headers(valid_ticket, encryption_setup):
    """Test that security headers are present in response."""
    headers = {
        "X-DEK": base64.b64encode(encryption_setup["dek"]).decode(),
        "X-Nonce": base64.b64encode(encryption_setup["nonce"]).decode(),
        "X-Tag": base64.b64encode(encryption_setup["tag"]).decode(),
    }

    with patch("builtins.open", mock_open(read_data=encryption_setup["ciphertext"])):
        response = client.get(
            f"/stream/{valid_ticket}",
            headers=headers
        )

    assert response.status_code == 200
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert "no-cache" in response.headers.get("cache-control", "")