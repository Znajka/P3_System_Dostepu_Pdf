"""
JWT validation utility for FastAPI.
Per CONTRIBUTING.md API Design: JWT with expiration and revocation.
Validates open-ticket JWTs from Spring Boot.
"""

import logging
import os
from datetime import datetime
from typing import Optional, Dict, Any
import jwt
from jwt import PyJWTError

logger = logging.getLogger(__name__)


class JwtValidator:
    """
    Validates JWT tokens issued by Spring Boot.
    - Algorithm: HS512 (HMAC + SHA-512)
    - Claims: sub (user_id), doc (document_id), aud (pdf-microservice),
      jti (ticket_id), exp (expiration), iat (issued_at)
    """

    def __init__(self, secret_key: str = None):
        """
        Initialize JWT validator.

        Args:
            secret_key: JWT secret (shared between Spring Boot and FastAPI).
                       If None, loads from environment variable APP_JWT_SECRET.
        """
        self.secret_key = secret_key or os.getenv(
            "APP_JWT_SECRET", "change-me-in-production"
        )
        self.algorithm = "HS512"

        if not self.secret_key or self.secret_key == "change-me-in-production":
            logger.warning(
                "JWT secret not properly configured. Use APP_JWT_SECRET "
                "environment variable."
            )

    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT token and extract claims.

        Args:
            token: JWT token string

        Returns:
            Dictionary of decoded claims

        Raises:
            jwt.ExpiredSignatureError: token is expired
            jwt.InvalidTokenError: token is invalid or malformed
        """
        try:
            payload = jwt.decode(
                token, self.secret_key, algorithms=[self.algorithm]
            )
            logger.debug("Token validated successfully for user: %s", payload.get("sub"))
            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("Token expired: %s", token[:50])
            raise

        except jwt.InvalidTokenError as e:
            logger.warning("Invalid token: %s", str(e))
            raise

        except Exception as e:
            logger.error("Unexpected error validating token: %s", str(e))
            raise jwt.InvalidTokenError(f"Token validation failed: {str(e)}")

    def validate_open_ticket(
        self, token: str, expected_document_id: str = None,
        expected_user_id: str = None
    ) -> Dict[str, Any]:
        """
        Validate an open-ticket JWT specifically.
        Per API contract: ticket scoped to document, user, and pdf-microservice.

        Args:
            token: JWT token string
            expected_document_id: document ID to validate against (optional)
            expected_user_id: user ID to validate against (optional)

        Returns:
            Dictionary of validated claims

        Raises:
            ValueError: if ticket structure or claims are invalid
            jwt.InvalidTokenError: if token is invalid
        """
        try:
            payload = self.validate_token(token)

            # Validate required claims for open-ticket
            required_claims = ["sub", "doc", "aud", "jti", "exp", "iat"]
            for claim in required_claims:
                if claim not in payload:
                    raise ValueError(f"Missing required claim: {claim}")

            # Validate audience (must be pdf-microservice)
            if payload.get("aud") != "pdf-microservice":
                raise ValueError(
                    f"Invalid audience: {payload.get('aud')}, "
                    "expected 'pdf-microservice'"
                )

            # Validate document ID if provided
            if expected_document_id and payload.get("doc") != expected_document_id:
                logger.warning(
                    "Document ID mismatch: expected=%s, got=%s",
                    expected_document_id, payload.get("doc")
                )
                raise ValueError("Document ID mismatch")

            # Validate user ID if provided
            if expected_user_id and payload.get("sub") != expected_user_id:
                logger.warning(
                    "User ID mismatch: expected=%s, got=%s",
                    expected_user_id, payload.get("sub")
                )
                raise ValueError("User ID mismatch")

            # Validate expiration (redundant but explicit)
            exp_timestamp = payload.get("exp")
            if exp_timestamp < datetime.utcnow().timestamp():
                raise ValueError("Token has expired")

            logger.info(
                "Open-ticket validated: user=%s, doc=%s, jti=%s",
                payload.get("sub"), payload.get("doc"), payload.get("jti")
            )

            return payload

        except (ValueError, jwt.InvalidTokenError) as e:
            logger.error("Open-ticket validation failed: %s", str(e))
            raise

    def extract_user_id(self, token: str) -> str:
        """Extract user ID from token."""
        payload = self.validate_token(token)
        return payload.get("sub")

    def extract_document_id(self, token: str) -> str:
        """Extract document ID from token."""
        payload = self.validate_token(token)
        return payload.get("doc")

    def extract_jti(self, token: str) -> str:
        """Extract JTI (ticket nonce) from token."""
        payload = self.validate_token(token)
        return payload.get("jti")

    def extract_expiration(self, token: str) -> int:
        """Extract expiration timestamp from token."""
        payload = self.validate_token(token)
        return payload.get("exp")

    def is_token_expired(self, token: str) -> bool:
        """Check if token is expired."""
        try:
            self.validate_token(token)
            return False
        except jwt.ExpiredSignatureError:
            return True
        except Exception:
            return True