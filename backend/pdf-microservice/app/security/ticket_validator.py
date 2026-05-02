"""
FastAPI dependency for validating open-ticket JWTs.
Used to protect streaming and decryption endpoints.
"""

import logging
from typing import Optional
from fastapi import Depends, HTTPException, Header
import jwt

from app.security.jwt_validator import JwtValidator

logger = logging.getLogger(__name__)

# Global JWT validator (singleton)
_jwt_validator: Optional[JwtValidator] = None


def get_jwt_validator() -> JwtValidator:
    """Get or create JWT validator singleton."""
    global _jwt_validator
    if _jwt_validator is None:
        _jwt_validator = JwtValidator()
    return _jwt_validator


async def validate_open_ticket(
    authorization: str = Header(
        None, description="Bearer token from /documents/{id}/open-ticket"
    ),
    jwt_validator: JwtValidator = Depends(get_jwt_validator)
) -> dict:
    """
    Dependency: validate open-ticket JWT from Authorization header.
    Extracts "Bearer <token>" from header and validates.

    Args:
        authorization: Authorization header value (format: "Bearer <token>")
        jwt_validator: JWT validator instance

    Returns:
        Decoded JWT payload (sub, doc, aud, jti, exp, iat)

    Raises:
        HTTPException: if token is missing, invalid, or expired
    """
    if not authorization:
        logger.warning("Missing Authorization header")
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    # Parse "Bearer <token>"
    try:
        parts = authorization.split(" ")
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise ValueError("Invalid Authorization header format")
        token = parts[1]
    except ValueError as e:
        logger.warning("Invalid Authorization format: %s", str(e))
        raise HTTPException(
            status_code=401, detail="Invalid Authorization header format"
        )

    # Validate token
    try:
        payload = jwt_validator.validate_open_ticket(token)
        logger.info(
            "Ticket validated: user=%s, doc=%s", payload.get("sub"),
            payload.get("doc")
        )
        return payload

    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        raise HTTPException(status_code=401, detail="Token has expired")

    except jwt.InvalidTokenError as e:
        logger.warning("Invalid token: %s", str(e))
        raise HTTPException(status_code=401, detail="Invalid token")

    except ValueError as e:
        logger.warning("Token validation failed: %s", str(e))
        raise HTTPException(status_code=401, detail=str(e))

    except Exception as e:
        logger.error("Unexpected error validating token: %s", str(e))
        raise HTTPException(status_code=500, detail="Token validation error")


async def validate_ticket_nonce(
    payload: dict = Depends(validate_open_ticket),
) -> str:
    """
    Dependency: extract and return ticket nonce (JTI) from validated payload.
    Used for replay prevention (mark nonce as used in DB).

    Args:
        payload: decoded JWT payload from validate_open_ticket

    Returns:
        JTI (unique ticket nonce)
    """
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=400, detail="Missing JTI in token")
    return jti


async def validate_ticket_for_document(
    document_id: str,
    payload: dict = Depends(validate_open_ticket),
) -> dict:
    """
    Dependency: validate ticket is scoped to specific document.

    Args:
        document_id: expected document UUID
        payload: decoded JWT payload

    Returns:
        Payload if document ID matches

    Raises:
        HTTPException: if document ID doesn't match
    """
    token_doc_id = payload.get("doc")
    if token_doc_id != document_id:
        logger.warning(
            "Document ID mismatch: expected=%s, got=%s", document_id, token_doc_id
        )
        raise HTTPException(status_code=403, detail="Access denied for this document")
    return payload