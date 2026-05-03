"""
FastAPI dependency for validating open-ticket JWTs with IP-pinning.
Used to protect streaming and decryption endpoints.
"""

import logging
from typing import Optional
from fastapi import Depends, HTTPException, Header, Request
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


async def validate_open_ticket_with_ip_pinning(
    request: Request,
    authorization: str = Header(
        None, description="Bearer token from /documents/{id}/open-ticket"
    ),
    jwt_validator: JwtValidator = Depends(get_jwt_validator)
) -> dict:
    """
    Dependency: validate open-ticket JWT with IP-pinning from Authorization header.
    Extracts "Bearer <token>" from header, validates signature, and checks IP pinning.

    Args:
        request: FastAPI Request object (for extracting client IP)
        authorization: Authorization header value (format: "Bearer <token>")
        jwt_validator: JWT validator instance

    Returns:
        Decoded JWT payload (sub, doc, aud, jti, exp, iat, ip)

    Raises:
        HTTPException: if token is missing, invalid, expired, or IP mismatch
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

    # Extract client IP from request
    client_ip = request.client.host if request.client else "unknown"
    logger.info("Validating ticket with IP pinning: clientIp=%s", client_ip)

    # TODO: Extract document ID and user ID from path/query params
    # For now, these are passed as dependencies or extracted from JWT
    document_id = request.path_params.get("document_id", "")
    user_id = ""  # Will be extracted from token

    # Validate token with IP pinning
    try:
        # First validate token to extract user_id
        payload = jwt_validator._validate_token(token)
        user_id = payload.get("sub", "")
        document_id = payload.get("doc", "")

        # Now validate with IP pinning
        payload = jwt_validator.validate_open_ticket_with_ip_pinning(
            token, document_id, user_id, client_ip
        )

        logger.info(
            "Ticket validated with IP pinning: user=%s, doc=%s, ip=%s",
            user_id, document_id, client_ip
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
    payload: dict = Depends(validate_open_ticket_with_ip_pinning),
) -> str:
    """
    Dependency: extract and return ticket nonce (JTI) from validated payload.
    Used for replay prevention (mark nonce as used in DB).

    Args:
        payload: decoded JWT payload from validate_open_ticket_with_ip_pinning

    Returns:
        JTI (unique ticket nonce)
    """
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=400, detail="Missing JTI in token")
    return jti


async def validate_ticket_for_document(
    document_id: str,
    payload: dict = Depends(validate_open_ticket_with_ip_pinning),
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