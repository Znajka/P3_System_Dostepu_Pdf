"""
FastAPI streaming endpoint using ticket-based access control.
GET /stream/{ticket} - stream decrypted PDF via JWT ticket validation.
"""

import logging
import base64
import os
from typing import Optional
import httpx
from fastapi import APIRouter, Path, HTTPException, Query, Header, Request
from fastapi.responses import StreamingResponse

from app.security.jwt_validator import JwtValidator
from app.services.streaming_service import StreamingService
from app.models.streaming import StreamingAuditLog

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/stream", tags=["streaming"])

# Singleton instances
_jwt_validator: Optional[JwtValidator] = None
_streaming_service: Optional[StreamingService] = None


def get_jwt_validator() -> JwtValidator:
    """Get or create JWT validator singleton."""
    global _jwt_validator
    if _jwt_validator is None:
        _jwt_validator = JwtValidator()
    return _jwt_validator


def get_streaming_service() -> StreamingService:
    """Get or create streaming service singleton."""
    global _streaming_service
    if _streaming_service is None:
        _streaming_service = StreamingService()
    return _streaming_service


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for") or request.headers.get(
        "X-Forwarded-For"
    )
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "127.0.0.1"


async def _mark_ticket_used_spring(nonce: str, user_id: str) -> None:
    base = os.getenv(
        "SPRING_BOOT_SERVICE_URL", "http://spring-boot-backend:8080"
    ).rstrip("/")
    key = os.getenv("APP_INTERNAL_API_KEY", "")
    if not key:
        logger.error("APP_INTERNAL_API_KEY not configured")
        raise HTTPException(
            status_code=503,
            detail="Ticket replay protection not configured (internal API key)",
        )
    url = f"{base}/api/internal/tickets/mark-used"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            url,
            json={"nonce": nonce, "userId": user_id},
            headers={"X-Internal-Api-Key": key},
        )
    if response.status_code == 401:
        raise HTTPException(
            status_code=503, detail="Internal ticket API authentication failed"
        )
    if response.status_code == 409:
        raise HTTPException(
            status_code=403, detail="Ticket already used, expired, or invalid"
        )
    if response.status_code not in (200, 204):
        logger.error(
            "mark-used failed: status=%s body=%s",
            response.status_code,
            response.text,
        )
        raise HTTPException(
            status_code=503, detail="Ticket validation service unavailable"
        )


@router.get("/{ticket}", summary="Stream decrypted PDF via ticket")
async def stream_decrypted_pdf_via_ticket(
    request: Request,
    ticket: str = Path(..., description="Open-ticket JWT"),
    chunk_size: int = Query(
        default=65536,
        ge=1024,
        le=1048576,
        description="Streaming chunk size in bytes (1KB - 1MB)"
    ),
    x_dek: str = Header(
        None,
        alias="X-DEK",
        description="Base64-encoded DEK (optional; from Spring Boot via proxy)"
    ),
    x_nonce: str = Header(
        None,
        alias="X-Nonce",
        description="Base64-encoded nonce (optional; from Spring Boot)"
    ),
    x_tag: str = Header(
        None,
        alias="X-Tag",
        description="Base64-encoded authentication tag (optional; from Spring Boot)"
    ),
):
    """
    Stream decrypted PDF to client via JWT ticket validation.
    Ticket is validated, encrypted blob retrieved, decrypted on-the-fly,
    and streamed to client. Plaintext never written to disk.

    Per CONTRIBUTING.md:
      - Document access only via temporary secure ticket (60-120 seconds)
      - PDF streamed to frontend and rendered via PDF.js (canvas), not downloaded
      - No direct file access via URL

    Security flow:
      1. Validate JWT ticket (signature, expiration, audience, claims)
      2. Extract document ID and user ID from ticket
      3. Check ticket nonce hasn't been used (replay prevention)
      4. Retrieve encrypted blob from storage
      5. Retrieve or receive encryption metadata (nonce, tag, DEK)
      6. Decrypt in-memory (AES-256-GCM)
      7. Stream plaintext chunks to client
      8. Mark ticket nonce as used (prevent replay)
      9. Log stream_start and stream_end events

    Args:
        ticket: Open-ticket JWT (path parameter)
        chunk_size: streaming chunk size in bytes (query parameter, optional)
        x_dek: Base64-encoded DEK (header, optional; from Spring Boot proxy)
        x_nonce: Base64-encoded nonce (header, optional)
        x_tag: Base64-encoded tag (header, optional)

    Returns:
        StreamingResponse with decrypted PDF bytes (application/pdf)

    Status codes:
        200 OK: streaming started successfully
        400 Bad Request: invalid ticket, missing metadata, invalid encoding
        401 Unauthorized: ticket invalid, expired, or audience mismatch
        403 Forbidden: document ID mismatch
        404 Not Found: encrypted blob not found
        500 Internal Server Error: decryption failed or storage error
    """
    jwt_validator = get_jwt_validator()
    streaming_service = get_streaming_service()
    storage_path = os.getenv("STORAGE_LOCAL_PATH", "/data/encrypted-documents")

    try:
        logger.info("Stream request via ticket: ticket=%s...", ticket[:50])
        ip = _client_ip(request)

        try:
            payload = jwt_validator.validate_stream_ticket(ticket, ip)
        except Exception as e:
            logger.warning("Ticket validation failed: %s", str(e))
            raise HTTPException(status_code=401, detail=f"Invalid ticket: {str(e)}")

        user_id = str(payload.get("sub"))
        document_id = str(payload.get("doc"))
        ticket_nonce = str(payload.get("jti"))

        await _mark_ticket_used_spring(ticket_nonce, user_id)

        logger.info(
            "Ticket validated and consumed: user=%s, document=%s, nonce=%s",
            user_id, document_id, ticket_nonce
        )

        # Retrieve encrypted blob from storage
        blob_filename = f"{document_id}.pdf.enc"
        blob_path = os.path.join(storage_path, blob_filename)

        try:
            with open(blob_path, "rb") as f:
                ciphertext = f.read()
            logger.info(
                "Retrieved encrypted blob: %s (%d bytes)",
                blob_path, len(ciphertext)
            )
        except FileNotFoundError:
            logger.error("Encrypted blob not found: %s", blob_path)
            raise HTTPException(
                status_code=404, detail="Document blob not found"
            )
        except Exception as e:
            logger.error("Failed to read encrypted blob: %s", str(e))
            raise HTTPException(
                status_code=500, detail="Storage read error"
            )

        # Step 6: Retrieve or decode encryption metadata
        try:
            if x_dek and x_nonce and x_tag:
                # Metadata provided via headers (from Spring Boot proxy)
                dek = base64.b64decode(x_dek)
                nonce = base64.b64decode(x_nonce)
                tag = base64.b64decode(x_tag)

                if len(dek) != 32 or len(nonce) != 12 or len(tag) != 16:
                    raise ValueError("Invalid metadata sizes")

                logger.debug(
                    "Using metadata from headers: dek=%d bytes, nonce=%d bytes, "
                    "tag=%d bytes",
                    len(dek), len(nonce), len(tag)
                )
            else:
                # TODO: Retrieve metadata from Spring Boot API
                # For now, raise error
                raise HTTPException(
                    status_code=400,
                    detail="Encryption metadata required (X-DEK, X-Nonce, X-Tag headers)"
                )

        except ValueError as e:
            logger.error("Invalid metadata: %s", str(e))
            raise HTTPException(
                status_code=400, detail=f"Invalid metadata: {str(e)}"
            )

        # Step 7: Log stream_start event (before decryption)
        try:
            log_stream_start(
                document_id, user_id, ticket_nonce
            )
        except Exception as e:
            logger.warning("Failed to log stream_start: %s", str(e))
            # Don't fail the request if logging fails

        # Step 8: Create streaming generator
        async def stream_generator():
            bytes_streamed = 0
            try:
                async for chunk in streaming_service.stream_decrypted_pdf(
                    document_id, ciphertext, nonce, tag, dek, chunk_size
                ):
                    bytes_streamed += len(chunk)
                    yield chunk

                # Step 9: Log stream_end event (success)
                try:
                    log_stream_end(
                        document_id, user_id, ticket_nonce,
                        bytes_streamed, True, None
                    )
                except Exception as e:
                    logger.warning("Failed to log stream_end: %s", str(e))

            except Exception as e:
                logger.error("Stream error: %s", str(e))
                # Log stream_end event (failure)
                try:
                    log_stream_end(
                        document_id, user_id, ticket_nonce,
                        bytes_streamed, False, str(e)
                    )
                except Exception as log_err:
                    logger.warning("Failed to log stream_end error: %s", str(log_err))
                raise

        # Step 10: Return streaming response with secure headers
        logger.info(
            "Starting stream to client: user=%s, document=%s, nonce=%s",
            user_id, document_id, ticket_nonce
        )

        return StreamingResponse(
            stream_generator(),
            media_type="application/pdf",
            headers={
                # File metadata
                "Content-Disposition": f"inline; filename=\"document-{document_id}.pdf\"",
                # Security headers: prevent caching, downloads, and attacks
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "no-referrer",
                # Custom headers for client integration
                "X-Document-ID": document_id,
                "X-User-ID": user_id,
                "X-Chunk-Size": str(chunk_size),
            }
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(
            "Unexpected error during streaming: %s", str(e), exc_info=True
        )
        raise HTTPException(
            status_code=500, detail="Internal server error during streaming"
        )


def log_stream_start(document_id: str, user_id: str, ticket_nonce: str) -> None:
    """
    Log stream_start event to audit trail.
    TODO: Call Spring Boot API to log event.
    """
    logger.info(
        "Stream start: document=%s, user=%s, nonce=%s",
        document_id, user_id, ticket_nonce
    )
    # TODO: POST to Spring Boot /api/internal/audit/stream-start


def log_stream_end(
    document_id: str, user_id: str, ticket_nonce: str,
    bytes_streamed: int, success: bool, reason: str
) -> None:
    """
    Log stream_end event to audit trail.
    TODO: Call Spring Boot API to log event.
    """
    logger.info(
        "Stream end: document=%s, user=%s, nonce=%s, bytes=%d, status=%s, reason=%s",
        document_id, user_id, ticket_nonce, bytes_streamed,
        ("SUCCESS" if success else "FAILURE"), reason
    )
    # TODO: POST to Spring Boot /api/internal/audit/stream-end