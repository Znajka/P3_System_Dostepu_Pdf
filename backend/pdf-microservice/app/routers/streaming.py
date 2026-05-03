"""
FastAPI endpoints for streaming decrypted PDFs to clients.
Uses open-ticket JWT validation for access control.
"""

import logging
import base64
import os
from typing import Callable
from io import BytesIO
from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.responses import StreamingResponse
import asyncio

from app.security.ticket_validator import (
    validate_open_ticket_with_ip_pinning,
    validate_ticket_nonce,
    validate_ticket_for_document,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/stream", tags=["streaming"])


@router.get("/document/{document_id}", summary="Stream decrypted PDF to client")
async def stream_document(
    document_id: str,
    payload: dict = Depends(validate_open_ticket_with_ip_pinning),
    nonce: str = Depends(validate_ticket_nonce),
    x_dek: str = Header(None, alias="X-DEK", description="Base64-encoded DEK"),
    x_nonce: str = Header(None, alias="X-Nonce", description="Base64-encoded nonce"),
    x_tag: str = Header(None, alias="X-Tag", description="Base64-encoded tag"),
    chunk_size: int = Header(
        default=65536, alias="X-Chunk-Size", ge=1024, le=1048576
    ),
):
    """
    Stream decrypted PDF to authenticated client.
    Per API contract: only accessible via valid open-ticket JWT.

    Access control:
      1. JWT must be valid (not expired, correctly signed)
      2. JWT aud must be "pdf-microservice" (but this is for browser/client use,
         so aud validation may differ in production)
      3. JWT must be scoped to this document ID
      4. Ticket nonce must not be replay (checked via DB)

    Args:
        document_id: document UUID (path parameter)
        payload: validated JWT payload (from validate_open_ticket)
        nonce: ticket nonce/JTI (from validate_ticket_nonce)
        validated_payload: document-scoped payload (from validate_ticket_for_document)
        x_dek: Base64-encoded DEK (provided by Spring Boot in X-DEK header)
        x_nonce: Base64-encoded encryption nonce (from metadata)
        x_tag: Base64-encoded authentication tag (from metadata)
        chunk_size: streaming chunk size in bytes

    Returns:
        StreamingResponse with decrypted PDF bytes
    """
    try:
        user_id = payload.get("sub")
        # Ensure ticket is scoped to requested document.
        await validate_ticket_for_document(document_id, payload)
        logger.info(
            "Stream request: document=%s, user=%s, nonce=%s",
            document_id, user_id, nonce
        )

        # Step 1: Validate required headers
        if not x_dek or not x_nonce or not x_tag:
            logger.error(
                "Missing encryption metadata: dek=%s, nonce=%s, tag=%s",
                bool(x_dek), bool(x_nonce), bool(x_tag)
            )
            raise HTTPException(
                status_code=400,
                detail="Missing encryption metadata in headers"
            )

        # Step 2: Decode encryption parameters
        try:
            dek = base64.b64decode(x_dek)
            enc_nonce = base64.b64decode(x_nonce)
            tag = base64.b64decode(x_tag)
        except Exception as e:
            logger.error("Failed to decode encryption parameters: %s", str(e))
            raise HTTPException(status_code=400, detail="Invalid encoding in headers")

        # Validate sizes
        if len(dek) != 32:
            raise HTTPException(status_code=400, detail="Invalid DEK size")
        if len(enc_nonce) != 12:
            raise HTTPException(status_code=400, detail="Invalid nonce size")
        if len(tag) != 16:
            raise HTTPException(status_code=400, detail="Invalid tag size")

        # Step 3: Mark ticket as used (prevent replay)
        # TODO: Call Spring Boot API to mark nonce as used in DB
        logger.info("Marking ticket nonce as used: %s", nonce)

        # Step 4: Retrieve encrypted blob from storage
        storage_path = os.getenv("STORAGE_LOCAL_PATH", "/data/encrypted-documents")
        blob_path = os.path.join(storage_path, f"{document_id}.pdf.enc")

        try:
            with open(blob_path, "rb") as f:
                ciphertext = f.read()
            logger.info("Read encrypted blob: %s (%d bytes)", blob_path, len(ciphertext))
        except FileNotFoundError:
            logger.error("Blob not found: %s", blob_path)
            raise HTTPException(status_code=404, detail="Document blob not found")
        except Exception as e:
            logger.error("Failed to read blob: %s", str(e))
            raise HTTPException(status_code=500, detail="Storage read error")

        # Step 5: Decrypt PDF (streaming to client)
        from app.utils.crypto import AES256GCMEncryption

        try:
            plaintext = AES256GCMEncryption.decrypt_data(
                ciphertext, enc_nonce, tag, dek, document_id
            )
            logger.info(
                "Decrypted PDF: %s (%d bytes plaintext)",
                document_id, len(plaintext)
            )
        except Exception as e:
            logger.error(
                "Decryption failed (authentication or data corruption): %s", str(e)
            )
            # Log failed stream attempt
            raise HTTPException(
                status_code=400,
                detail="Decryption failed (data may be corrupted)"
            )

        # Step 6: Stream plaintext to client in chunks
        async def stream_generator():
            offset = 0
            while offset < len(plaintext):
                chunk = plaintext[offset:offset + chunk_size]
                yield chunk
                offset += chunk_size
                # Allow other tasks to run
                await asyncio.sleep(0)

        logger.info("Streaming PDF to client: %s (chunks of %d bytes)",
                   document_id, chunk_size)

        return StreamingResponse(
            stream_generator(),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"inline; filename=\"{document_id}.pdf\"",
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block"
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Unexpected error during streaming: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")