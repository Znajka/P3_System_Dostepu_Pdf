"""
FastAPI endpoints for PDF decryption and streaming to clients.
"""

import logging
import base64
from io import BytesIO
from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import StreamingResponse
import asyncio

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/decrypt", tags=["decryption"])


@router.get("/document/{document_id}", summary="Stream decrypted PDF")
async def stream_decrypted_pdf(
    document_id: str,
    nonce: str = Header(..., description="Base64-encoded nonce"),
    tag: str = Header(..., description="Base64-encoded auth tag"),
    dek_base64: str = Header(
        ..., alias="X-DEK", description="Base64-encoded DEK (from Spring Boot)"
    ),
    chunk_size: int = Query(default=65536, ge=1024, le=1048576)
):
    """
    Stream decrypted PDF to client (FastAPI validates ticket, decrypts on-the-fly).
    Per API contract: returns streaming PDF bytes (not downloadable blob).

    Args:
        document_id: document identifier
        nonce: Base64-encoded 12-byte nonce
        tag: Base64-encoded 16-byte authentication tag
        dek_base64: Base64-encoded 32-byte DEK
        chunk_size: streaming chunk size (1KB - 1MB)

    Returns:
        StreamingResponse with decrypted PDF bytes
    """
    try:
        # Decode parameters
        nonce_bytes = base64.b64decode(nonce)
        tag_bytes = base64.b64decode(tag)
        dek = base64.b64decode(dek_base64)

        if len(dek) != 32:
            raise HTTPException(status_code=400, detail="Invalid DEK size")
        if len(nonce_bytes) != 12:
            raise HTTPException(status_code=400, detail="Invalid nonce size")
        if len(tag_bytes) != 16:
            raise HTTPException(status_code=400, detail="Invalid tag size")

        # TODO: Read encrypted blob from storage (S3, local, etc.)
        # For now, assume it's passed as a stream
        logger.info("Streaming decrypted PDF: %s", document_id)

        from app.services.encryption_service import EncryptionService
        enc_service = EncryptionService(spring_boot_url="http://localhost:8080")

        # Placeholder: read encrypted blob from storage
        encrypted_blob = b""  # TODO: retrieve from storage

        # Decrypt
        plaintext = await enc_service.decrypt_pdf(
            document_id, encrypted_blob, nonce_bytes, tag_bytes, dek
        )

        # Stream plaintext in chunks
        async def stream_generator():
            offset = 0
            while offset < len(plaintext):
                chunk = plaintext[offset:offset + chunk_size]
                yield chunk
                offset += chunk_size

        return StreamingResponse(
            stream_generator(),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"inline; filename=\"{document_id}.pdf\"",
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )

    except ValueError as e:
        logger.error("Invalid parameters: %s", str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Decryption stream failed: %s", str(e))
        raise HTTPException(status_code=500, detail="Decryption failed")