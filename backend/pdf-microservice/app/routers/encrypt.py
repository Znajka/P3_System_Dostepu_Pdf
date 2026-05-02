"""
FastAPI endpoints for PDF encryption/decryption.
"""

import logging
import base64
from io import BytesIO
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import StreamingResponse
import asyncio

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/encrypt", tags=["encryption"])


@router.post("/pdf", summary="Encrypt a PDF file")
async def encrypt_pdf_endpoint(
    document_id: str = Form(..., description="Document UUID"),
    dek_base64: str = Form(..., description="Base64-encoded 256-bit DEK"),
    file: UploadFile = File(..., description="PDF file to encrypt")
):
    """
    Encrypt a PDF file with AES-256-GCM.
    Per API: receives plaintext PDF + DEK -> returns encrypted bytes + metadata.

    Args:
        document_id: document identifier
        dek_base64: Base64-encoded 32-byte DEK
        file: multipart PDF file

    Returns:
        JSON: encrypted file metadata (nonce, tag, size)
    """
    try:
        # Decode DEK
        dek = base64.b64decode(dek_base64)
        if len(dek) != 32:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid DEK size: {len(dek)}, expected 32"
            )

        # Read PDF
        pdf_bytes = await file.read()
        logger.info("Received PDF: %s (%d bytes)", document_id, len(pdf_bytes))

        # Encrypt
        from app.services.encryption_service import EncryptionService
        enc_service = EncryptionService(spring_boot_url="http://localhost:8080")

        ciphertext, nonce, tag = await enc_service.encrypt_pdf(
            document_id, pdf_bytes, dek
        )

        # Return encrypted bytes (can be streamed to storage)
        return StreamingResponse(
            iter([ciphertext]),
            media_type="application/octet-stream",
            headers={
                "X-Nonce": base64.b64encode(nonce).decode(),
                "X-Tag": base64.b64encode(tag).decode(),
                "X-Document-ID": document_id,
                "Content-Length": str(len(ciphertext))
            }
        )

    except ValueError as e:
        logger.error("Invalid input: %s", str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Encryption failed: %s", str(e))
        raise HTTPException(status_code=500, detail="Encryption failed")


@router.post("/stream", summary="Encrypt PDF stream")
async def encrypt_stream_endpoint(
    document_id: str = Form(...),
    dek_base64: str = Form(...),
    file: UploadFile = File(...)
):
    """
    Encrypt PDF stream (memory-efficient for large files).

    Args:
        document_id: document identifier
        dek_base64: Base64-encoded DEK
        file: PDF file

    Returns:
        StreamingResponse with encrypted bytes
    """
    try:
        dek = base64.b64decode(dek_base64)
        if len(dek) != 32:
            raise HTTPException(status_code=400, detail="Invalid DEK size")

        from app.services.encryption_service import EncryptionService
        enc_service = EncryptionService(spring_boot_url="http://localhost:8080")

        input_stream = BytesIO(await file.read())
        output_stream = BytesIO()

        nonce, tag = await enc_service.encrypt_pdf_stream(
            document_id, input_stream, output_stream, dek
        )

        output_stream.seek(0)

        return StreamingResponse(
            output_stream,
            media_type="application/octet-stream",
            headers={
                "X-Nonce": base64.b64encode(nonce).decode(),
                "X-Tag": base64.b64encode(tag).decode(),
                "X-Document-ID": document_id
            }
        )

    except Exception as e:
        logger.error("Stream encryption failed: %s", str(e))
        raise HTTPException(status_code=500, detail="Stream encryption failed")