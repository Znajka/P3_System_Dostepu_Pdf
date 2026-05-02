"""
Internal FastAPI endpoints for Spring Boot service-to-service communication.
These endpoints are NOT exposed to clients; used only by Spring Boot backend.
Per CONTRIBUTING.md: mTLS + service-to-service authentication required.
"""

import logging
import base64
import os
from io import BytesIO
from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from pathlib import Path
import json

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/internal", tags=["internal"])


def verify_service_token(x_service_id: str = Header(None)) -> str:
    """
    Verify service-to-service authentication.
    In production: validate JWT or mTLS certificate.
    For dev: check header.
    """
    if not x_service_id or x_service_id != "spring-boot-backend":
        logger.warning("Invalid service ID: %s", x_service_id)
        raise HTTPException(status_code=401, detail="Invalid service credentials")
    return x_service_id


@router.post("/encrypt", summary="Encrypt PDF from Spring Boot")
async def encrypt_pdf_internal(
    document_id: str = Form(..., description="Document UUID"),
    dek_base64: str = Form(..., description="Base64-encoded 256-bit DEK"),
    file: UploadFile = File(..., description="PDF file to encrypt"),
    service_id: str = Depends(verify_service_token)
):
    """
    Internal endpoint: Spring Boot uploads plaintext PDF for encryption.
    FastAPI encrypts with provided DEK, saves encrypted blob to secure storage,
    and returns nonce/tag for metadata storage in DB.

    Per architecture:
      1. Spring Boot generates DEK
      2. Spring Boot sends PDF + DEK to FastAPI via mTLS
      3. FastAPI encrypts and saves encrypted blob
      4. FastAPI returns nonce + tag
      5. Spring Boot wraps DEK with KMS and stores metadata

    Args:
        document_id: document UUID (used as AAD for authentication)
        dek_base64: Base64-encoded 32-byte DEK
        file: multipart PDF file
        service_id: verified service ID (from Depends)

    Returns:
        JSON: {
            "status": "encrypted",
            "document_id": "uuid",
            "blob_path": "/data/encrypted-documents/uuid.pdf.enc",
            "nonce": "base64-encoded-nonce",
            "tag": "base64-encoded-tag",
            "ciphertext_size": 12345
        }
    """
    storage_path = os.getenv("STORAGE_LOCAL_PATH", "/data/encrypted-documents")
    
    try:
        logger.info(
            "Encrypt request from %s: document=%s, file=%s",
            service_id, document_id, file.filename
        )

        # Step 1: Validate and decode DEK
        try:
            dek = base64.b64decode(dek_base64)
        except Exception as e:
            logger.error("Failed to decode DEK: %s", str(e))
            raise HTTPException(status_code=400, detail="Invalid DEK encoding")

        if len(dek) != 32:
            logger.error("Invalid DEK size: %d", len(dek))
            raise HTTPException(
                status_code=400,
                detail=f"DEK must be 32 bytes, got {len(dek)}"
            )

        # Step 2: Read PDF from upload
        pdf_bytes = await file.read()
        if not pdf_bytes:
            logger.error("Empty file upload: %s", document_id)
            raise HTTPException(status_code=400, detail="File is empty")

        max_size = int(os.getenv("MAX_PDF_SIZE", "104857600"))  # 100MB default
        if len(pdf_bytes) > max_size:
            logger.error("File too large: %d bytes", len(pdf_bytes))
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds maximum size of {max_size} bytes"
            )

        logger.info("Received PDF: %s (%d bytes)", document_id, len(pdf_bytes))

        # Step 3: Encrypt PDF with AES-256-GCM
        from app.utils.crypto import AES256GCMEncryption

        try:
            ciphertext, nonce, tag = AES256GCMEncryption.encrypt_data(
                pdf_bytes, dek, document_id
            )
            logger.info(
                "Encrypted PDF: %s -> ciphertext=%d bytes, nonce=%d bytes, "
                "tag=%d bytes",
                document_id, len(ciphertext), len(nonce), len(tag)
            )
        except Exception as e:
            logger.error("Encryption failed: %s", str(e))
            raise HTTPException(status_code=500, detail="Encryption failed")

        # Step 4: Create secure storage directory
        try:
            Path(storage_path).mkdir(parents=True, exist_ok=True)
            # Restrict permissions: owner read/write only
            os.chmod(storage_path, 0o700)
        except Exception as e:
            logger.error("Failed to create storage directory: %s", str(e))
            raise HTTPException(status_code=500, detail="Storage setup failed")

        # Step 5: Save encrypted blob to secure location
        blob_filename = f"{document_id}.pdf.enc"
        blob_path = os.path.join(storage_path, blob_filename)

        try:
            # Write encrypted blob with restricted permissions
            with open(blob_path, "wb") as f:
                f.write(ciphertext)
            # Restrict permissions: owner read/write only (0o600)
            os.chmod(blob_path, 0o600)
            logger.info("Saved encrypted blob: %s (size=%d bytes)", blob_path,
                       len(ciphertext))
        except Exception as e:
            logger.error("Failed to save encrypted blob: %s", str(e))
            raise HTTPException(status_code=500, detail="Storage write failed")

        # Step 6: Return metadata (nonce, tag, blob path)
        response_data = {
            "status": "encrypted",
            "document_id": document_id,
            "blob_path": blob_path,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
            "ciphertext_size": len(ciphertext),
            "algorithm": "AES-256-GCM"
        }

        logger.info("Encryption response: %s", response_data)
        return JSONResponse(status_code=200, content=response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Unexpected error during encryption: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/decrypt", summary="Decrypt PDF and return plaintext")
async def decrypt_pdf_internal(
    document_id: str = Form(..., description="Document UUID"),
    dek_base64: str = Form(..., description="Base64-encoded 256-bit DEK"),
    nonce_base64: str = Form(..., description="Base64-encoded nonce"),
    tag_base64: str = Form(..., description="Base64-encoded authentication tag"),
    blob_path: str = Form(..., description="Path to encrypted blob"),
    service_id: str = Depends(verify_service_token)
):
    """
    Internal endpoint: Spring Boot requests decryption (used by audit/inspection).
    Returns plaintext PDF bytes.

    Args:
        document_id: document UUID
        dek_base64: Base64-encoded DEK
        nonce_base64: Base64-encoded nonce
        tag_base64: Base64-encoded tag
        blob_path: path to encrypted blob file
        service_id: verified service ID

    Returns:
        Plaintext PDF bytes (200 OK with content-type: application/pdf)
    """
    try:
        logger.info(
            "Decrypt request from %s: document=%s, blob=%s",
            service_id, document_id, blob_path
        )

        # Step 1: Validate and decode parameters
        try:
            dek = base64.b64decode(dek_base64)
            nonce = base64.b64decode(nonce_base64)
            tag = base64.b64decode(tag_base64)
        except Exception as e:
            logger.error("Failed to decode parameters: %s", str(e))
            raise HTTPException(status_code=400, detail="Invalid parameter encoding")

        if len(dek) != 32:
            raise HTTPException(status_code=400, detail="Invalid DEK size")
        if len(nonce) != 12:
            raise HTTPException(status_code=400, detail="Invalid nonce size")
        if len(tag) != 16:
            raise HTTPException(status_code=400, detail="Invalid tag size")

        # Step 2: Read encrypted blob from storage
        try:
            with open(blob_path, "rb") as f:
                ciphertext = f.read()
            logger.info("Read encrypted blob: %s (%d bytes)", blob_path,
                       len(ciphertext))
        except FileNotFoundError:
            logger.error("Blob not found: %s", blob_path)
            raise HTTPException(status_code=404, detail="Blob not found")
        except Exception as e:
            logger.error("Failed to read blob: %s", str(e))
            raise HTTPException(status_code=500, detail="Storage read failed")

        # Step 3: Decrypt
        from app.utils.crypto import AES256GCMEncryption

        try:
            plaintext = AES256GCMEncryption.decrypt_data(
                ciphertext, nonce, tag, dek, document_id
            )
            logger.info("Decrypted PDF: %s (%d bytes)", document_id, len(plaintext))
            return plaintext

        except Exception as e:
            logger.error("Decryption failed (auth or data corruption): %s", str(e))
            raise HTTPException(status_code=400, detail="Decryption failed")

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Unexpected error during decryption: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/dek/{document_id}", summary="Request DEK for streaming")
async def get_dek_for_streaming(
    document_id: str,
    authorization: str = Header(None),
    service_id: str = Depends(verify_service_token)
):
    """
    Internal endpoint: provide decrypted DEK for streaming decryption.
    Called by FastAPI streaming endpoint after validating client ticket.
    Per CONTRIBUTING.md Key Management: FastAPI requests temporary DEK via mTLS.

    Args:
        document_id: document UUID
        authorization: Bearer token from client (validated ticket)
        service_id: verified service ID

    Returns:
        JSON: {"dek": "base64-encoded-dek", "expires_at": "ISO8601"}
    """
    try:
        logger.info("DEK request from %s: document=%s", service_id, document_id)

        # TODO: Call Spring Boot internal API to get decrypted DEK
        # For now, return mock (in production, use mTLS to Spring Boot)
        mock_dek = base64.b64encode(os.urandom(32)).decode("utf-8")

        return JSONResponse(
            status_code=200,
            content={
                "document_id": document_id,
                "dek": mock_dek,
                "expires_at": "2026-05-02T13:00:00Z"
            }
        )

    except Exception as e:
        logger.error("DEK request failed: %s", str(e))
        raise HTTPException(status_code=500, detail="DEK retrieval failed")


@router.post("/health", summary="Internal health check")
async def internal_health_check(
    service_id: str = Depends(verify_service_token)
):
    """
    Internal health check for Spring Boot.
    """
    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "service": "pdf-microservice",
            "encryption": "AES-256-GCM",
            "verified_service": service_id
        }
    )