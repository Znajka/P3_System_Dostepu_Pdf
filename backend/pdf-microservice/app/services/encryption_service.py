"""
Encryption service: orchestrates PDF encryption/decryption with Spring Boot DEK retrieval.
"""

import logging
import base64
from io import BytesIO
from typing import Tuple, Optional
import httpx
from app.utils.crypto import AES256GCMEncryption
from app.models.encryption import DekMetadata, EncryptionResponse, DecryptionResponse

logger = logging.getLogger(__name__)


class EncryptionService:
    """Service for managing PDF encryption/decryption."""

    def __init__(self, spring_boot_url: str, verify_ssl: bool = True):
        """
        Initialize encryption service.

        Args:
            spring_boot_url: Spring Boot backend URL (e.g., https://localhost:8080)
            verify_ssl: whether to verify SSL certificates
        """
        self.spring_boot_url = spring_boot_url
        self.verify_ssl = verify_ssl

    async def encrypt_pdf(
        self,
        document_id: str,
        pdf_bytes: bytes,
        dek: bytes
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt PDF with AES-256-GCM.

        Args:
            document_id: document identifier
            pdf_bytes: plaintext PDF data
            dek: 32-byte Document Encryption Key

        Returns:
            Tuple of (ciphertext, nonce, tag)
        """
        logger.info("Encrypting PDF: %s (%d bytes)", document_id, len(pdf_bytes))

        try:
            ciphertext, nonce, tag = AES256GCMEncryption.encrypt_data(
                pdf_bytes, dek, document_id
            )
            logger.info(
                "Encrypted: %s -> %d bytes ciphertext, %d bytes nonce, %d bytes tag",
                document_id, len(ciphertext), len(nonce), len(tag)
            )
            return ciphertext, nonce, tag

        except Exception as e:
            logger.error("Encryption failed: %s", str(e))
            raise

    async def decrypt_pdf(
        self,
        document_id: str,
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes,
        dek: bytes
    ) -> bytes:
        """
        Decrypt PDF with AES-256-GCM.

        Args:
            document_id: document identifier
            ciphertext: encrypted PDF data
            nonce: 12-byte nonce from encryption
            tag: 16-byte authentication tag
            dek: 32-byte Document Encryption Key

        Returns:
            Plaintext PDF bytes
        """
        logger.info("Decrypting PDF: %s (%d bytes)", document_id, len(ciphertext))

        try:
            plaintext = AES256GCMEncryption.decrypt_data(
                ciphertext, nonce, tag, dek, document_id
            )
            logger.info(
                "Decrypted: %s -> %d bytes plaintext",
                document_id, len(plaintext)
            )
            return plaintext

        except Exception as e:
            logger.error("Decryption failed: %s", str(e))
            raise

    async def encrypt_pdf_stream(
        self,
        document_id: str,
        input_stream,
        output_stream,
        dek: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt PDF from stream (memory-efficient).

        Args:
            document_id: document identifier
            input_stream: file-like object (plaintext PDF)
            output_stream: file-like object (encrypted data)
            dek: 32-byte Document Encryption Key

        Returns:
            Tuple of (nonce, tag)
        """
        logger.info("Encrypting PDF stream: %s", document_id)

        try:
            nonce, tag = AES256GCMEncryption.encrypt_stream(
                input_stream, output_stream, dek, document_id
            )
            logger.info("Encrypted stream: %s", document_id)
            return nonce, tag

        except Exception as e:
            logger.error("Stream encryption failed: %s", str(e))
            raise

    async def decrypt_pdf_stream(
        self,
        document_id: str,
        input_stream,
        output_stream,
        nonce: bytes,
        tag: bytes,
        dek: bytes
    ) -> None:
        """
        Decrypt PDF to stream (streaming to client).

        Args:
            document_id: document identifier
            input_stream: file-like object (encrypted PDF)
            output_stream: file-like object (plaintext PDF)
            nonce: 12-byte nonce
            tag: 16-byte authentication tag
            dek: 32-byte Document Encryption Key
        """
        logger.info("Decrypting PDF stream: %s", document_id)

        try:
            AES256GCMEncryption.decrypt_stream(
                input_stream, output_stream, nonce, tag, dek, document_id
            )
            logger.info("Decrypted stream: %s", document_id)

        except Exception as e:
            logger.error("Stream decryption failed: %s", str(e))
            raise

    async def retrieve_dek_from_spring_boot(
        self,
        document_id: str,
        ticket: str
    ) -> bytes:
        """
        Request decrypted DEK from Spring Boot over mTLS.
        Per CONTRIBUTING.md Key Management: FastAPI requests temporary DEK access.

        Args:
            document_id: document identifier
            ticket: JWT ticket for service-to-service authentication

        Returns:
            32-byte Document Encryption Key
        """
        url = f"{self.spring_boot_url}/api/internal/dek/{document_id}"

        try:
            async with httpx.AsyncClient(verify=self.verify_ssl) as client:
                response = await client.get(
                    url,
                    headers={
                        "Authorization": f"Bearer {ticket}",
                        "X-Service-ID": "pdf-microservice"
                    },
                    timeout=10.0
                )

                if response.status_code == 200:
                    data = response.json()
                    dek_base64 = data.get("dek")
                    dek = base64.b64decode(dek_base64)

                    if len(dek) != 32:
                        raise ValueError(f"Invalid DEK size: {len(dek)}")

                    logger.info("Retrieved DEK from Spring Boot: %s", document_id)
                    return dek

                else:
                    logger.error(
                        "Failed to retrieve DEK: %s (status %d)",
                        document_id, response.status_code
                    )
                    raise RuntimeError(
                        f"DEK retrieval failed: {response.status_code}"
                    )

        except Exception as e:
            logger.error("DEK retrieval error: %s", str(e))
            raise