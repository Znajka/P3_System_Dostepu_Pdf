"""
Streaming service: orchestrates on-the-fly decryption and streaming.
Per CONTRIBUTING.md: decrypt only in-memory, stream directly to client.
"""

import logging
import asyncio
from io import BytesIO
from typing import AsyncGenerator, Tuple
import os

from app.utils.crypto import AES256GCMEncryption

logger = logging.getLogger(__name__)


class StreamingService:
    """Service for streaming decrypted PDFs."""

    def __init__(self):
        """Initialize streaming service."""
        self.chunk_size = int(os.getenv("FASTAPI_STREAM_CHUNK_SIZE", "65536"))

    async def stream_decrypted_pdf(
        self,
        document_id: str,
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes,
        dek: bytes,
        chunk_size: int = None
    ) -> AsyncGenerator[bytes, None]:
        """
        Stream decrypted PDF in chunks (memory-efficient).
        Decryption happens on-the-fly; plaintext never written to disk.

        Per CONTRIBUTING.md: decrypt only in-memory and stream directly to client.

        Args:
            document_id: document identifier (used as AAD)
            ciphertext: encrypted PDF bytes
            nonce: 12-byte nonce from encryption
            tag: 16-byte authentication tag
            dek: 32-byte Document Encryption Key
            chunk_size: bytes per chunk (default 64KB)

        Yields:
            Chunks of plaintext PDF bytes

        Raises:
            cryptography.exceptions.InvalidTag: if authentication fails
        """
        chunk_size = chunk_size or self.chunk_size

        try:
            logger.info(
                "Starting stream decryption: document=%s, ciphertext=%d bytes, "
                "chunk_size=%d",
                document_id, len(ciphertext), chunk_size
            )

            # Step 1: Decrypt entire PDF (AES-256-GCM limitation)
            # Note: GCM cannot decrypt and authenticate in chunks.
            # Full authentication requires all data present.
            plaintext = AES256GCMEncryption.decrypt_data(
                ciphertext, nonce, tag, dek, document_id
            )

            logger.info(
                "Decrypted PDF successfully: %s -> %d bytes plaintext",
                document_id, len(plaintext)
            )

            # Step 2: Stream plaintext in chunks to client
            bytes_streamed = 0
            for offset in range(0, len(plaintext), chunk_size):
                chunk = plaintext[offset:offset + chunk_size]
                bytes_streamed += len(chunk)

                yield chunk

                # Allow other tasks to run; prevent blocking
                await asyncio.sleep(0)

            logger.info(
                "Completed stream: document=%s, total_bytes=%d, chunks=%d",
                document_id, bytes_streamed,
                (len(plaintext) + chunk_size - 1) // chunk_size
            )

        except Exception as e:
            logger.error("Stream decryption failed: %s", str(e))
            raise

    async def validate_and_retrieve_encryption_metadata(
        self, document_id: str
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Retrieve encryption metadata (nonce, tag, DEK) for a document.
        In production: call Spring Boot internal API to get DEK + metadata.

        Args:
            document_id: document identifier

        Returns:
            Tuple of (nonce, tag, dek)
        """
        # TODO: Call Spring Boot API to retrieve:
        # - nonce (from DOCUMENT_KEY_METADATA.iv)
        # - tag (from DOCUMENT_KEY_METADATA.tag)
        # - dek (unwrapped from wrapped_dek via KMS)

        logger.info("Retrieving encryption metadata: %s", document_id)

        # Mock implementation (replace with actual API call)
        nonce = bytes(12)  # TODO: retrieve from DB
        tag = bytes(16)  # TODO: retrieve from DB
        dek = bytes(32)  # TODO: retrieve from Spring Boot

        return nonce, tag, dek