"""
Cryptography utility module for AES-256-GCM encryption/decryption.
Per CONTRIBUTING.md: use AES-256 for encrypting PDF content at rest.
DEK (Document Encryption Key) provided by Spring Boot via API or environment.
"""

import logging
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

logger = logging.getLogger(__name__)


class AES256GCMEncryption:
    """
    AES-256-GCM encryption/decryption utility.
    - Uses 256-bit keys (32 bytes)
    - 96-bit nonce/IV (12 bytes) - recommended for GCM
    - 128-bit authentication tag (16 bytes)
    - Associated data (AAD): document ID for integrity verification
    """

    ALGORITHM_NAME = "AES-256-GCM"
    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits (12 bytes)
    TAG_SIZE = 16  # 128 bits (16 bytes)

    @staticmethod
    def generate_dek() -> bytes:
        """
        Generate a new Document Encryption Key (DEK) using CSPRNG.
        Per CONTRIBUTING.md: DEK generated with CSPRNG (cryptographically secure).

        Returns:
            32 bytes of cryptographically secure random data
        """
        dek = secrets.token_bytes(AES256GCMEncryption.KEY_SIZE)
        logger.debug("Generated DEK: %d bytes", len(dek))
        return dek

    @staticmethod
    def generate_nonce() -> bytes:
        """
        Generate a random nonce (IV) for GCM mode.

        Returns:
            12 bytes of random data (96 bits)
        """
        nonce = secrets.token_bytes(AES256GCMEncryption.NONCE_SIZE)
        return nonce

    @staticmethod
    def encrypt_data(
        plaintext: bytes,
        dek: bytes,
        document_id: str,
        nonce: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext with AES-256-GCM.

        Args:
            plaintext: PDF bytes to encrypt
            dek: 32-byte Document Encryption Key
            document_id: document identifier (used as AAD)
            nonce: optional nonce; generated if None

        Returns:
            Tuple of (ciphertext, nonce, tag)
        """
        if len(dek) != AES256GCMEncryption.KEY_SIZE:
            raise ValueError(
                f"DEK must be {AES256GCMEncryption.KEY_SIZE} bytes, got {len(dek)}"
            )

        if nonce is None:
            nonce = AES256GCMEncryption.generate_nonce()

        if len(nonce) != AES256GCMEncryption.NONCE_SIZE:
            raise ValueError(
                f"Nonce must be {AES256GCMEncryption.NONCE_SIZE} bytes, got {len(nonce)}"
            )

        # Associated data: document ID for integrity
        aad = document_id.encode('utf-8')

        cipher = AESGCM(dek)
        # AESGCM.encrypt returns (ciphertext || tag)
        ciphertext_with_tag = cipher.encrypt(nonce, plaintext, aad)

        # Extract tag from end
        ciphertext = ciphertext_with_tag[:-AES256GCMEncryption.TAG_SIZE]
        tag = ciphertext_with_tag[-AES256GCMEncryption.TAG_SIZE:]

        logger.info(
            "Encrypted PDF: plaintext=%d bytes, ciphertext=%d bytes, nonce=%d bytes",
            len(plaintext), len(ciphertext), len(nonce)
        )

        return ciphertext, nonce, tag

    @staticmethod
    def decrypt_data(
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes,
        dek: bytes,
        document_id: str
    ) -> bytes:
        """
        Decrypt ciphertext with AES-256-GCM.

        Args:
            ciphertext: encrypted PDF bytes
            nonce: 12-byte nonce used during encryption
            tag: 16-byte authentication tag
            dek: 32-byte Document Encryption Key
            document_id: document identifier (used as AAD)

        Returns:
            Decrypted plaintext

        Raises:
            cryptography.exceptions.InvalidTag: if authentication fails
        """
        if len(dek) != AES256GCMEncryption.KEY_SIZE:
            raise ValueError(
                f"DEK must be {AES256GCMEncryption.KEY_SIZE} bytes, got {len(dek)}"
            )

        if len(nonce) != AES256GCMEncryption.NONCE_SIZE:
            raise ValueError(
                f"Nonce must be {AES256GCMEncryption.NONCE_SIZE} bytes, got {len(nonce)}"
            )

        if len(tag) != AES256GCMEncryption.TAG_SIZE:
            raise ValueError(
                f"Tag must be {AES256GCMEncryption.TAG_SIZE} bytes, got {len(tag)}"
            )

        # Associated data must match encryption
        aad = document_id.encode('utf-8')

        cipher = AESGCM(dek)
        # Combine ciphertext and tag for decryption
        ciphertext_with_tag = ciphertext + tag

        try:
            plaintext = cipher.decrypt(nonce, ciphertext_with_tag, aad)
            logger.info(
                "Decrypted PDF: ciphertext=%d bytes, plaintext=%d bytes",
                len(ciphertext), len(plaintext)
            )
            return plaintext
        except Exception as e:
            logger.error("Decryption failed (authentication): %s", str(e))
            raise

    @staticmethod
    def encrypt_stream(
        input_stream,
        output_stream,
        dek: bytes,
        document_id: str,
        chunk_size: int = 65536
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt a file stream in chunks (memory-efficient for large files).
        Note: GCM is not ideal for streaming (cannot authenticate in chunks).
        For production, consider ChaCha20-Poly1305 or chunked authentication.

        Args:
            input_stream: file-like object to read from
            output_stream: file-like object to write encrypted data
            dek: 32-byte Document Encryption Key
            document_id: document identifier
            chunk_size: bytes per chunk (default 64KB)

        Returns:
            Tuple of (nonce, tag) to store separately
        """
        nonce = AES256GCMEncryption.generate_nonce()
        aad = document_id.encode('utf-8')
        cipher = AESGCM(dek)

        # For streaming, encrypt all data in memory first (GCM limitation)
        # In production, use authenticated streaming cipher
        plaintext = input_stream.read()
        ciphertext_with_tag = cipher.encrypt(nonce, plaintext, aad)

        # Write ciphertext (without tag)
        ciphertext = ciphertext_with_tag[:-AES256GCMEncryption.TAG_SIZE]
        tag = ciphertext_with_tag[-AES256GCMEncryption.TAG_SIZE:]

        output_stream.write(ciphertext)

        logger.info(
            "Encrypted stream: plaintext=%d bytes, ciphertext=%d bytes",
            len(plaintext), len(ciphertext)
        )

        return nonce, tag

    @staticmethod
    def decrypt_stream(
        input_stream,
        output_stream,
        nonce: bytes,
        tag: bytes,
        dek: bytes,
        document_id: str,
        chunk_size: int = 65536
    ) -> None:
        """
        Decrypt a file stream in chunks (streaming to client).

        Args:
            input_stream: file-like object containing encrypted data
            output_stream: file-like object to write decrypted data
            nonce: 12-byte nonce from encryption
            tag: 16-byte authentication tag
            dek: 32-byte Document Encryption Key
            document_id: document identifier
            chunk_size: bytes per chunk (default 64KB)
        """
        aad = document_id.encode('utf-8')
        cipher = AESGCM(dek)

        # Read all ciphertext
        ciphertext = input_stream.read()
        ciphertext_with_tag = ciphertext + tag

        try:
            plaintext = cipher.decrypt(nonce, ciphertext_with_tag, aad)

            # Write plaintext in chunks to client
            for i in range(0, len(plaintext), chunk_size):
                output_stream.write(plaintext[i:i + chunk_size])

            logger.info(
                "Decrypted stream: ciphertext=%d bytes, plaintext=%d bytes",
                len(ciphertext), len(plaintext)
            )
        except Exception as e:
            logger.error("Stream decryption failed: %s", str(e))
            raise