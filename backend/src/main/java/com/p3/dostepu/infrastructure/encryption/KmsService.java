package com.p3.dostepu.infrastructure.encryption;

import java.util.UUID;

/**
 * KMS (Key Management Service) interface for DEK envelope encryption.
 * Implementations: Vault, AWS KMS, Azure Key Vault, etc.
 */
public interface KmsService {
  /**
   * Generate a new DEK (Document Encryption Key) for a document.
   *
   * @param documentId document identifier
   * @return DEK bytes (32 bytes for AES-256)
   */
  byte[] generateDek(UUID documentId);

  /**
   * Wrap (encrypt) DEK with KMS master key.
   *
   * @param dek plaintext DEK
   * @param documentId document identifier (for audit)
   * @return wrapped DEK metadata (wrapped bytes, IV, tag, algorithm)
   */
  WrappedDekMetadata wrapDek(byte[] dek, UUID documentId);

  /**
   * Unwrap (decrypt) DEK using KMS master key. Only accessible via mTLS.
   *
   * @param wrappedMetadata wrapped DEK metadata
   * @return plaintext DEK (32 bytes)
   */
  byte[] unwrapDek(WrappedDekMetadata wrappedMetadata);

  /**
   * DTO for wrapped DEK metadata.
   */
  class WrappedDekMetadata {
    public byte[] wrappedDek;
    public byte[] iv;
    public byte[] tag;
    public String algorithm;
    public String kmsKeyId;
    public String kmsKeyVersion;
    public String kmsMetadata;
  }
}