package com.p3.dostepu.infrastructure.encryption;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;

/**
 * HashiCorp Vault KMS implementation. Generates DEK, wraps/unwraps via Vault.
 * NOTE: This is a mock implementation. In production, use Vault API client.
 */
@Slf4j
@Service
@ConditionalOnProperty(name = "kms.provider", havingValue = "vault", matchIfMissing = true)
public class VaultKmsService implements KmsService {

  @Value("${kms.endpoint:http://vault:8200}")
  private String vaultEndpoint;

  @Value("${kms.auth-token:}")
  private String vaultToken;

  private final SecureRandom secureRandom = new SecureRandom();

  @Override
  public byte[] generateDek(UUID documentId) {
    byte[] dek = new byte[32]; // 256 bits
    secureRandom.nextBytes(dek);
    log.debug("Generated DEK for document: {}", documentId);
    return dek;
  }

  @Override
  public WrappedDekMetadata wrapDek(byte[] dek, UUID documentId) {
    // TODO: Call Vault transit engine API to wrap DEK
    // Dev-only: store plaintext DEK bytes in wrapped_dek with DEV-PLAINTEXT algorithm
    // so streaming/decryption uses the same key as upload encryption.
    WrappedDekMetadata metadata = new WrappedDekMetadata();
    metadata.wrappedDek = Arrays.copyOf(dek, dek.length);
    metadata.iv = new byte[12];
    secureRandom.nextBytes(metadata.iv);
    metadata.tag = new byte[16];
    secureRandom.nextBytes(metadata.tag);
    metadata.algorithm = "DEV-PLAINTEXT";
    metadata.kmsKeyId = "vault-key-v1";
    metadata.kmsKeyVersion = "1";
    metadata.kmsMetadata = "{\"wrapped_at\":\"" + System.currentTimeMillis() + "\"}";

    log.debug("Wrapped DEK for document: {} (dev envelope)", documentId);
    return metadata;
  }

  @Override
  public byte[] unwrapDek(WrappedDekMetadata wrappedMetadata) {
    // TODO: Call Vault transit engine API to unwrap DEK
    if ("DEV-PLAINTEXT".equals(wrappedMetadata.algorithm)
        && wrappedMetadata.wrappedDek != null) {
      return Arrays.copyOf(wrappedMetadata.wrappedDek, wrappedMetadata.wrappedDek.length);
    }
    log.warn("unwrapDek: unsupported algorithm {}", wrappedMetadata.algorithm);
    throw new IllegalStateException("KMS unwrap not implemented for algorithm: "
        + wrappedMetadata.algorithm);
  }
}