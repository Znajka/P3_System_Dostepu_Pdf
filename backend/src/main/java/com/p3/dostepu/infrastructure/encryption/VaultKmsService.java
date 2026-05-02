package com.p3.dostepu.infrastructure.encryption;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
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
    // For now, mock implementation (NOT secure; for dev only)
    byte[] wrappedDek = new byte[dek.length + 16]; // simplified
    secureRandom.nextBytes(wrappedDek);

    byte[] iv = new byte[12];
    secureRandom.nextBytes(iv);

    byte[] tag = new byte[16];
    secureRandom.nextBytes(tag);

    WrappedDekMetadata metadata = new WrappedDekMetadata();
    metadata.wrappedDek = wrappedDek;
    metadata.iv = iv;
    metadata.tag = tag;
    metadata.algorithm = "AES-KW";
    metadata.kmsKeyId = "vault-key-v1";
    metadata.kmsKeyVersion = "1";
    metadata.kmsMetadata = "{\"wrapped_at\":\"" + System.currentTimeMillis() + "\"}";

    log.debug("Wrapped DEK for document: {}", documentId);
    return metadata;
  }

  @Override
  public byte[] unwrapDek(WrappedDekMetadata wrappedMetadata) {
    // TODO: Call Vault transit engine API to unwrap DEK
    // For now, mock (NOT secure; for dev only)
    log.debug("Unwrapped DEK from Vault");
    byte[] dek = new byte[32];
    secureRandom.nextBytes(dek);
    return dek;
  }
}