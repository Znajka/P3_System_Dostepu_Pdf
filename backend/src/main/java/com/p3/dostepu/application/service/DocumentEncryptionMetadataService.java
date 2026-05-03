package com.p3.dostepu.application.service;

import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.p3.dostepu.api.dto.EncryptionMetadataResponse;
import com.p3.dostepu.application.exception.ResourceNotFoundException;
import com.p3.dostepu.application.exception.UnauthorizedException;
import com.p3.dostepu.domain.entity.Document;
import com.p3.dostepu.domain.entity.DocumentKeyMetadata;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.entity.UserRole;
import com.p3.dostepu.domain.repository.AccessGrantRepository;
import com.p3.dostepu.domain.repository.DocumentKeyMetadataRepository;
import com.p3.dostepu.domain.repository.DocumentRepository;
import com.p3.dostepu.infrastructure.encryption.KmsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Exposes encryption parameters to authorized viewers (same rules as open-ticket).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DocumentEncryptionMetadataService {

  private final DocumentRepository documentRepository;
  private final DocumentKeyMetadataRepository keyMetadataRepository;
  private final AccessGrantRepository grantRepository;
  private final KmsService kmsService;
  private final ObjectMapper objectMapper;

  @Transactional(readOnly = true)
  public EncryptionMetadataResponse getEncryptionMetadata(UUID documentId, User user) {
    Document document = documentRepository.findByIdAndDeletedAtNull(documentId)
        .orElseThrow(() -> new ResourceNotFoundException("Document not found: " + documentId));

    ZonedDateTime now = ZonedDateTime.now();
    boolean hasGrant = grantRepository
        .findByDocumentIdAndGranteeUserIdAndRevokedFalseAndExpiresAtAfter(
            documentId, user.getId(), now)
        .isPresent();
    boolean isOwner = document.getOwner().getId().equals(user.getId());
    boolean isAdmin = user.getRoles().contains(UserRole.ADMIN);

    if (!hasGrant && !isOwner && !isAdmin) {
      throw new UnauthorizedException("Access denied: no valid grant for this document");
    }

    DocumentKeyMetadata meta = keyMetadataRepository.findById(documentId)
        .orElseThrow(() -> new ResourceNotFoundException(
            "Encryption metadata not found for document: " + documentId));

    String nonceB64;
    String tagB64;
    try {
      JsonNode node = objectMapper.readTree(meta.getKmsMetadata() == null ? "{}"
          : meta.getKmsMetadata());
      nonceB64 = node.path("encryption_nonce_b64").asText(null);
      tagB64 = node.path("encryption_tag_b64").asText(null);
    } catch (Exception e) {
      throw new IllegalStateException("Invalid encryption metadata JSON", e);
    }
    if (nonceB64 == null || nonceB64.isBlank() || tagB64 == null || tagB64.isBlank()) {
      throw new IllegalStateException(
          "Document missing encryption nonce/tag (re-upload may be required)");
    }

    KmsService.WrappedDekMetadata wrapped = new KmsService.WrappedDekMetadata();
    wrapped.wrappedDek = meta.getWrappedDek();
    wrapped.iv = meta.getIv();
    wrapped.tag = meta.getTag();
    wrapped.algorithm = meta.getWrapAlgorithm();
    wrapped.kmsKeyId = meta.getKmsKeyId();
    wrapped.kmsKeyVersion = meta.getKmsKeyVersion();
    wrapped.kmsMetadata = meta.getKmsMetadata();

    byte[] dek = kmsService.unwrapDek(wrapped);
    String dekB64 = Base64.getEncoder().encodeToString(dek);

    return EncryptionMetadataResponse.builder()
        .dek(dekB64)
        .nonce(nonceB64)
        .tag(tagB64)
        .algorithm(document.getEncryptedAlgorithm())
        .build();
  }
}
