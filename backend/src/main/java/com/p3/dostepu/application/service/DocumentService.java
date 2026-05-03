package com.p3.dostepu.application.service;

import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.UUID;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import com.p3.dostepu.api.dto.DocumentUploadRequest;
import com.p3.dostepu.api.dto.DocumentUploadResponse;
import com.p3.dostepu.domain.entity.AccessAction;
import com.p3.dostepu.domain.entity.AccessEventLog;
import com.p3.dostepu.domain.entity.AccessResult;
import com.p3.dostepu.domain.entity.Document;
import com.p3.dostepu.domain.entity.DocumentKeyMetadata;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.repository.AccessEventLogRepository;
import com.p3.dostepu.domain.repository.DocumentKeyMetadataRepository;
import com.p3.dostepu.domain.repository.DocumentRepository;
import com.p3.dostepu.infrastructure.encryption.KmsService;
import com.p3.dostepu.infrastructure.pdf.FastApiPdfClient;
import com.p3.dostepu.infrastructure.storage.StorageService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Document upload and encryption service.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DocumentService {

  private final DocumentRepository documentRepository;
  private final DocumentKeyMetadataRepository keyMetadataRepository;
  private final AccessEventLogRepository auditLogRepository;
  private final StorageService storageService;
  private final FastApiPdfClient fastApiClient;
  private final KmsService kmsService;
  private final AuditLogService auditLogService;
  private final ObjectMapper objectMapper;

  /**
   * Upload and encrypt document.
   */
  @Transactional
  public DocumentUploadResponse uploadDocument(DocumentUploadRequest request,
      MultipartFile pdfFile, User owner, String clientIp) {
    UUID documentId = UUID.randomUUID();

    try {
      if (pdfFile == null || pdfFile.isEmpty()) {
        logAccessEvent(null, null, AccessAction.UPLOAD, AccessResult.FAILURE, clientIp,
            "Missing file");
        throw new IllegalArgumentException("PDF file is required");
      }

      if (pdfFile.getSize() > 104857600) {
        logAccessEvent(null, null, AccessAction.UPLOAD, AccessResult.FAILURE, clientIp,
            "File too large");
        throw new IllegalArgumentException("File exceeds 100 MB limit");
      }

      log.debug("Generating DEK for document: {}", documentId);
      byte[] dek = kmsService.generateDek(documentId);

      log.debug("Sending PDF to FastAPI for encryption: {}", documentId);
      String dekBase64 = Base64.getEncoder().encodeToString(dek);
      FastApiPdfClient.EncryptionResponse encryptResponse = fastApiClient.encryptPdfDocument(
          documentId, pdfFile, dekBase64);

      log.debug("Storing encrypted PDF blob: {}", documentId);
      ByteArrayInputStream encryptedStream = new ByteArrayInputStream(
          Base64.getDecoder().decode(encryptResponse.getCiphertext())
      );
      
      String blobPath = storageService.storeEncryptedDocument(documentId,
          pdfFile.getOriginalFilename(), encryptedStream, pdfFile.getSize());

      Long blobSize = storageService.getBlobSize(blobPath);

      log.debug("Wrapping DEK with KMS master key: {}", documentId);
      KmsService.WrappedDekMetadata wrappedMetadata = kmsService.wrapDek(dek, documentId);

      Document document = Document.builder()
          .id(documentId)
          .owner(owner)
          .title(request.getTitle())
          .description(request.getDescription())
          .tags(request.getTags())
          .blobPath(blobPath)
          .blobSizeBytes(blobSize)
          .encryptedAlgorithm("AES-256-GCM")
          .build();

      document = documentRepository.save(document);
      log.info("Persisted document entity: {}", documentId);

      ObjectNode kmsMeta = objectMapper.createObjectNode();
      kmsMeta.put("encryption_nonce_b64", encryptResponse.getNonce());
      kmsMeta.put("encryption_tag_b64", encryptResponse.getTag());
      kmsMeta.put("wrapped_at", System.currentTimeMillis());

      DocumentKeyMetadata keyMetadata = DocumentKeyMetadata.builder()
          .documentId(documentId)
          .wrappedDek(wrappedMetadata.wrappedDek)
          .iv(wrappedMetadata.iv)
          .tag(wrappedMetadata.tag)
          .wrapAlgorithm(wrappedMetadata.algorithm)
          .kmsKeyId(wrappedMetadata.kmsKeyId)
          .kmsKeyVersion(wrappedMetadata.kmsKeyVersion)
          .kmsMetadata(objectMapper.writeValueAsString(kmsMeta))
          .build();

      keyMetadataRepository.save(keyMetadata);
      log.info("Persisted key metadata for document: {}", documentId);

      auditLogService.logUpload(owner.getId(), documentId, blobSize, clientIp, null,
          true, null);

      return DocumentUploadResponse.builder()
          .documentId(documentId)
          .ownerId(owner.getId())
          .createdAt(document.getCreatedAt())
          .status("uploaded")
          .build();

    } catch (Exception e) {
      log.error("Document upload failed: {}", documentId, e);
      auditLogService.logUpload(owner.getId(), documentId, 0L, clientIp, null, false,
          e.getMessage());
      throw e;
    }
  }

  private void logAccessEvent(UUID userId, UUID documentId, AccessAction action,
      AccessResult result, String clientIp, String reason) {
    AccessEventLog event = AccessEventLog.builder()
        .user(userId != null ? new User() { { setId(userId); } } : null)
        .document(documentId != null ? new Document() { { setId(documentId); } } : null)
        .action(action)
        .result(result)
        .ipAddress(clientIp)
        .reason(reason)
        .timestampUtc(java.time.ZonedDateTime.now())
        .build();

    auditLogRepository.save(event);
  }
}